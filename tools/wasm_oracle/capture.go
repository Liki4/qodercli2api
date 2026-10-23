package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Capture has no arbitrary-input mode. Only the exact historical synthetic
// fixture inputs are seeds; expected values are always obtained from WASM.
type captureHost struct {
	value transcript
	calls []hostCall
	next  byte
}

func newCaptureHost() *captureHost {
	return &captureHost{value: transcript{EntropyReads: []entropyRead{}}}
}
func (h *captureHost) Now() (time.Time, error) {
	h.calls = append(h.calls, hostCall{Kind: hostClock})
	h.value.UnixMilli = append(h.value.UnixMilli, syntheticUnixMilli)
	return time.UnixMilli(syntheticUnixMilli), nil
}
func (h *captureHost) Read(dst []byte) error {
	for i := range dst {
		h.next++
		if h.next == 0 {
			h.next = 1
		}
		dst[i] = h.next
	}
	h.calls = append(h.calls, hostCall{Kind: hostEntropy, Length: len(dst)})
	h.value.EntropyReads = append(h.value.EntropyReads, entropyRead{Length: len(dst), Bytes: append([]byte(nil), dst...)})
	return nil
}
func (h *captureHost) validate(name string) error {
	if err := validateTranscript(name, h.value); err != nil {
		return err
	}
	want := entropyCalls(h.value)
	if name == "infer-user.json" || name == "infer-user-no-org.json" {
		want = append(want[:2:2], hostCall{Kind: hostClock}, want[2])
	}
	if !reflect.DeepEqual(h.calls, want) && !(len(h.calls) == 0 && len(want) == 0) {
		return fail("transcript-order")
	}
	return nil
}

func captureFixtures(ctx context.Context, source []byte, seeds fixtureSet, identity oracleIdentity) (fixtureSet, error) {
	if err := validateWASMForIdentity(source, identity); err != nil {
		return nil, err
	}
	backend, err := newWASMBackend(ctx, source)
	if err != nil {
		return nil, err
	}
	defer backend.Close(ctx)
	fixtures := make(fixtureSet, len(fixtureNames))
	for _, name := range fixtureNames {
		host := newCaptureHost()
		backend.setReplay(host)
		input := append(json.RawMessage(nil), seeds[name].Input...)
		var expected any
		switch name {
		case "credential.json":
			in, err := mustDecode[credentialInput](input)
			if err != nil {
				return nil, err
			}
			encrypted, err := backend.callString(ctx, "credential_storage_encrypt", in.Plain, in.MachineKey)
			if err != nil {
				return nil, err
			}
			decrypted, err := backend.callString(ctx, "credential_storage_decrypt", encrypted, in.MachineKey)
			if err != nil {
				return nil, err
			}
			expected = credentialExpected{decrypted, encrypted}
		case "runtime-fields.json":
			in, err := mustDecode[runtimeInput](input)
			if err != nil {
				return nil, err
			}
			raw, err := backend.callString(ctx, "generate_runtime_auth_fields", in.Raw)
			if err != nil {
				return nil, err
			}
			var fields struct {
				Info string `json:"encrypt_user_info"`
				Key  string `json:"key"`
			}
			if err := decodeStrictValue([]byte(raw), &fields); err != nil {
				return nil, err
			}
			expected = runtimeExpected{raw, fields.Info, fields.Key}
		case "model-cache.json":
			in, err := mustDecode[modelInput](input)
			if err != nil {
				return nil, err
			}
			encrypted, err := backend.callString(ctx, "model_cache_encrypt", in.Plain, in.UID)
			if err != nil {
				return nil, err
			}
			decrypted, err := backend.callString(ctx, "model_cache_decrypt", encrypted, in.UID)
			if err != nil {
				return nil, err
			}
			expected = modelExpected{decrypted, encrypted}
		case "infer-user.json", "infer-user-no-org.json":
			in, err := mustDecode[inferFixtureInputPolicy](input)
			if err != nil {
				return nil, err
			}
			in.Version = identity.Version
			// Only change the synthetic business version, never JSON ordering.
			from := `"version":"` + pinnedVersion + `"`
			if strings.Count(in.BodyRaw, from) != 1 {
				return nil, fail("fixture-schema")
			}
			in.BodyRaw = strings.Replace(in.BodyRaw, from, `"version":"`+identity.Version+`"`, 1)
			if name == "infer-user.json" {
				fields, err := mustDecode[runtimeExpected](fixtures["runtime-fields.json"].Expected)
				if err != nil {
					return nil, err
				}
				in.User.EncryptUserInfo, in.User.Key = fields.EncryptUserInfo, fields.Key
			}
			input, err = json.Marshal(in)
			if err != nil {
				return nil, fail("fixture-schema")
			}
			user, _ := json.Marshal(in.User)
			scene, _ := json.Marshal(in.Scene)
			ptr, err := backend.newContext(ctx, in.MachineID, in.Version, string(user), string(scene))
			if err != nil {
				return nil, err
			}
			prepared, prepareErr := backend.prepareInfer(ctx, ptr, in.Endpoint, in.BodyRaw, in.ModelKey, in.ModelSource)
			closeErr := backend.freeContext(ctx, ptr)
			if prepareErr != nil {
				return nil, prepareErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			headers := make(map[string][]string, len(prepared.Headers))
			for key, value := range prepared.Headers {
				headers[http.CanonicalHeaderKey(key)] = []string{value}
			}
			expected = inferExpected{prepared.URL, headers, prepared.Body, base64.StdEncoding.EncodeToString([]byte(prepared.Body))}
		default:
			return nil, fail("fixture-schema")
		}
		if err := host.validate(name); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(expected)
		if err != nil {
			return nil, fail("fixture-schema")
		}
		fixtures[name] = fixtureDocument{Oracle: identity, Input: input, Transcript: host.value, Expected: encoded}
	}
	compatibility, err := captureCompatibility(ctx, backend, identity)
	if err != nil {
		return nil, err
	}
	fixtures["compatibility.json"] = compatibility
	// A fresh instance must replay every recorded host call and result exactly.
	if _, err := verifyFixtures(ctx, source, fixtures, io.Discard); err != nil {
		return nil, err
	}
	return fixtures, nil
}

func writeCapturedFixtures(destination string, fixtures fixtureSet, identity oracleIdentity) error {
	// Exclusive directory creation prevents replacement of historical fixtures.
	if err := os.Mkdir(destination, 0o700); err != nil {
		return fail("capture-destination")
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(destination)
		}
	}()
	manifest := fixtureManifest{Version: identity.Version, Size: identity.Size, SHA256: identity.SHA256, Documents: map[string]string{}}
	write := func(name string, value any) ([]byte, error) {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, fail("fixture-schema")
		}
		data = append(data, '\n')
		if err := validateFixtureSafety(name, data); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(filepath.Join(destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fail("capture-write")
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return nil, fail("capture-write")
		}
		return data, nil
	}
	for _, name := range fixtureNamesForVersion(identity.Version) {
		data, err := write(name, fixtures[name])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		manifest.Documents[name] = hex.EncodeToString(sum[:])
	}
	if _, err := write("manifest.json", manifest); err != nil {
		return err
	}
	complete = true
	return nil
}

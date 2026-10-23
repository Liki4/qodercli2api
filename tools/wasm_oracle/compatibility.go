package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
)

type compatibilityCase struct {
	Operation string   `json:"operation"`
	Args      []string `json:"args"`
}
type compatibilityInput struct {
	Cases []compatibilityCase `json:"cases"`
}
type compatibilityResult struct {
	Output     string     `json:"output"`
	Decoded    string     `json:"decoded"`
	Failed     bool       `json:"failed"`
	Transcript transcript `json:"transcript"`
}
type compatibilityExpected struct {
	Results []compatibilityResult `json:"results"`
}

func syntheticCompatibilityInput() compatibilityInput {
	var cases []compatibilityCase
	for _, body := range []string{"", "{}", "{ }", `{"text":"合成🙂"}`, "synthetic\x00body", "x", "xy", "xyz", strings.Repeat("synthetic-", 113)} {
		cases = append(cases, compatibilityCase{"body-roundtrip", []string{body}})
	}
	for _, encoded := range []string{"a", "ab", "abc", "????", "_$__", "kwm", "$kwm$", "$k\rwm", "$k\nwm", "$kwm?", "$d$_"} {
		cases = append(cases, compatibilityCase{"body-decode", []string{encoded}})
	}
	cases = append(cases, compatibilityCase{"credential-encrypt", []string{"synthetic-plain", "short"}})
	for _, encoded := range []string{"", "!!!!", "AAAA", "YWI", "YWI=garbage"} {
		cases = append(cases, compatibilityCase{"credential-decrypt", []string{encoded, syntheticMachineKey}})
	}
	for _, raw := range []string{"{", "{}", `{"uid":null}`, `{"uid":"synthetic-user-0001","organization_tags":1}`} {
		cases = append(cases, compatibilityCase{"runtime", []string{raw}})
	}
	for _, encoded := range []string{"", "!!!!", "UU1DAQ=="} {
		cases = append(cases, compatibilityCase{"model-decrypt", []string{encoded, syntheticUID}})
	}
	return compatibilityInput{cases}
}

func compatibilityCalls(input compatibilityCase) []hostCall {
	if input.Operation == "runtime" {
		return []hostCall{{Kind: hostEntropy, Length: 16}, {Kind: hostEntropy, Length: 109}}
	}
	if input.Operation == "body-roundtrip" {
		return []hostCall{{Kind: hostEntropy, Length: 16}, {Kind: hostEntropy, Length: 109}, {Kind: hostClock}, {Kind: hostEntropy, Length: 16}}
	}
	return nil
}

func runCompatibilityCase(ctx context.Context, backend *wasmBackend, input compatibilityCase, version string) (result compatibilityResult, err error) {
	switch input.Operation {
	case "body-roundtrip":
		user, _ := json.Marshal(inferUser{syntheticUID, noOrgCallerInfo, noOrgCallerKey, "", []string{}, false})
		scene, _ := json.Marshal(inferScene{"5", "cli", "agent", "assistant"})
		ptr, e := backend.newContext(ctx, syntheticMachineID, version, string(user), string(scene))
		if e != nil {
			return result, e
		}
		prepared, e := backend.prepareInfer(ctx, ptr, syntheticEndpoint, input.Args[0], "", "system")
		closeErr := backend.freeContext(ctx, ptr)
		if e != nil {
			return result, e
		}
		if closeErr != nil {
			return result, closeErr
		}
		result.Output = prepared.Body
		result.Decoded, err = backend.callString(ctx, "decrypt_server_response", prepared.Body)
	case "body-decode":
		result.Output, err = backend.callString(ctx, "decrypt_server_response", input.Args...)
	case "credential-encrypt":
		result.Output, err = backend.callString(ctx, "credential_storage_encrypt", input.Args...)
	case "credential-decrypt":
		result.Output, err = backend.callString(ctx, "credential_storage_decrypt", input.Args...)
	case "runtime":
		result.Output, err = backend.callString(ctx, "generate_runtime_auth_fields", input.Args...)
	case "model-decrypt":
		result.Output, err = backend.callString(ctx, "model_cache_decrypt", input.Args...)
	default:
		return result, fail("fixture-synthetic-schema")
	}
	if err != nil {
		// A Rust Result error is a compatibility observation. A host, ABI, or
		// execution failure is never converted into an expected input rejection.
		if categoryOf(err) != "wasm-result" {
			return result, err
		}
		result.Failed = true
	}
	return result, nil
}

func captureCompatibility(ctx context.Context, backend *wasmBackend, identity oracleIdentity) (fixtureDocument, error) {
	input := syntheticCompatibilityInput()
	expected := compatibilityExpected{Results: make([]compatibilityResult, 0, len(input.Cases))}
	for _, test := range input.Cases {
		host := newCaptureHost()
		backend.setReplay(host)
		result, err := runCompatibilityCase(ctx, backend, test, identity.Version)
		if err != nil {
			return fixtureDocument{}, err
		}
		if !reflect.DeepEqual(host.calls, compatibilityCalls(test)) {
			return fixtureDocument{}, fail("transcript-order")
		}
		result.Transcript = host.value
		expected.Results = append(expected.Results, result)
	}
	in, _ := json.Marshal(input)
	out, _ := json.Marshal(expected)
	return fixtureDocument{identity, in, newCaptureHost().value, out}, nil
}

func validateCompatibilityFixture(fixture fixtureDocument) error {
	if fixture.Oracle.Version != upgradeVersion || len(fixture.Transcript.UnixMilli) != 0 || len(fixture.Transcript.EntropyReads) != 0 {
		return fail("fixture-synthetic-schema")
	}
	var input compatibilityInput
	var expected compatibilityExpected
	if decodeStrictValue(fixture.Input, &input) != nil || decodeStrictValue(fixture.Expected, &expected) != nil || !reflect.DeepEqual(input, syntheticCompatibilityInput()) || len(input.Cases) != len(expected.Results) {
		return fail("fixture-synthetic-schema")
	}
	encoded, _ := json.Marshal(expected)
	if stringHash(string(encoded)) != compatibilityExpectedHash {
		return fail("fixture-synthetic-schema")
	}
	for i, test := range input.Cases {
		name := "credential.json"
		if test.Operation == "runtime" {
			name = "runtime-fields.json"
		}
		if test.Operation == "body-roundtrip" {
			name = "infer-user-no-org.json"
		}
		if err := validateTranscript(name, expected.Results[i].Transcript); err != nil {
			return err
		}
	}
	return nil
}

const compatibilityExpectedHash = "36a1dc00a8f162096d08de6554a9ec1c4ad8bc9f93eeb3f1b8e6ba235f011c47"

func verifyCompatibility(ctx context.Context, source []byte, fixture fixtureDocument, version string) error {
	backend, err := newWASMBackend(ctx, source)
	if err != nil {
		return err
	}
	defer backend.Close(ctx)
	input, err := mustDecode[compatibilityInput](fixture.Input)
	if err != nil {
		return err
	}
	expected, err := mustDecode[compatibilityExpected](fixture.Expected)
	if err != nil || len(input.Cases) != len(expected.Results) {
		return fail("fixture-schema")
	}
	for i, test := range input.Cases {
		want := expected.Results[i]
		replay := newOrderedReplay(want.Transcript, compatibilityCalls(test))
		backend.setReplay(replay)
		got, err := runCompatibilityCase(ctx, backend, test, version)
		if err != nil {
			return err
		}
		if err := replay.Exhausted(); err != nil {
			return err
		}
		if got.Output != want.Output || got.Decoded != want.Decoded || got.Failed != want.Failed {
			return fail("compatibility-output")
		}
	}
	return nil
}

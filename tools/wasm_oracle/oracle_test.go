package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionRegistrySelectsExactIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		identity oracleIdentity
		category string
	}{
		{"historical", oracleIdentity{"1.1.34", 297238, "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"}, "fixture-manifest-hash"},
		{"new", oracleIdentity{"1.1.74", 298606, "6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d"}, "fixture-manifest-hash"},
		{"unknown version", oracleIdentity{"1.1.75", 298606, "6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d"}, "fixture-oracle-identity"},
		{"relabeled historical", oracleIdentity{"1.1.74", 297238, "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"}, "fixture-oracle-identity"},
		{"mixed hash", oracleIdentity{"1.1.34", 297238, "6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d"}, "fixture-oracle-identity"},
		{"mixed size", oracleIdentity{"1.1.74", 297238, "6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d"}, "fixture-oracle-identity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir, _ := writeSyntheticFixtureSet(t)
			manifest := fixtureManifest{Version: test.identity.Version, Size: test.identity.Size, SHA256: test.identity.SHA256, Documents: map[string]string{}}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), canonicalBytes(t, manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if status := run(context.Background(), []string{"--fixtures", dir, "validate-fixtures"}, &out); status != 1 {
				t.Fatalf("status = %d", status)
			}
			if !strings.Contains(out.String(), `"category":"`+test.category+`"`) {
				t.Fatalf("safe output = %s", out.String())
			}
		})
	}
}

func TestCaptureArgumentsAreExplicitAndRestricted(t *testing.T) {
	if _, err := parseArgs([]string{"--wasm", "synthetic.wasm", "--fixtures", "synthetic-seeds", "--version", "1.1.74", "--output", "synthetic-new-directory", "capture-fixtures"}); err != nil {
		t.Fatalf("explicit capture arguments rejected: %s", categoryOf(err))
	}
	for _, args := range [][]string{
		{"capture-fixtures"},
		{"--wasm", "synthetic.wasm", "--fixtures", "synthetic-seeds", "capture-fixtures"},
		{"--wasm", "synthetic.wasm", "--fixtures", "synthetic-seeds", "--version", "unknown", "--output", "synthetic-new-directory", "capture-fixtures"},
		{"--fixtures", "synthetic-seeds", "--output", "synthetic-new-directory", "validate-fixtures"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Fatal("unsafe capture arguments accepted")
		}
	}
}

func TestDecodeResultLayoutsUsesObjectOffsetPlus12(t *testing.T) {
	stringResult, err := decodeStringResult([]byte{1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0})
	if err != nil || stringResult.ptr != 1 || stringResult.length != 2 || stringResult.errorRef != 3 || stringResult.errorFlag != 4 {
		t.Fatalf("string result = %#v, %v", stringResult, err)
	}
	objectResult, err := decodeObjectResult([]byte{5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0})
	if err != nil || objectResult.ptr != 5 || objectResult.errorRef != 6 || objectResult.errorFlag != 7 {
		t.Fatalf("object result = %#v, %v", objectResult, err)
	}
	if objectResultOffset != 12 {
		t.Fatalf("object result offset = %d, want 12", objectResultOffset)
	}
}

func TestOrderedReplayEnforcesGlobalOrderAndExhaustion(t *testing.T) {
	replay := newOrderedReplay(transcript{UnixMilli: []int64{1234}, EntropyReads: []entropyRead{{Length: 2, Bytes: []byte("ab")}}}, []hostCall{{Kind: hostClock}, {Kind: hostEntropy, Length: 2}})
	if err := replay.Read(make([]byte, 2)); categoryOf(err) != "transcript-order" {
		t.Fatalf("entropy before clock category = %q", categoryOf(err))
	}
	replay = newOrderedReplay(transcript{UnixMilli: []int64{1234}, EntropyReads: []entropyRead{{Length: 2, Bytes: []byte("ab")}}}, []hostCall{{Kind: hostClock}, {Kind: hostEntropy, Length: 2}})
	if got, err := replay.Now(); err != nil || got.UnixMilli() != 1234 {
		t.Fatalf("Now = %v, %v", got, err)
	}
	buf := make([]byte, 2)
	if err := replay.Read(buf); err != nil || string(buf) != "ab" {
		t.Fatalf("Read = %q, %v", buf, err)
	}
	if err := replay.Exhausted(); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.Now(); categoryOf(err) != "transcript-order-exhausted" {
		t.Fatalf("extra clock category = %q", categoryOf(err))
	}
}

func TestGuardedOutputRedactsPanics(t *testing.T) {
	var out bytes.Buffer
	status := guarded(&out, func() int { panic("Authorization synthetic-access-token traceback") })
	if status != 1 || out.String() != "{\"operation\":\"verify-fixtures\",\"transcript\":\"unavailable\",\"result\":\"FAIL\",\"category\":\"internal\"}\n" {
		t.Fatalf("status=%d output=%q", status, out.String())
	}
}

func TestSafeOutputNeverContainsContent(t *testing.T) {
	var out bytes.Buffer
	emitStatus(&out, statusLine{Operation: "verify-fixtures", Transcript: "unavailable", Result: "FAIL", Category: "internal"})
	got := out.String()
	if got != "{\"operation\":\"verify-fixtures\",\"transcript\":\"unavailable\",\"result\":\"FAIL\",\"category\":\"internal\"}\n" {
		t.Fatalf("output = %q", got)
	}
	for _, forbidden := range []string{"Authorization", "synthetic-access-token", "synthetic-user", "traceback", "secret"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("output contains %q", forbidden)
		}
	}
}

func TestReadBoundedRegularFileRejectsSymlinkDirectoryAndOversize(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(regular, 3, "read"); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir} {
		if _, err := readBoundedRegularFile(path, 10, "read"); categoryOf(err) != "read" {
			t.Fatalf("%s category = %q", path, categoryOf(err))
		}
	}
	if _, err := readBoundedRegularFile(regular, 2, "read"); categoryOf(err) != "read" {
		t.Fatalf("oversize category = %q", categoryOf(err))
	}
}

func TestFixtureInventoryIsExactlySixRegularFiles(t *testing.T) {
	if len(fixtureJSONNames) != 6 {
		t.Fatalf("fixture JSON inventory length = %d, want 6", len(fixtureJSONNames))
	}
	dir := t.TempDir()
	for _, name := range fixtureJSONNames {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateInventory(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unexpected.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateInventory(dir); categoryOf(err) != "fixture-inventory" {
		t.Fatalf("unexpected file category = %q", categoryOf(err))
	}
	if err := os.Remove(filepath.Join(dir, "unexpected.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "credential.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "credential.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateInventory(dir); categoryOf(err) != "fixture-inventory" {
		t.Fatalf("directory category = %q", categoryOf(err))
	}
}

func TestStrictCanonicalJSONAndLF(t *testing.T) {
	var value map[string]any
	if err := decodeCanonicalJSON([]byte("{\n  \"a\": 1\n}\n"), &value); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		[]byte("{\r\n  \"a\": 1\r\n}\r\n"),
		[]byte("{\"a\":1}\n"),
		[]byte("{\n  \"a\": 1\n}\n\n"),
		[]byte("{\n  \"a\": 1,\n  \"a\": 2\n}\n"),
	} {
		if err := decodeCanonicalJSON(invalid, &value); err == nil {
			t.Fatalf("accepted noncanonical JSON %q", invalid)
		}
	}
}

func TestPinnedPolicyRejectsTamperedDocumentWithRecomputedManifest(t *testing.T) {
	dir, policy := writeSyntheticFixtureSet(t)
	path := filepath.Join(dir, "credential.json")
	var fixture fixtureDocument
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(fixture.Input, &input); err != nil {
		t.Fatal(err)
	}
	input["plain"] = "tampered"
	fixture.Input, _ = json.Marshal(input)
	tampered := canonicalBytes(t, fixture)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	var manifest fixtureManifest
	manifestData, _ := os.ReadFile(manifestPath)
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tampered)
	manifest.Documents["credential.json"] = hex.EncodeToString(sum[:])
	if err := os.WriteFile(manifestPath, canonicalBytes(t, manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateFixtureSet(dir, policy); categoryOf(err) != "fixture-manifest-hash" {
		t.Fatalf("category = %q", categoryOf(err))
	}
}

func TestFixtureSafetyScanRejectsSensitiveMarkers(t *testing.T) {
	for _, marker := range []string{"/home/", "/Users/", "/root/", `C:\\Users\\`, ".qoder", "re/secrets", "SENTINEL-PROTOCOL-SECRET", "-----BEGIN PRIVATE KEY-----", "AKIA", "github_pat_", "ghp_", "xoxb-"} {
		if err := validateFixtureSafety("synthetic.json", []byte(`{"value":"`+marker+`"}`)); categoryOf(err) != "fixture-safety" {
			t.Fatalf("marker %q category = %q", marker, categoryOf(err))
		}
	}
	if err := validateFixtureSafety("synthetic.json", []byte(`{"value":"synthetic-safe"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticSchemaRejectsUnsafeIdentity(t *testing.T) {
	dir, policy := writeSyntheticFixtureSet(t)
	path := filepath.Join(dir, "model-cache.json")
	var fixture fixtureDocument
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.Input = json.RawMessage(`{"plain":"{}","uid":"real-user"}`)
	changed := canonicalBytes(t, fixture)
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(changed)
	policy.DocumentHashes["model-cache.json"] = hex.EncodeToString(sum[:])
	var manifest fixtureManifest
	manifestData, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	_ = json.Unmarshal(manifestData, &manifest)
	manifest.Documents = cloneMap(policy.DocumentHashes)
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), canonicalBytes(t, manifest), 0o600)
	if _, err := validateFixtureSet(dir, policy); categoryOf(err) != "fixture-synthetic-schema" {
		t.Fatalf("category = %q", categoryOf(err))
	}
}

func writeSyntheticFixtureSet(t *testing.T) (string, fixturePolicy) {
	t.Helper()
	dir := t.TempDir()
	identity := oracleIdentity{Version: pinnedVersion, Size: pinnedWASMSize, SHA256: pinnedWASMHash}
	docs := map[string]fixtureDocument{
		"credential.json":        {Oracle: identity, Input: json.RawMessage(`{"machine_key":"00000000-1111-42","plain":"{\"uid\":\"synthetic-user-0001\",\"organization_id\":\"synthetic-org-0001\",\"access_token\":\"synthetic-access-token-0001\"}"}`), Transcript: transcript{}, Expected: json.RawMessage(`{"decrypted":"{\"uid\":\"synthetic-user-0001\",\"organization_id\":\"synthetic-org-0001\",\"access_token\":\"synthetic-access-token-0001\"}","encrypted":"synthetic-encrypted"}`)},
		"runtime-fields.json":    {Oracle: identity, Input: json.RawMessage(`{"raw":"{\"uid\":\"synthetic-user-0001\",\"organization_id\":\"synthetic-org-0001\"}"}`), Transcript: transcript{}, Expected: json.RawMessage(`{"raw":"{}","encrypt_user_info":"synthetic-encrypted","key":"synthetic-key"}`)},
		"model-cache.json":       {Oracle: identity, Input: json.RawMessage(`{"plain":"{}","uid":"synthetic-user-0001"}`), Transcript: transcript{}, Expected: json.RawMessage(`{"decrypted":"{}","encrypted":"synthetic-encrypted"}`)},
		"infer-user.json":        {Oracle: identity, Input: json.RawMessage(`{"machine_id":"00000000-1111-4222-8333-444444444444","version":"1.1.34","user":{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001"},"scene":{},"endpoint":"https://example.invalid/base","body_raw":"{}","model_key":"auto","model_source":"system"}`), Transcript: transcript{UnixMilli: []int64{1}, EntropyReads: []entropyRead{{Length: 1, Bytes: []byte{1}}}}, Expected: json.RawMessage(`{"url":"https://example.invalid","header":{},"body_string":"x","body_bytes":"eA=="}`)},
		"infer-user-no-org.json": {Oracle: identity, Input: json.RawMessage(`{"machine_id":"00000000-1111-4222-8333-444444444444","version":"1.1.34","user":{"uid":"synthetic-user-0001","encrypt_user_info":"synthetic-caller-info-not-effective","key":"synthetic-caller-key-not-effective","organization_id":"","organization_tags":[],"data_policy_agreed":false},"scene":{"client_type":"5","business_product":"cli","business_type":"agent","scene":"assistant"},"endpoint":"https://example.invalid/base","body_raw":"{}","model_key":"","model_source":"system"}`), Transcript: transcript{UnixMilli: []int64{1}, EntropyReads: []entropyRead{{Length: 1, Bytes: []byte{1}}}}, Expected: json.RawMessage(`{"url":"https://example.invalid","header":{"Cosy-Key":["synthetic-caller-key-not-effective"]},"body_string":"x","body_bytes":"eA=="}`)},
	}
	hashes := map[string]string{}
	for name, doc := range docs {
		data := canonicalBytes(t, doc)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest := fixtureManifest{Version: identity.Version, Size: identity.Size, SHA256: identity.SHA256, Documents: cloneMap(hashes)}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), canonicalBytes(t, manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, fixturePolicy{Identity: identity, DocumentHashes: hashes}
}

func canonicalBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func cloneMap(source map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range source {
		out[k] = v
	}
	return out
}

func TestEntropyReadJSONUsesStrictPaddedBase64(t *testing.T) {
	var read entropyRead
	if err := json.Unmarshal([]byte(`{"length":2,"bytes":"YWI="}`), &read); err != nil || string(read.Bytes) != "ab" {
		t.Fatalf("read=%#v err=%v", read, err)
	}
	for _, encoded := range []string{"YWI", base64.RawStdEncoding.EncodeToString([]byte("ab")), "YWI=garbage"} {
		if err := json.Unmarshal([]byte(`{"length":2,"bytes":"`+encoded+`"}`), &read); err == nil {
			t.Fatalf("accepted %q", encoded)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func authorizedPaths(t *testing.T) (string, string) {
	t.Helper()
	wasmPath := os.Getenv("QODER2API_WASM_ORACLE")
	fixturePath := os.Getenv("QODER2API_WASM_ORACLE_FIXTURES")
	if wasmPath == "" || fixturePath == "" {
		t.Skip("explicit authorized WASM and fixture paths are required")
	}
	return wasmPath, fixturePath
}

func TestAuthorizedCompatibilityHostOrder(t *testing.T) {
	path := os.Getenv("QODER2API_WASM_CAPTURE_ORACLE")
	if path == "" {
		t.Skip("explicit capture oracle is required")
	}
	source, err := readBoundedRegularFile(path, upgradeWASMSize, "wasm-read")
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	backend, err := newWASMBackend(context.Background(), source)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	defer backend.Close(context.Background())
	for i, test := range syntheticCompatibilityInput().Cases {
		host := newCaptureHost()
		backend.setReplay(host)
		result, err := runCompatibilityCase(context.Background(), backend, test, upgradeVersion)
		if err != nil {
			t.Fatalf("case %d operation %s category %s", i, test.Operation, categoryOf(err))
		}
		if !reflect.DeepEqual(host.calls, compatibilityCalls(test)) {
			t.Errorf("case %d operation %s calls %v failed=%t", i, test.Operation, host.calls, result.Failed)
		}
	}
}

func TestAuthorizedCaptureIsIndependentAndReplays(t *testing.T) {
	wasmPath := os.Getenv("QODER2API_WASM_CAPTURE_ORACLE")
	seedPath := os.Getenv("QODER2API_WASM_CAPTURE_SEEDS")
	if wasmPath == "" || seedPath == "" {
		t.Skip("explicit capture oracle and synthetic seed paths are required")
	}
	destination := filepath.Join(t.TempDir(), "captured")
	var out bytes.Buffer
	args := []string{"--wasm", wasmPath, "--fixtures", seedPath, "--version", "1.1.74", "--output", destination, "capture-fixtures"}
	if status := run(context.Background(), args, &out); status != 0 {
		t.Fatalf("capture status=%d safe-output=%s", status, out.String())
	}
	data, err := os.ReadFile(filepath.Join(destination, "infer-user.json"))
	if err != nil {
		t.Fatal("missing captured infer fixture")
	}
	var fixture fixtureDocument
	if err := decodeCanonicalJSON(data, &fixture); err != nil {
		t.Fatal(categoryOf(err))
	}
	input, _ := mustDecode[inferInput](fixture.Input)
	expected, _ := mustDecode[inferExpected](fixture.Expected)
	if fixture.Oracle.Version != "1.1.74" || input.Version != "1.1.74" || len(expected.Header) != 22 || expected.Header["Cosy-Version"][0] != "1.1.74" {
		t.Fatal("capture did not use the new context version and raw WASM headers")
	}
	if _, err := os.Stat(filepath.Join(destination, "compatibility.json")); err != nil {
		t.Fatal("capture omitted body and malformed-input comparisons")
	}
	out.Reset()
	if status := run(context.Background(), args, &out); status == 0 {
		t.Fatal("capture overwrote an existing destination")
	}
	for _, forbidden := range []string{"Authorization", "synthetic-access-token", "synthetic-user", "Bearer", destination, wasmPath} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatal("capture output leaked content")
		}
	}
}

func TestAuthorizedWASMRejectsMismatchedFixtureIdentity(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	policy, err := policyForDirectory(fixturePath)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	source, err := readBoundedRegularFile(wasmPath, int64(policy.Identity.Size), "wasm-read")
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	fixtures, err := validateFixtureSet(fixturePath, policy)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	otherVersion := upgradeVersion
	if policy.Identity.Version == upgradeVersion {
		otherVersion = pinnedVersion
	}
	other, _ := policyForVersion(otherVersion)
	fixture := fixtures["credential.json"]
	fixture.Oracle = other.Identity
	fixtures["credential.json"] = fixture
	if _, err := verifyFixtures(context.Background(), source, fixtures, &bytes.Buffer{}); err == nil {
		t.Fatal("mismatched oracle/fixture identity accepted")
	}
}

func TestAuthorizedWASMCompatibility(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	compatibilityPath := os.Getenv("QODER2API_WASM_COMPATIBILITY_FIXTURES")
	if compatibilityPath == "" {
		t.Skip("explicit compatibility fixture path is required")
	}
	policy, err := policyForDirectory(fixturePath)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	source, err := readBoundedRegularFile(wasmPath, int64(policy.Identity.Size), "wasm-read")
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	if err := validateWASMForIdentity(source, policy.Identity); err != nil {
		t.Fatal(categoryOf(err))
	}
	upgrade, _ := policyForVersion(upgradeVersion)
	fixtures, err := validateFixtureSet(compatibilityPath, upgrade)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	if err := verifyCompatibility(context.Background(), source, fixtures["compatibility.json"], policy.Identity.Version); err != nil {
		t.Fatal(categoryOf(err))
	}
}

func TestAuthorizedWASMFixtureIntegration(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	var output bytes.Buffer
	status := run(context.Background(), []string{"--wasm", wasmPath, "--fixtures", fixturePath, "verify-fixtures"}, &output)
	if status != 0 {
		t.Fatalf("status=%d safe-output=%q", status, output.String())
	}
	wantOperations := []string{`"operation":"credential"`, `"operation":"runtime"`, `"operation":"model-cache"`, `"operation":"infer"`, `"operation":"infer-no-org"`}
	cursor := 0
	for _, operation := range wantOperations {
		index := strings.Index(output.String()[cursor:], operation)
		if index < 0 {
			t.Fatalf("missing ordered operation %s in %q", operation, output.String())
		}
		cursor += index + len(operation)
	}
	for _, forbidden := range []string{"Authorization", "synthetic-access-token", "synthetic-user-0001", "synthetic-org-0001", "Bearer", "Traceback"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("safe output contains %q", forbidden)
		}
	}
}

func TestAuthorizedRecomputedManifestNestedTamperingRejected(t *testing.T) {
	fixturePath := os.Getenv("QODER2API_WASM_ORACLE_FIXTURES")
	if fixturePath == "" {
		t.Skip("explicit frozen fixture path is required")
	}
	tests := []struct {
		name     string
		document string
		category string
		mutate   func(*fixtureDocument)
	}{
		{name: "credential nested extra", document: "credential.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			var plain map[string]any
			_ = json.Unmarshal([]byte(input["plain"].(string)), &plain)
			plain["scope"] = "synthetic-extra"
			encoded, _ := json.Marshal(plain)
			input["plain"] = string(encoded)
			f.Input, _ = json.Marshal(input)
		}},
		{name: "token marker", document: "credential.json", category: "fixture-safety", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			input["plain"] = `{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001","access_token":"github_pat_sentinel"}`
			f.Input, _ = json.Marshal(input)
		}},
		{name: "prompt substitution", document: "infer-user.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			var body map[string]any
			_ = json.Unmarshal([]byte(input["body_raw"].(string)), &body)
			body["system"] = "synthetic-changed-prompt"
			encoded, _ := json.Marshal(body)
			input["body_raw"] = string(encoded)
			f.Input, _ = json.Marshal(input)
		}},
		{name: "user nested extra", document: "infer-user.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var input map[string]any
			_ = json.Unmarshal(f.Input, &input)
			input["user"].(map[string]any)["access_token"] = "synthetic-token-substitution"
			f.Input, _ = json.Marshal(input)
		}},
		{name: "no-org caller key substitution", document: "infer-user-no-org.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var expected inferFixtureExpectedPolicy
			_ = json.Unmarshal(f.Expected, &expected)
			expected.Header["Cosy-Key"] = []string{"synthetic-substituted-key"}
			f.Expected, _ = json.Marshal(expected)
		}},
		{name: "arbitrary expected", document: "model-cache.json", category: "fixture-synthetic-schema", mutate: func(f *fixtureDocument) {
			var expected map[string]any
			_ = json.Unmarshal(f.Expected, &expected)
			expected["encrypted"] = "synthetic-arbitrary-expected"
			f.Expected, _ = json.Marshal(expected)
		}},
		{name: "extra transcript read", document: "runtime-fields.json", category: "fixture-transcript-shape", mutate: func(f *fixtureDocument) {
			f.Transcript.EntropyReads = append(f.Transcript.EntropyReads, entropyRead{Length: 1, Bytes: []byte{1}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := copyFrozenFixtureSet(t, fixturePath)
			policy, err := policyForDirectory(fixturePath)
			if err != nil {
				t.Fatal(categoryOf(err))
			}
			policy.DocumentHashes = cloneMap(policy.DocumentHashes)
			path := filepath.Join(dir, test.document)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture fixtureDocument
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			test.mutate(&fixture)
			changed := canonicalBytes(t, fixture)
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(changed)
			policy.DocumentHashes[test.document] = hex.EncodeToString(sum[:])
			manifestPath := filepath.Join(dir, "manifest.json")
			manifestData, _ := os.ReadFile(manifestPath)
			var manifest fixtureManifest
			_ = json.Unmarshal(manifestData, &manifest)
			manifest.Documents = cloneMap(policy.DocumentHashes)
			if err := os.WriteFile(manifestPath, canonicalBytes(t, manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := validateFixtureSet(dir, policy); categoryOf(err) != test.category {
				t.Fatalf("category = %q, want %q", categoryOf(err), test.category)
			}
		})
	}
}

func copyFrozenFixtureSet(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	policy, err := policyForDirectory(source)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	for _, name := range append(fixtureNamesForVersion(policy.Identity.Version), "manifest.json") {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAuthorizedWASMFreeAccounting(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	policy, err := policyForDirectory(fixturePath)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	source, err := readBoundedRegularFile(wasmPath, int64(policy.Identity.Size), "wasm-read")
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	fixtures, err := validateFixtureSet(fixturePath, policy)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	accounting, err := verifyFixtures(context.Background(), source, fixtures, &bytes.Buffer{})
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	if accounting != (freeAccounting{ResultStrings: 9, Contexts: 2, RequestResults: 2}) {
		t.Fatalf("free accounting = %#v", accounting)
	}
}

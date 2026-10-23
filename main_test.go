package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeModelCacheDecryptor struct {
	calls int
	input string
	uid   string
	data  []byte
	err   error
}

func (f *fakeModelCacheDecryptor) Decrypt(_ context.Context, input, uid string) ([]byte, error) {
	f.calls++
	f.input = input
	f.uid = uid
	return f.data, f.err
}

func modelByKey(catalog []*modelConfig, key string) *modelConfig {
	for _, model := range catalog {
		if model.Key == key {
			return model
		}
	}
	return nil
}

func TestLoadCatalogExplicitFileBypassesDecryptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"chat":[{"key":"explicit","display_name":"Explicit"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &fakeModelCacheDecryptor{err: errors.New("must not be called")}

	catalog := loadCatalog(context.Background(), decryptor, filepath.Join(t.TempDir(), "auth", "user"), "synthetic-user", path, t.Logf)

	if decryptor.calls != 0 {
		t.Fatalf("Decrypt() calls = %d, want 0", decryptor.calls)
	}
	if model := modelByKey(catalog, "explicit"); model == nil || !model.Enable || model.Format != "openai" || model.Source != "system" {
		t.Fatalf("explicit model = %#v, want merged defaults", model)
	}
}

func TestLoadCatalogKeepsChatWhenBYOKGroupIsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	data := []byte(`{"chat":[{"key":"cached","display_name":"Cached"}],"byok_teams":{}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if modelByKey(loadCatalog(context.Background(), nil, "", "", path, t.Logf), "cached") == nil {
		t.Fatal("malformed byok_teams discarded the valid chat catalog")
	}
}

func TestLoadCatalogMergesBYOKGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	data := []byte(`{
		"chat":[{"key":"cached-chat","display_name":"Cached Chat"}],
		"byok_enterprise":[{"key":"enterprise-byok","display_name":"Enterprise BYOK","source":"organization"}],
		"byok_teams":[null,{"display_name":"Invalid"},{"key":"team-byok","display_name":"Team BYOK","source":"byokTeams"}]
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	resolver := newModelResolver(loadCatalog(context.Background(), nil, "", "", path, t.Logf), nil, "", "")
	for _, want := range []struct {
		key, name, source string
	}{
		{key: "enterprise-byok", name: "Enterprise BYOK", source: "organization"},
		{key: "team-byok", name: "Team BYOK", source: "byokTeams"},
	} {
		model, ok := resolver.byKey[want.key]
		if !ok || !model.Enable || model.Source != want.source {
			t.Errorf("catalog model %q = %+v, want enabled source %q", want.key, model, want.source)
			continue
		}
		if got := resolver.publicID(model); got != want.name {
			t.Errorf("publicID(%q) = %q, want %q", want.key, got, want.name)
		}
		if got := resolver.resolve(want.name); got.Key != want.key || got.Source != want.source {
			t.Errorf("resolve(%q) = %+v, want key %q source %q", want.name, got, want.key, want.source)
		}
	}
	if _, ok := resolver.byKey[""]; ok {
		t.Fatal("invalid BYOK entry produced an empty model key")
	}
}

func TestLoadCatalogUsesModelCacheDecryptor(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-user"
	cachePath := filepath.Join(root, ".models", uid, "catalog-v6")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("  encrypted-catalog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &fakeModelCacheDecryptor{data: []byte(`{"chat":[{"key":"cached","display_name":"Cached","context_config":{"default":{"token_count":321000}}}]}`)}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

	if decryptor.calls != 1 || decryptor.input != "encrypted-catalog" || decryptor.uid != uid {
		t.Fatalf("Decrypt() = calls %d, input %q, uid %q", decryptor.calls, decryptor.input, decryptor.uid)
	}
	if model := modelByKey(catalog, "cached"); model == nil || model.MaxInputTokens != 321000 || !model.Enable {
		t.Fatalf("cached model = %#v, want merged cache model", model)
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("merged catalog lost builtin auto model")
	}
}

func TestLoadCatalogFallsBackAfterDecryptError(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-user"
	cachePath := filepath.Join(root, ".models", uid, "catalog-v6")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &fakeModelCacheDecryptor{err: errors.New("synthetic decrypt failure")}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

	if decryptor.calls != 1 {
		t.Fatalf("Decrypt() calls = %d, want 1", decryptor.calls)
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("fallback catalog is missing builtin auto model")
	}
}

func TestLoadCatalogNilDecryptorFallsBack(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	cachePath := filepath.Join(root, ".models", "synthetic-user", "catalog-v6")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := loadCatalog(context.Background(), nil, authFile, "synthetic-user", "", t.Logf)
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("fallback catalog is missing builtin auto model")
	}
}

func TestLoadCatalogMissingCacheDoesNotDecrypt(t *testing.T) {
	decryptor := &fakeModelCacheDecryptor{}
	catalog := loadCatalog(context.Background(), decryptor, filepath.Join(t.TempDir(), ".auth", "user"), "synthetic-user", "", t.Logf)
	if decryptor.calls != 0 {
		t.Fatalf("Decrypt() calls = %d, want 0", decryptor.calls)
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("catalog is missing builtin auto model")
	}
}

func TestLoadCatalogMergesNativeQMCV1Cache(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-native-catalog-user"
	plain := []byte(`{"chat":[{"key":"native-cached","display_name":"Native Cached","context_config":{"default":{"token_count":654321}}}]}`)
	blob, err := encryptQMCV1ForTest(plain, uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("catalog plaintext length %d: encrypt returned kind %q", len(plain), protocolErrorKindOf(err))
	}
	writeDynamicCatalogCache(t, authFile, uid, blob)

	catalog := loadCatalog(context.Background(), nativeModelCacheDecryptor{}, authFile, uid, "", func(string, ...any) {})

	model := modelByKey(catalog, "native-cached")
	if model == nil || !model.Enable || model.Format != "openai" || model.Source != "system" || model.MaxInputTokens != 654321 {
		t.Fatal("native QMC catalog model was not merged with approved defaults")
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("native QMC merge lost builtin auto model")
	}
}

func TestLoadCatalogNativeQMCV1FailuresRetainBuiltinCatalog(t *testing.T) {
	const uid = "synthetic-fallback-catalog-user"
	validPlain := []byte(`{"chat":[{"key":"must-not-merge","display_name":"Must Not Merge"}]}`)
	valid, err := encryptQMCV1ForTest(validPlain, uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("valid fallback setup length %d: encrypt returned kind %q", len(validPlain), protocolErrorKindOf(err))
	}
	unknownVersion := mutateCatalogQMCBlob(t, valid, len(qmcV1Prefix)-1)
	badTag := mutateCatalogQMCBlob(t, valid, -1)
	wrongUIDBlob, err := encryptQMCV1ForTest(validPlain, "synthetic-other-catalog-user", []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("wrong-UID setup length %d: encrypt returned kind %q", len(validPlain), protocolErrorKindOf(err))
	}
	invalidJSON, err := encryptQMCV1ForTest([]byte("synthetic invalid JSON"), uid, []byte("nonce-12byte"))
	if err != nil {
		t.Fatalf("invalid-JSON setup length %d: encrypt returned kind %q", len("synthetic invalid JSON"), protocolErrorKindOf(err))
	}

	tests := []struct {
		name      string
		blob      string
		writeFile bool
		decryptor modelCacheDecryptor
	}{
		{name: "unknown version", blob: unknownVersion, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "bad tag", blob: badTag, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "wrong UID", blob: wrongUIDBlob, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "invalid JSON", blob: invalidJSON, writeFile: true, decryptor: nativeModelCacheDecryptor{}},
		{name: "missing file", decryptor: nativeModelCacheDecryptor{}},
		{name: "nil decryptor", blob: valid, writeFile: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			authFile := filepath.Join(root, ".auth", "user")
			if tt.writeFile {
				writeDynamicCatalogCache(t, authFile, uid, tt.blob)
			}
			catalog := loadCatalog(context.Background(), tt.decryptor, authFile, uid, "", func(string, ...any) {})
			if modelByKey(catalog, "auto") == nil {
				t.Fatalf("case %s: fallback catalog lacks builtin auto model", tt.name)
			}
			if modelByKey(catalog, "must-not-merge") != nil {
				t.Fatalf("case %s: invalid dynamic catalog was merged", tt.name)
			}
		})
	}
}

func TestCatalogReadErrorDetailOmitsPath(t *testing.T) {
	const path = "/SENTINEL-DYNAMIC-CATALOG-UID/catalog-v6"
	err := &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	detail := catalogReadErrorDetail(err)
	if !strings.Contains(detail, "open") || !strings.Contains(detail, os.ErrPermission.Error()) {
		t.Fatalf("detail = %q, want operation and errno", detail)
	}
	if strings.Contains(detail, path) || strings.Contains(detail, "SENTINEL-DYNAMIC-CATALOG-UID") {
		t.Fatalf("detail leaked path: %q", detail)
	}
}

func TestCatalogDecryptErrorDetailUsesTypedProtocolCauseButHidesArbitraryText(t *testing.T) {
	typed := newProtocolError(
		protocolBackendIncompatible,
		"model cache data is incompatible",
		errors.New("model cache envelope authentication failed"),
	)
	typedDetail := catalogDecryptErrorDetail(typed)
	if !strings.Contains(typedDetail, string(protocolBackendIncompatible)) ||
		!strings.Contains(typedDetail, "authentication failed") {
		t.Fatalf("typed detail = %q", typedDetail)
	}

	arbitrary := errors.New("SENTINEL-DYNAMIC-CATALOG-ERROR")
	arbitraryDetail := catalogDecryptErrorDetail(arbitrary)
	if strings.Contains(arbitraryDetail, arbitrary.Error()) || arbitraryDetail == "" {
		t.Fatalf("arbitrary detail = %q", arbitraryDetail)
	}

	wrappedCancellation := fmt.Errorf("SENTINEL-CATALOG-CANCELLATION: %w", context.Canceled)
	cancellationDetail := catalogDecryptErrorDetail(wrappedCancellation)
	if cancellationDetail != context.Canceled.Error() {
		t.Fatalf("wrapped cancellation detail = %q, want %q", cancellationDetail, context.Canceled)
	}
}

func TestLoadCatalogDynamicCacheLoggingIsValueFree(t *testing.T) {
	const uid = "SENTINEL-DYNAMIC-CATALOG-UID"
	const blob = "SENTINEL-DYNAMIC-CATALOG-BLOB"
	const plain = "SENTINEL-DYNAMIC-CATALOG-PLAINTEXT"

	t.Run("decrypt failure", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		cachePath := writeDynamicCatalogCache(t, authFile, uid, blob)
		decryptErr := errors.New("SENTINEL-DYNAMIC-CATALOG-ERROR " + uid + " " + blob + " " + plain + " " + cachePath)
		decryptor := &fakeModelCacheDecryptor{err: decryptErr}
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("decrypt failure fallback lacks builtin auto model")
		}
		output := logs.String()
		if !strings.Contains(output, "catalog decrypt failed") {
			t.Fatal("decrypt failure log lacks safe category")
		}
		assertCatalogLogOmits(t, output, uid, blob, plain, cachePath, "SENTINEL-DYNAMIC-CATALOG-ERROR")
	})

	t.Run("typed decrypt failure includes safe detail", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		cachePath := writeDynamicCatalogCache(t, authFile, uid, blob)
		decryptor := &fakeModelCacheDecryptor{err: newProtocolError(
			protocolBackendIncompatible,
			"model cache data is incompatible",
			errors.New("model cache envelope authentication failed"),
		)}
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("typed decrypt failure fallback lacks builtin auto model")
		}
		output := logs.String()
		if !strings.Contains(output, "kind=backend-incompatible") || !strings.Contains(output, "authentication failed") {
			t.Fatalf("typed decrypt failure log lacks safe detail: %q", output)
		}
		assertCatalogLogOmits(t, output, uid, blob, cachePath)
	})

	t.Run("missing cache is silent", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), nativeModelCacheDecryptor{}, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("missing cache fallback lacks builtin auto model")
		}
		if output := logs.String(); output != "" {
			t.Fatalf("missing cache log = %q, want silence", output)
		}
	})

	t.Run("nil decryptor", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		cachePath := writeDynamicCatalogCache(t, authFile, uid, blob)
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), nil, authFile, uid, "", logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("nil decryptor fallback lacks builtin auto model")
		}
		output := logs.String()
		if !strings.Contains(output, "catalog decrypt failed") {
			t.Fatal("nil decryptor log lacks safe category")
		}
		assertCatalogLogOmits(t, output, uid, blob, cachePath)
	})
}

func writeDynamicCatalogCache(t *testing.T, authFile, uid, blob string) string {
	t.Helper()
	return writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", blob)
}

func writeDynamicCatalogCacheVersion(t *testing.T, authFile, uid, filename, blob string) string {
	t.Helper()
	cachePath := filepath.Clean(filepath.Join(filepath.Dir(authFile), "..", ".models", uid, filename))
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal("create dynamic catalog directory failed")
	}
	if err := os.WriteFile(cachePath, []byte(blob), 0o600); err != nil {
		t.Fatalf("write dynamic catalog blob length %d failed", len(blob))
	}
	return cachePath
}

// catalogBlobDecryptor records every decrypted input so tests can assert which
// cache file was actually consulted.
type catalogBlobDecryptor struct {
	calls []string
	data  map[string][]byte
	err   error
}

func (d *catalogBlobDecryptor) Decrypt(_ context.Context, input, _ string) ([]byte, error) {
	d.calls = append(d.calls, input)
	if d.err != nil {
		return nil, d.err
	}
	return d.data[input], nil
}

func TestLoadCatalogPrefersV7WhenBothCachesExist(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-v7-user"
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v7", "v7-blob")
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
	decryptor := &catalogBlobDecryptor{data: map[string][]byte{
		"v7-blob": []byte(`{"chat":[{"key":"v7-model","display_name":"V7"}]}`),
		"v6-blob": []byte(`{"chat":[{"key":"v6-model","display_name":"V6"}]}`),
	}}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

	if len(decryptor.calls) != 1 || decryptor.calls[0] != "v7-blob" {
		t.Fatalf("Decrypt() inputs = %v, want only [v7-blob]", decryptor.calls)
	}
	if modelByKey(catalog, "v7-model") == nil {
		t.Fatal("v7 catalog model was not merged")
	}
	if modelByKey(catalog, "v6-model") != nil {
		t.Fatal("v6 catalog model was merged even though v7 exists")
	}
}

func TestLoadCatalogFallsBackToV6OnlyWhenV7Absent(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-v6-fallback-user"
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
	decryptor := &catalogBlobDecryptor{data: map[string][]byte{
		"v6-blob": []byte(`{"chat":[{"key":"v6-model","display_name":"V6"}]}`),
	}}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

	if len(decryptor.calls) != 1 || decryptor.calls[0] != "v6-blob" {
		t.Fatalf("Decrypt() inputs = %v, want only [v6-blob]", decryptor.calls)
	}
	if model := modelByKey(catalog, "v6-model"); model == nil || !model.Enable {
		t.Fatalf("v6 fallback model = %#v, want merged enabled model", model)
	}
}

func TestLoadCatalogV7FailureNeverFallsBackToV6(t *testing.T) {
	v6Plain := []byte(`{"chat":[{"key":"must-not-merge","display_name":"Must Not Merge"}]}`)
	uid := "synthetic-v7-failure-user"

	t.Run("v7 read error", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		v7Dir := filepath.Clean(filepath.Join(filepath.Dir(authFile), "..", ".models", uid, "catalog-v7"))
		if err := os.MkdirAll(v7Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
		decryptor := &catalogBlobDecryptor{data: map[string][]byte{"v6-blob": v6Plain}}

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

		if len(decryptor.calls) != 0 {
			t.Fatalf("Decrypt() inputs = %v, want none (v6 must not hide v7 read failure)", decryptor.calls)
		}
		if modelByKey(catalog, "must-not-merge") != nil {
			t.Fatal("v6 catalog was merged after a v7 read error")
		}
		if modelByKey(catalog, "auto") == nil {
			t.Fatal("builtin fallback catalog is missing auto")
		}
	})

	t.Run("v7 decrypt failure", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v7", "v7-blob")
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
		decryptor := &catalogBlobDecryptor{data: map[string][]byte{"v6-blob": v6Plain}, err: errors.New("synthetic v7 decrypt failure")}

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

		if len(decryptor.calls) != 1 || decryptor.calls[0] != "v7-blob" {
			t.Fatalf("Decrypt() inputs = %v, want only [v7-blob]", decryptor.calls)
		}
		if modelByKey(catalog, "must-not-merge") != nil {
			t.Fatal("v6 catalog was merged after a v7 decrypt failure")
		}
		if modelByKey(catalog, "auto") == nil {
			t.Fatal("builtin fallback catalog is missing auto")
		}
	})

	t.Run("v7 invalid JSON", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v7", "v7-blob")
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
		decryptor := &catalogBlobDecryptor{data: map[string][]byte{
			"v7-blob": []byte("synthetic invalid JSON"),
			"v6-blob": v6Plain,
		}}

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

		if len(decryptor.calls) != 1 || decryptor.calls[0] != "v7-blob" {
			t.Fatalf("Decrypt() inputs = %v, want only [v7-blob]", decryptor.calls)
		}
		if modelByKey(catalog, "must-not-merge") != nil {
			t.Fatal("v6 catalog was merged after v7 plaintext failed to parse")
		}
		if modelByKey(catalog, "auto") == nil {
			t.Fatal("builtin fallback catalog is missing auto")
		}
	})

	t.Run("v7 empty plaintext", func(t *testing.T) {
		root := t.TempDir()
		authFile := filepath.Join(root, ".auth", "user")
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v7", "v7-blob")
		writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
		decryptor := &catalogBlobDecryptor{data: map[string][]byte{
			"v7-blob": []byte{},
			"v6-blob": v6Plain,
		}}

		catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", t.Logf)

		if len(decryptor.calls) != 1 || decryptor.calls[0] != "v7-blob" {
			t.Fatalf("Decrypt() inputs = %v, want only [v7-blob]", decryptor.calls)
		}
		if modelByKey(catalog, "must-not-merge") != nil {
			t.Fatal("v6 catalog was merged after v7 decrypted to empty content")
		}
		if modelByKey(catalog, "auto") == nil {
			t.Fatal("builtin fallback catalog is missing auto")
		}
	})
}

func TestLoadCatalogExplicitCatalogOverridesCacheFiles(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-explicit-override-user"
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v7", "v7-blob")
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"chat":[{"key":"explicit","display_name":"Explicit"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	decryptor := &catalogBlobDecryptor{err: errors.New("must not be called")}

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, path, t.Logf)

	if len(decryptor.calls) != 0 {
		t.Fatalf("Decrypt() inputs = %v, want none (explicit catalog must win)", decryptor.calls)
	}
	if modelByKey(catalog, "explicit") == nil {
		t.Fatal("explicit catalog model was not merged")
	}
}

func TestLoadCatalogUsesSelectedAuthFileRoot(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	authFileA := filepath.Join(rootA, ".auth", "user")
	authFileB := filepath.Join(rootB, ".auth", "user")
	uid := "synthetic-root-user"
	writeDynamicCatalogCacheVersion(t, authFileA, uid, "catalog-v7", "blob-a")
	writeDynamicCatalogCacheVersion(t, authFileB, uid, "catalog-v7", "blob-b")
	decryptor := &catalogBlobDecryptor{data: map[string][]byte{
		"blob-a": []byte(`{"chat":[{"key":"root-a-model","display_name":"Root A"}]}`),
		"blob-b": []byte(`{"chat":[{"key":"root-b-model","display_name":"Root B"}]}`),
	}}

	catalog := loadCatalog(context.Background(), decryptor, authFileA, uid, "", t.Logf)

	if len(decryptor.calls) != 1 || decryptor.calls[0] != "blob-a" {
		t.Fatalf("Decrypt() inputs = %v, want only [blob-a]", decryptor.calls)
	}
	if modelByKey(catalog, "root-a-model") == nil {
		t.Fatal("selected root's catalog model was not merged")
	}
	if modelByKey(catalog, "root-b-model") != nil {
		t.Fatal("catalog from another root leaked into the selected root")
	}
}

func writeExplicitCatalog(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCatalogEntryAliases(t *testing.T) {
	path := writeExplicitCatalog(t, `{"chat":[
		{"model_key":"model-key-alias","display_name":"Model Key Alias"},
		{"key":null,"model_key":"null-key-alias","name":"Null Key Alias"},
		{"key":"primary-key","model_key":"ignored-alias","display_name":null,"name":"Name Alias"},
		{"key":123,"model_key":"numeric-key-alias","display_name":"Numeric Key Alias"},
		{"display_name":"No Key"},
		{"key":"","model_key":"empty-key-alias","display_name":"Empty Key"},
		{"key":"empty-display","display_name":"","name":"Name Fallback"}
	]}`)
	catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)

	want := []struct{ key, name string }{
		{"model-key-alias", "Model Key Alias"},
		{"null-key-alias", "Null Key Alias"},
		{"primary-key", "Name Alias"},
		{"empty-display", ""},
	}
	for _, w := range want {
		model := modelByKey(catalog, w.key)
		if model == nil {
			t.Errorf("alias entry %q missing from catalog", w.key)
			continue
		}
		if model.DisplayName != w.name {
			t.Errorf("entry %q display_name = %q, want %q", w.key, model.DisplayName, w.name)
		}
	}
	// Explicit empty key is not nullish: the entry must be skipped rather than
	// falling back to model_key.
	if modelByKey(catalog, "empty-key-alias") != nil {
		t.Error("explicit empty key fell back to model_key")
	}
}

func TestLoadCatalogExplicitEmptyDisplayNameDoesNotFallBackToName(t *testing.T) {
	path := writeExplicitCatalog(t, `{"chat":[
		{"key":"empty-display","display_name":"","name":"Name Fallback"}
	]}`)
	catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)

	model := modelByKey(catalog, "empty-display")
	if model == nil {
		t.Fatal("entry with explicit empty display_name missing from catalog")
	}
	if model.DisplayName != "" {
		t.Fatalf("display_name = %q, want empty (explicit empty is not nullish)", model.DisplayName)
	}
}

func TestLoadCatalogEnableSemantics(t *testing.T) {
	tests := []struct {
		name string
		json string
		want bool
	}{
		{"missing enable", `{"key":"alias-model"}`, true},
		{"null enable", `{"key":"alias-model","enable":null}`, true},
		{"true enable", `{"key":"alias-model","enable":true}`, true},
		{"explicit false", `{"key":"alias-model","enable":false}`, false},
		{"numeric zero", `{"key":"alias-model","enable":0}`, false},
		{"numeric one", `{"key":"alias-model","enable":1}`, true},
		{"string enable", `{"key":"alias-model","enable":"false"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeExplicitCatalog(t, `{"chat":[`+tt.json+`]}`)
			catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)
			model := modelByKey(catalog, "alias-model")
			if model == nil {
				t.Fatalf("entry missing from catalog")
			}
			if model.Enable != tt.want {
				t.Fatalf("Enable = %v, want %v", model.Enable, tt.want)
			}
		})
	}
}

func TestLoadCatalogDisabledEntryOverridesBuiltinWithoutReenabling(t *testing.T) {
	path := writeExplicitCatalog(t, `{"chat":[{"key":"auto","enable":false}]}`)

	catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)

	model := modelByKey(catalog, "auto")
	if model == nil || model.Enable {
		t.Fatalf("disabled auto entry = %#v, want present with Enable=false", model)
	}
	if modelByKey(catalog, "gmodel") == nil {
		t.Fatal("disabled builtin override lost other builtin models")
	}
	resolver := newModelResolver(catalog, nil, "auto", "ultimate")
	if resolved := resolver.byKeyOrSynthetic("auto"); resolved == nil || resolved.Enable {
		t.Fatalf("byKeyOrSynthetic(auto) = %#v, want disabled known entry", resolved)
	}
	if resolved := resolver.resolve("auto"); resolved.Enable {
		t.Fatalf("resolve(auto) = %#v, want disabled metadata preserved", resolved)
	}
	if resolved := resolver.resolve("unknown-model"); resolved.Key != "auto" || resolved.Enable {
		t.Fatalf("resolve(unknown) = %#v, want default auto with Enable=false", resolved)
	}
}

func TestLoadCatalogGroupCollisionRules(t *testing.T) {
	path := writeExplicitCatalog(t, `{
		"chat": [
			{"key":"shared","display_name":"Chat Shared","context_config":{"default":{"token_count":500000}}},
			{"key":"chat-dup","display_name":"First"},
			{"key":"chat-dup","display_name":"Second"},
			{"key":"blocked","enable":false}
		],
		"byok_enterprise": [
			{"key":"shared","display_name":"Enterprise Shared","source":"organization"},
			{"key":"ent-dup","display_name":"First Ent"},
			{"key":"ent-dup","display_name":"Second Ent"},
			{"key":"blocked","enable":true,"display_name":"Enterprise Blocked"}
		],
		"byok_teams": [
			{"key":"ent-dup","display_name":"Team Ent"},
			{"key":"team-model","display_name":"Team Model","source":"byokTeams"}
		]
	}`)

	catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)

	if model := modelByKey(catalog, "shared"); model == nil || model.DisplayName != "Chat Shared" || model.Source != "system" {
		t.Fatalf("shared key = %#v, want chat entry to win over enterprise", model)
	}
	if model := modelByKey(catalog, "chat-dup"); model == nil || model.DisplayName != "Second" {
		t.Fatalf("chat-dup = %#v, want later chat duplicate to win", model)
	}
	if model := modelByKey(catalog, "ent-dup"); model == nil || model.DisplayName != "First Ent" {
		t.Fatalf("ent-dup = %#v, want first non-default duplicate to win", model)
	}
	if model := modelByKey(catalog, "blocked"); model == nil || model.Enable || model.DisplayName == "Enterprise Blocked" {
		t.Fatalf("blocked = %#v, want disabled chat entry to win over enterprise", model)
	}
	if model := modelByKey(catalog, "team-model"); model == nil || model.Source != "byokTeams" {
		t.Fatalf("team-model = %#v, want BYOK teams entry with source", model)
	}
	if model := modelByKey(catalog, "shared"); model != nil && model.MaxInputTokens != 500000 {
		t.Fatalf("shared max_input_tokens = %d, want context tier maximum 500000", model.MaxInputTokens)
	}
}

func TestLoadCatalogIgnoresUnsupportedSceneGroups(t *testing.T) {
	path := writeExplicitCatalog(t, `{
		"chat": [{"key":"chat-model","display_name":"Chat"}],
		"embedding": [{"key":"embedding-model","display_name":"Embedding"}],
		"service_account": [{"key":"service-account-model","display_name":"Service Account"}]
	}`)

	catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)

	if modelByKey(catalog, "chat-model") == nil {
		t.Fatal("chat scene entry missing")
	}
	for _, key := range []string{"embedding-model", "service-account-model"} {
		if modelByKey(catalog, key) != nil {
			t.Errorf("unsupported scene entry %q leaked into the catalog", key)
		}
	}
}

func TestLoadCatalogUnsupportedSceneCannotTouchSupportedKeys(t *testing.T) {
	path := writeExplicitCatalog(t, `{
		"chat": [{"key":"supported","display_name":"Chat Supported"}],
		"other_scene": [
			{"key":"auto","enable":false},
			{"key":"supported","display_name":"Scene Override"}
		]
	}`)

	catalog := loadCatalog(context.Background(), nil, "", "", path, t.Logf)

	if model := modelByKey(catalog, "supported"); model == nil || model.DisplayName != "Chat Supported" {
		t.Fatalf("supported = %#v, want chat entry untouched by unsupported scene", model)
	}
	if model := modelByKey(catalog, "auto"); model == nil || !model.Enable {
		t.Fatalf("auto = %#v, want enabled builtin untouched by unsupported scene", model)
	}
}

func TestLoadCatalogInvalidJSONLogsContentSilentDiagnostic(t *testing.T) {
	path := writeExplicitCatalog(t, `{"chat":[{"key":"leak`)

	logs, logf := captureCatalogLogs()
	catalog := loadCatalog(context.Background(), nil, "", "", path, logf)

	if modelByKey(catalog, "auto") == nil {
		t.Fatal("invalid JSON fallback lacks builtin auto model")
	}
	if !strings.Contains(logs.String(), "catalog parse failed") {
		t.Fatalf("invalid JSON log lacks parse diagnostic: %q", logs.String())
	}
	assertCatalogLogOmits(t, logs.String(), "leak")
}

func TestLoadCatalogNonCatalogShapesFailWithDiagnostic(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"null document", `null`},
		{"chat object not array", `{"chat":{"bad":"value"}}`},
		{"wrapper data", `{"data":{"chat":[{"key":"wrapped"}]}}`},
		{"only unsupported scenes", `{"embedding":[{"key":"embed"}]}`},
		{"chat null", `{"chat":null}`},
		{"byok enterprise null", `{"byok_enterprise":null}`},
		{"all null groups", `{"chat":null,"byok_enterprise":{},"byok_teams":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeExplicitCatalog(t, tt.data)
			logs, logf := captureCatalogLogs()

			catalog := loadCatalog(context.Background(), nil, "", "", path, logf)

			if modelByKey(catalog, "auto") == nil {
				t.Fatal("non-catalog shape fallback lacks builtin auto model")
			}
			for _, key := range []string{"bad", "wrapped", "embed"} {
				if modelByKey(catalog, key) != nil {
					t.Errorf("entry %q merged from non-catalog shape", key)
				}
			}
			if !strings.Contains(logs.String(), "catalog parse failed") {
				t.Fatalf("non-catalog shape log lacks parse diagnostic: %q", logs.String())
			}
		})
	}
}

func TestLoadCatalogSupportedGroupsResilience(t *testing.T) {
	t.Run("empty supported array is valid", func(t *testing.T) {
		path := writeExplicitCatalog(t, `{"chat":[]}`)
		logs, logf := captureCatalogLogs()
		_ = logs

		catalog := loadCatalog(context.Background(), nil, "", "", path, logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("empty chat array fallback lacks builtin auto model")
		}
		if output := logs.String(); output != "" {
			t.Fatalf("valid empty catalog log = %q, want silence", output)
		}
	})

	t.Run("supported group survives bad neighbors and entries", func(t *testing.T) {
		path := writeExplicitCatalog(t, `{
			"chat": [
				{"key":"good-model","display_name":"Good"},
				{"key":null},
				"not-an-object",
				{"display_name":"No Key"}
			],
			"embedding": [{"key":"ignored-model"}],
			"byok_teams": [{"key":"team-model","display_name":"Team","source":"byokTeams"}]
		}`)
		logs, logf := captureCatalogLogs()
		_ = logs

		catalog := loadCatalog(context.Background(), nil, "", "", path, logf)

		if modelByKey(catalog, "good-model") == nil {
			t.Fatal("valid chat entry discarded because of bad neighbor entries")
		}
		if model := modelByKey(catalog, "team-model"); model == nil || model.Source != "byokTeams" {
			t.Fatalf("team-model = %#v, want supported byok_teams entry preserved", model)
		}
		if modelByKey(catalog, "ignored-model") != nil {
			t.Fatal("unsupported scene entry merged alongside supported groups")
		}
	})

	t.Run("null group tolerated when a valid supported array exists", func(t *testing.T) {
		path := writeExplicitCatalog(t, `{"chat":null,"byok_teams":[]}`)
		logs, logf := captureCatalogLogs()

		catalog := loadCatalog(context.Background(), nil, "", "", path, logf)

		if modelByKey(catalog, "auto") == nil {
			t.Fatal("valid control fallback lacks builtin auto model")
		}
		if output := logs.String(); output != "" {
			t.Fatalf("valid control log = %q, want silence", output)
		}
	})
}

func TestLoadCatalogNonCatalogShapeV7NeverFallsBackToV6(t *testing.T) {
	root := t.TempDir()
	authFile := filepath.Join(root, ".auth", "user")
	uid := "synthetic-shape-failure-user"
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v7", "v7-blob")
	writeDynamicCatalogCacheVersion(t, authFile, uid, "catalog-v6", "v6-blob")
	decryptor := &catalogBlobDecryptor{data: map[string][]byte{
		"v7-blob": []byte(`null`),
		"v6-blob": []byte(`{"chat":[{"key":"must-not-merge","display_name":"Must Not Merge"}]}`),
	}}
	logs, logf := captureCatalogLogs()

	catalog := loadCatalog(context.Background(), decryptor, authFile, uid, "", logf)

	if len(decryptor.calls) != 1 || decryptor.calls[0] != "v7-blob" {
		t.Fatalf("Decrypt() inputs = %v, want only [v7-blob]", decryptor.calls)
	}
	if modelByKey(catalog, "must-not-merge") != nil {
		t.Fatal("v6 catalog was read to hide a v7 non-catalog shape failure")
	}
	if modelByKey(catalog, "auto") == nil {
		t.Fatal("shape failure fallback lacks builtin auto model")
	}
	if !strings.Contains(logs.String(), "catalog parse failed") {
		t.Fatalf("shape failure log lacks parse diagnostic: %q", logs.String())
	}
}

func mutateCatalogQMCBlob(t *testing.T, blob string, index int) string {
	t.Helper()
	envelope, err := decodeStrictStdBase64(blob)
	if err != nil {
		t.Fatalf("decode mutation setup blob length %d: strict decode failed", len(blob))
	}
	if index < 0 {
		index = len(envelope) - 1
	}
	changed := append([]byte(nil), envelope...)
	changed[index] ^= 1
	return base64.StdEncoding.EncodeToString(changed)
}

func captureCatalogLogs() (*strings.Builder, func(string, ...any)) {
	var logs strings.Builder
	return &logs, func(format string, args ...any) {
		_, _ = fmt.Fprintf(&logs, format, args...)
		logs.WriteByte('\n')
	}
}

func assertCatalogLogOmits(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && strings.Contains(output, value) {
			t.Fatal("dynamic catalog log contains a forbidden content marker")
		}
	}
}

func TestQoderProtocolVersion(t *testing.T) {
	if qoderProtocolVersion != "1.1.74" {
		t.Fatalf("qoderProtocolVersion = %q, want %q", qoderProtocolVersion, "1.1.74")
	}
	if qoderUserAgent() != "qoder/1.1.74" {
		t.Fatalf("qoderUserAgent() = %q, want %q", qoderUserAgent(), "qoder/1.1.74")
	}
}

func TestBusinessInfoUsesQoderProtocolVersion(t *testing.T) {
	got := businessInfo([]upMessage{{Role: "user", Content: "synthetic"}})
	if got["version"] != qoderProtocolVersion {
		t.Fatalf("businessInfo version = %v, want %q", got["version"], qoderProtocolVersion)
	}
}

func TestBuiltinCatalogContainsApprovedStableModels(t *testing.T) {
	models := make(map[string]*modelConfig)
	for _, model := range builtinCatalog() {
		models[model.Key] = model
	}

	cmodel, ok := models["cmodel"]
	if !ok {
		t.Fatal("builtinCatalog is missing cmodel")
	}
	if cmodel.DisplayName != "Cantus" {
		t.Fatalf("cmodel DisplayName = %q, want Cantus", cmodel.DisplayName)
	}

	gmodel, ok := models["gmodel"]
	if !ok {
		t.Fatal("builtinCatalog is missing gmodel")
	}
	if gmodel.DisplayName != "GLM-5.3" {
		t.Fatalf("gmodel DisplayName = %q, want GLM-5.3", gmodel.DisplayName)
	}
	if !gmodel.IsReasoning {
		t.Fatal("gmodel IsReasoning = false, want true")
	}
	if !gmodel.IsVL {
		t.Fatal("gmodel IsVL = false, want true")
	}
	if gmodel.MaxInputTokens != 1_000_000 {
		t.Fatalf("gmodel MaxInputTokens = %d, want 1000000", gmodel.MaxInputTokens)
	}

	if _, ok := models["qwen3.8-v116-dogfood-crit"]; ok {
		t.Fatal("builtinCatalog contains qwen3.8-v116-dogfood-crit")
	}
}

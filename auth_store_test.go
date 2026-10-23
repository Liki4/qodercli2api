package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConstructorHonorsCancellationWhileOfficialLeaseIsHeld(t *testing.T) {
	dir := t.TempDir()
	lease, err := acquireCredentialLease(context.Background(), dir, testLeaseOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = newAuthManagerWithOptions(storeTestServices(), dir, "", "", "", nil, authManagerOptions{ctx: ctx, leaseOptions: testLeaseOptions()})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("constructor ignored caller cancellation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "machine_id")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled constructor created an identity")
	}
}

func TestConstructorReportsCompromisedLeaseRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".credential-transaction.lock")
	calls := 0
	options := testLeaseOptions()
	options.heartbeat = time.Hour
	options.lstat = func(p string) (os.FileInfo, error) {
		if p == path {
			calls++
			if calls == 3 {
				changed := time.Now().Add(time.Hour)
				if err := os.Chtimes(path, changed, changed); err != nil {
					t.Fatal(err)
				}
			}
		}
		return os.Lstat(p)
	}
	_, err := newAuthManagerWithOptions(storeTestServices(), dir, "", "", "", nil, authManagerOptions{leaseOptions: options})
	if !isAuthConflict(err) {
		t.Fatalf("constructor lost lease release error: %v (checks %d)", err, calls)
	}
}

func TestMachineIDNeverRegeneratesInvalidExistingIdentity(t *testing.T) {
	for _, kind := range []string{"empty", "short", "directory", "symlink", "unreadable", "user", "user.daily", "user.test"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "machine_id")
			switch kind {
			case "empty":
				os.WriteFile(p, nil, 0600)
			case "short":
				os.WriteFile(p, []byte("short"), 0600)
			case "unreadable":
				os.WriteFile(p, []byte("synthetic-machine"), 0000)
			case "directory":
				os.Mkdir(p, 0700)
			case "symlink":
				target := filepath.Join(dir, "target")
				os.WriteFile(target, []byte("synthetic-machine"), 0600)
				symlinkOrSkipWindows(t, target, p)
			default:
				os.WriteFile(filepath.Join(dir, kind), []byte("synthetic-existing-user"), 0600)
			}
			if id, err := loadOrCreateMachineID(dir); err == nil {
				t.Fatalf("unsafe identity replaced/accepted: %q", id)
			}
			if kind == "empty" {
				b, _ := os.ReadFile(p)
				if len(b) != 0 {
					t.Fatal("empty identity replaced")
				}
			}
			if kind == "user" || kind == "user.daily" || kind == "user.test" {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing machine identity regenerated alongside user")
				}
			}
		})
	}
}

func TestConcurrentMachineIDCreationAndLegacyReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root", ".auth")
	const n = 8
	results := make(chan string, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() { defer wg.Done(); id, err := loadOrCreateMachineID(dir); results <- id; errs <- err }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var want string
	for id := range results {
		if want == "" {
			want = id
		}
		if id != want {
			t.Fatal("concurrent constructors produced different identities")
		}
	}
	assertCredentialFileMode(t, filepath.Join(dir, "machine_id"))
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatalf("directory mode = %v", info.Mode())
	}
	legacy := "valid-non-uuid-legacy-machine-identity"
	if err := os.WriteFile(filepath.Join(dir, "machine_id"), []byte(legacy+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadOrCreateMachineID(dir); err != nil || got != legacy {
		t.Fatalf("legacy identity = %q %v", got, err)
	}
}

// Legacy unit tests construct managers directly to inject codecs/contexts. Give
// those fixtures actual synthetic identities and persisted baselines, not a
// production bypass of store/lease checks.
func syntheticAuthManager(t *testing.T, a *authManager) *authManager {
	t.Helper()
	if a.authFile == "" {
		return a
	}
	if a.machineID == "" {
		a.machineID = "synthetic-machine"
	}
	dir := filepath.Dir(a.authFile)
	if _, err := ensureAuthDirectory(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "machine_id")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if _, err := f.WriteString(a.machineID); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if a.openapiBase == "" {
		a.openapiBase = defaultOpenapi
	}
	if a.webBase == "" {
		a.webBase = defaultBase
	}
	if a.inferBase == "" {
		a.inferBase = defaultInfer
	}
	a.store = &authStore{dir: dir, machineID: a.machineID, expected: authBinding{Version: 1, Region: "global", Issuer: a.openapiBase, ClientID: prodClientID}, leaseOptions: testLeaseOptions()}
	a.store.baseline, err = a.store.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	a.store.baseline.login = loginIdentity(a.ui)
	return a
}

func storeTestServices() *protocolServices {
	return &protocolServices{credentials: &fakeCredentialCodec{}, runtimeFields: &fakeRuntimeFieldGenerator{}, contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}, &fakeProtocolContext{}, &fakeProtocolContext{}, &fakeProtocolContext{}}}}
}

func TestLegacyLoadAndCloseRegenerateOnlyInMemoryWithoutBinding(t *testing.T) {
	for _, region := range []string{"global", "cn"} {
		t.Run(region, func(t *testing.T) {
			dir := t.TempDir()
			original := []byte(`{"uid":"legacy","security_oauth_token":"fake-legacy","encrypt_user_info":"legacy-fields","key":"legacy-key","future":{"large":9007199254740993}}`)
			if err := os.WriteFile(filepath.Join(dir, "machine_id"), []byte("synthetic-legacy-machine"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "user"), original, 0600); err != nil {
				t.Fatal(err)
			}
			a, err := newAuthManagerWithOptions(storeTestServices(), dir, "", "", "", nil, authManagerOptions{region: region})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.load(context.Background()); err != nil {
				t.Fatal(err)
			}
			if a.ui.EncryptUserInfo == "legacy-fields" || a.credentialDirty {
				t.Fatal("legacy upgrade failed or dirtied store on load")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			current, err := os.ReadFile(a.authFile)
			if err != nil || string(current) != string(original) {
				t.Fatal("loading rewrote legacy credentials")
			}
			if _, err := os.Stat(filepath.Join(dir, authBindingName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("loading labelled legacy credentials")
			}
		})
	}
}

func TestBindingInstalledBeforeFailedPublicationPreservesOriginalUser(t *testing.T) {
	a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A missing staged file simulates publication failure AFTER binding installation.
	tx, err := a.store.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.close()
	staged := &stagedCredential{tempPath: filepath.Join(a.store.dir, "missing-stage"), finalPath: a.authFile}
	if err := tx.publish(staged, &userInfo{UID: "synthetic"}); err == nil {
		t.Fatal("missing staged file published")
	}
	if _, err := os.Stat(filepath.Join(a.store.dir, authBindingName)); err != nil {
		t.Fatal("binding was not installed before attempted publication")
	}
	if _, err := os.Stat(a.authFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed publication changed original missing user state")
	}
}

func TestDelayedProfileEnrichmentRefusesExternalAccountChange(t *testing.T) {
	a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.ui = &userInfo{UID: "original", SecurityOAuthToken: "fake-token", Name: "Original", EncryptUserInfo: "original-fields", Key: "original-key"}
	if err := a.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	external := []byte(`{"uid":"other-login","security_oauth_token":"fake-other"}`)
	a.httpc = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if err := os.WriteFile(a.authFile, external, 0600); err != nil {
			t.Fatal(err)
		}
		return fakeJSONResponse(200, `{"uid":"original","name":"Stale enrichment"}`), nil
	})}
	a.fetchUserInfo(context.Background(), a.ui)
	if a.ui.Name != "Original" || a.credentialDirty {
		t.Fatal("stale disk enrichment mutated active profile")
	}
	got, _ := os.ReadFile(a.authFile)
	if string(got) != string(external) {
		t.Fatal("stale enrichment overwrote external login")
	}
}

func TestAuthStoreBindingIsLazyAndMismatchFailsBeforeCredentialUse(t *testing.T) {
	dir := t.TempDir()
	a, err := newAuthManagerWithOptions(storeTestServices(), dir, "", "", "", nil, authManagerOptions{region: "global"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	binding := filepath.Join(dir, ".qoder2api-auth-binding.json")
	if _, err := os.Stat(binding); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("constructor labelled legacy store")
	}
	a.ui = &userInfo{UID: "synthetic", LoginMethod: "browser", LoginTimestamp: 123, SecurityOAuthToken: "fake-token", EncryptUserInfo: "fake-runtime", Key: "fake-key"}
	if err := a.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(binding)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["region"] != "global" || metadata["issuer"] != defaultOpenapi || metadata["client_id"] != prodClientID {
		t.Fatalf("binding = %s", raw)
	}
	if _, err := newAuthManagerWithOptions(storeTestServices(), dir, "", "", "", nil, authManagerOptions{region: "cn"}); !isAuthConflict(err) {
		t.Fatalf("region mismatch = %v", err)
	}
}

func TestStagingRechecksDirectoryIdentityAfterEncryption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	services := storeTestServices()
	a, err := newAuthManager(services, dir, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.ui = &userInfo{UID: "synthetic"}
	started, release := make(chan struct{}), make(chan struct{})
	codec := services.credentials.(*fakeCredentialCodec)
	codec.encryptStarted = started
	codec.encryptRelease = release
	done := make(chan error, 1)
	go func() { done <- a.save(context.Background()) }()
	<-started
	if err := os.Rename(dir, dir+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fixed := time.Now().Add(-time.Hour)
	if err := os.Chtimes(dir, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !isAuthConflict(err) {
		t.Fatalf("directory replacement error = %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("staging wrote into a successor auth directory")
	}
}

func TestDirtyRetryNeverRebasesAfterExternalLogin(t *testing.T) {
	services := storeTestServices()
	a, err := newAuthManager(services, t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.ui = &userInfo{UID: "original", SecurityOAuthToken: "fake-old", RefreshToken: "fake-refresh", ExpireTime: 1, EncryptUserInfo: "old-fields", Key: "old-key"}
	if err := a.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	codec := services.credentials.(*fakeCredentialCodec)
	codec.encryptErr = errors.New("synthetic disk failure")
	a.httpc = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return fakeJSONResponse(200, `{"token":"fake-new","refresh_token":"fake-rotated","expires_in":7200}`), nil
	})}
	if err := a.forceRefresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.credentialDirty || a.ui.SecurityOAuthToken != "fake-new" {
		t.Fatal("ordinary failure lost usable dirty state")
	}
	external := []byte(`{"uid":"external-login","security_oauth_token":"fake-other"}`)
	if err := os.WriteFile(a.authFile, external, 0600); err != nil {
		t.Fatal(err)
	}
	codec.encryptErr = nil
	if err := a.ensureFresh(context.Background()); !isAuthConflict(err) {
		t.Fatalf("dirty retry silently rebased: %v", err)
	}
	if err := a.Close(); !isAuthConflict(err) {
		t.Fatalf("close must report last conflict: %v", err)
	}
	got, _ := os.ReadFile(a.authFile)
	if string(got) != string(external) {
		t.Fatal("dirty retry overwrote another login")
	}
}

func TestManagerRejectsInMemoryMachineIdentityChange(t *testing.T) {
	a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.ui = &userInfo{UID: "synthetic"}
	a.machineID = "different-valid-machine"
	if err := a.save(context.Background()); !isAuthConflict(err) {
		t.Fatalf("changed in-memory identity accepted: %v", err)
	}
	if _, err := os.Stat(a.authFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("credential encrypted with wrong identity")
	}
}

func TestAuthStoreRejectsChangedMachineAndUserRevision(t *testing.T) {
	for _, which := range []string{"machine_id", "user"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			a, err := newAuthManager(storeTestServices(), dir, "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			a.ui = &userInfo{UID: "first", SecurityOAuthToken: "fake-original", ExpireTime: 0, EncryptUserInfo: "fake-runtime", Key: "fake-key"}
			if err := a.save(context.Background()); err != nil {
				t.Fatal(err)
			}
			replacement := []byte(`{"uid":"another-login","security_oauth_token":"fake-other"}`)
			if which == "machine_id" {
				replacement = []byte("different-machine-identity")
			}
			if err := os.WriteFile(filepath.Join(dir, which), replacement, 0600); err != nil {
				t.Fatal(err)
			}
			a.ui.Name = "pending enrichment"
			if err := a.save(context.Background()); !isAuthConflict(err) {
				t.Fatalf("changed %s not a conflict: %v", which, err)
			}
			if err := a.Close(); err != nil && !isAuthConflict(err) {
				t.Fatalf("close error = %v", err)
			}
			got, _ := os.ReadFile(filepath.Join(dir, which))
			if string(got) != string(replacement) {
				t.Fatal("external state overwritten")
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUserInfoPreservesUnknownJSONAndCloneIsolation(t *testing.T) {
	input := []byte(`{"uid":"old","organization_tags":["original"],"future":{"large":900719925474099312345,"nested":[null,{"x":true}]},"future_null":null}`)
	var ui userInfo
	if err := json.Unmarshal(input, &ui); err != nil {
		t.Fatal(err)
	}
	clone := cloneUserInfo(&ui)
	clone.UID = "new"
	clone.OrgTags[0] = "changed"
	encoded, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["future"]) != `{"large":900719925474099312345,"nested":[null,{"x":true}]}` || string(fields["future_null"]) != "null" {
		t.Fatalf("unknown JSON lost: %s", encoded)
	}
	if string(fields["uid"]) != `"new"` || ui.UID != "old" || ui.OrgTags[0] != "original" {
		t.Fatal("typed fields or clone isolation incorrect")
	}
	clone.extra["future"][0] = '['
	clone.extra["future_null"] = []byte(`true`)
	if ui.extra["future"][0] != '{' || string(ui.extra["future_null"]) != "null" {
		t.Fatal("extra map or byte slices alias original")
	}
	ui.extra["uid"] = []byte(`"untrusted"`)
	ui.extra["name"] = []byte(`"should stay omitted"`)
	encoded, err = json.Marshal(ui)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "untrusted") || strings.Contains(string(encoded), "should stay omitted") {
		t.Fatal("extras override typed fields")
	}
}

type fakeCredentialCodec struct {
	mu sync.Mutex

	encryptCalls   int
	encryptKeys    []string
	encryptPlains  []string
	encrypted      string
	encryptErrs    []error
	encryptErr     error
	encryptStarted chan struct{}
	encryptRelease <-chan struct{}
	encryptOnce    sync.Once
	respectContext bool

	decryptCalls int
	decryptKeys  []string
	decrypted    string
	decryptErr   error
}

func (c *fakeCredentialCodec) Encrypt(ctx context.Context, plain, key string) (string, error) {
	if c.respectContext {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
	}
	c.mu.Lock()
	c.encryptCalls++
	c.encryptKeys = append(c.encryptKeys, key)
	c.encryptPlains = append(c.encryptPlains, plain)
	if c.encryptStarted != nil {
		c.encryptOnce.Do(func() { close(c.encryptStarted) })
	}
	release := c.encryptRelease
	encryptErr := c.encryptErr
	if len(c.encryptErrs) > 0 {
		encryptErr = c.encryptErrs[0]
		c.encryptErrs = c.encryptErrs[1:]
	}
	encrypted := c.encrypted
	c.mu.Unlock()
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if c.respectContext {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
	}
	if encryptErr != nil {
		return "", encryptErr
	}
	if encrypted != "" {
		return encrypted, nil
	}
	return plain, nil
}

func (c *fakeCredentialCodec) Decrypt(_ context.Context, blob, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decryptCalls++
	c.decryptKeys = append(c.decryptKeys, key)
	if c.decryptErr != nil {
		return "", c.decryptErr
	}
	if c.decrypted != "" {
		return c.decrypted, nil
	}
	return blob, nil
}

type fakeRuntimeFieldGenerator struct {
	mu             sync.Mutex
	calls          int
	inputs         []runtimeFieldInput
	output         runtimeFieldOutput
	err            error
	respectContext bool
}

func (g *fakeRuntimeFieldGenerator) Generate(ctx context.Context, input runtimeFieldInput) (runtimeFieldOutput, error) {
	if g.respectContext {
		select {
		case <-ctx.Done():
			return runtimeFieldOutput{}, ctx.Err()
		default:
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	input.OrganizationTags = slices.Clone(input.OrganizationTags)
	g.inputs = append(g.inputs, input)
	if g.err != nil {
		return runtimeFieldOutput{}, g.err
	}
	if g.output == (runtimeFieldOutput{}) {
		return runtimeFieldOutput{EncryptUserInfo: "synthetic-encrypted-user", Key: "synthetic-key"}, nil
	}
	return g.output, nil
}

type fakeProtocolContextFactory struct {
	mu             sync.Mutex
	configs        []protocolContextConfig
	contexts       []protocolContext
	errs           []error
	err            error
	respectContext bool
}

func (f *fakeProtocolContextFactory) New(ctx context.Context, config protocolContextConfig) (protocolContext, error) {
	if f.respectContext {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	config.User.OrganizationTags = slices.Clone(config.User.OrganizationTags)
	f.configs = append(f.configs, config)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	if len(f.contexts) == 0 {
		return nil, nil
	}
	next := f.contexts[0]
	f.contexts = f.contexts[1:]
	return next, nil
}

type deadlineConsumingContextFactory struct {
	mu      sync.Mutex
	configs []protocolContextConfig
	next    protocolContext
}

func (f *deadlineConsumingContextFactory) New(ctx context.Context, config protocolContextConfig) (protocolContext, error) {
	config.User.OrganizationTags = slices.Clone(config.User.OrganizationTags)
	f.mu.Lock()
	f.configs = append(f.configs, config)
	f.mu.Unlock()
	<-ctx.Done()
	if f.next != nil {
		return f.next, nil
	}
	return nil, ctx.Err()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type cancelAfterReadCloser struct {
	payload []byte
	cancel  context.CancelFunc
	done    bool
}

func (r *cancelAfterReadCloser) Read(dst []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	n := copy(dst, r.payload)
	r.payload = r.payload[n:]
	if len(r.payload) == 0 {
		r.done = true
		r.cancel()
		return n, io.EOF
	}
	return n, nil
}

func (*cancelAfterReadCloser) Close() error { return nil }

type fakeProtocolContext struct {
	prepareStarted chan struct{}
	prepareRelease <-chan struct{}
	prepareOnce    sync.Once
	prepared       *preparedRequest
	prepareErr     error

	mu                sync.Mutex
	closes            int
	closeErr          error
	closed            bool
	prepareAfterClose int
}

func (c *fakeProtocolContext) PrepareInferRequest(ctx context.Context, _ inferRequestInput) (*preparedRequest, error) {
	c.mu.Lock()
	if c.closed {
		c.prepareAfterClose++
	}
	c.mu.Unlock()
	if c.prepareStarted != nil {
		c.prepareOnce.Do(func() { close(c.prepareStarted) })
	}
	if c.prepareRelease != nil {
		select {
		case <-c.prepareRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.prepareErr != nil {
		return nil, c.prepareErr
	}
	if c.prepared != nil {
		return c.prepared, nil
	}
	return &preparedRequest{URL: "https://api.example.test", Header: make(http.Header), Body: []byte(`{}`)}, nil
}

func (c *fakeProtocolContext) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	c.closed = true
	return c.closeErr
}

func (c *fakeProtocolContext) state() (closes, prepareAfterClose int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes, c.prepareAfterClose
}

func waitForAuthContextWriter(t *testing.T, a *authManager) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for a.ctxMu.TryRLock() {
		a.ctxMu.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for auth context writer")
		}
		time.Sleep(time.Millisecond)
	}
}

func assertCredentialFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	mode := info.Mode()
	if !mode.IsRegular() {
		t.Fatalf("credential mode = %v, want regular file", mode)
	}
	if runtime.GOOS == "windows" {
		if mode.Perm()&0o222 == 0 {
			t.Fatalf("credential mode = %v, want writable/non-readonly file", mode)
		}
		return
	}
	if got := mode.Perm(); got != 0o600 {
		t.Fatalf("credential mode = %o, want 600", got)
	}
}

func symlinkOrSkipWindows(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		message := strings.ToLower(err.Error())
		if runtime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) || strings.Contains(message, "privilege") || strings.Contains(message, "not supported") || strings.Contains(message, "not permitted")) {
			t.Skipf("symlink unavailable on Windows: %v", err)
		}
		t.Fatalf("Symlink() error = %v", err)
	}
}

func TestNewAuthManagerRejectsMissingProtocolCapabilities(t *testing.T) {
	valid := &protocolServices{
		credentials:    &fakeCredentialCodec{},
		runtimeFields:  &fakeRuntimeFieldGenerator{},
		contextFactory: &fakeProtocolContextFactory{},
	}
	tests := []struct {
		name     string
		services *protocolServices
	}{
		{name: "services", services: nil},
		{name: "credentials", services: &protocolServices{runtimeFields: valid.runtimeFields, contextFactory: valid.contextFactory}},
		{name: "runtime fields", services: &protocolServices{credentials: valid.credentials, contextFactory: valid.contextFactory}},
		{name: "context factory", services: &protocolServices{credentials: valid.credentials, runtimeFields: valid.runtimeFields}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newAuthManager(tt.services, t.TempDir(), "", "", "", nil); err == nil {
				t.Fatal("newAuthManager() error = nil, want safe validation error")
			}
		})
	}
}

func TestAuthManagerLoggedInSynchronizesWithCredentialUpdates(t *testing.T) {
	a := syntheticAuthManager(t, &authManager{ui: &userInfo{SecurityOAuthToken: "synthetic-token"}})
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			a.mu.Lock()
			if i%2 == 0 {
				a.ui.SecurityOAuthToken = "synthetic-token"
			} else {
				a.ui.SecurityOAuthToken = ""
			}
			a.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			_ = a.loggedIn()
		}
	}()
	close(start)
	wg.Wait()
}

func TestAuthManagerRefreshReplacesContext(t *testing.T) {
	newRefreshServer := func(t *testing.T) *httptest.Server {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/deviceToken/refresh" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_token":"synthetic-new-token","refresh_token":"synthetic-new-refresh","expires_in":7200}`))
		}))
		t.Cleanup(server.Close)
		return server
	}

	t.Run("generated fields replace active context and save new token", func(t *testing.T) {
		server := newRefreshServer(t)
		old := &fakeProtocolContext{}
		newCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://refreshed.example.test"}}
		generator := &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "new-encrypted-user", Key: "new-key"}}
		factory := &fakeProtocolContextFactory{contexts: []protocolContext{newCtx}}
		codec := &fakeCredentialCodec{encrypted: "synthetic-saved-credential"}
		authFile := filepath.Join(t.TempDir(), "user")
		a := syntheticAuthManager(t, &authManager{
			protocol: &protocolServices{credentials: codec, runtimeFields: generator, contextFactory: factory},
			authFile: authFile, machineID: "0123456789abcdef-extra", openapiBase: server.URL,
			httpc: server.Client(), protoCtx: old, logf: func(string, ...any) {},
			ui: &userInfo{
				UID: "synthetic-user", RefreshToken: "synthetic-old-refresh",
				SecurityOAuthToken: "synthetic-old-token", AccessToken: "synthetic-old-token",
				EncryptUserInfo: "old-encrypted-user", Key: "old-key",
			},
		})

		if err := a.forceRefresh(context.Background()); err != nil {
			t.Fatalf("forceRefresh() error = %v", err)
		}
		a.mu.Lock()
		gotToken := a.ui.SecurityOAuthToken
		gotRefresh := a.ui.RefreshToken
		gotFields := runtimeFieldOutput{EncryptUserInfo: a.ui.EncryptUserInfo, Key: a.ui.Key}
		a.mu.Unlock()
		if gotToken != "synthetic-new-token" || gotRefresh != "synthetic-new-refresh" {
			t.Fatalf("refreshed tokens = (%q, %q), want synthetic replacements", gotToken, gotRefresh)
		}
		if gotFields != (runtimeFieldOutput{EncryptUserInfo: "new-encrypted-user", Key: "new-key"}) {
			t.Fatalf("runtime fields = %#v, want regenerated fields", gotFields)
		}
		if closes, _ := old.state(); closes != 1 {
			t.Fatalf("old context Close() count = %d, want 1", closes)
		}
		prepared, err := a.prepareWithCurrentContext(context.Background(), inferRequestInput{})
		if err != nil {
			t.Fatalf("prepare with refreshed context error = %v", err)
		}
		if prepared.URL != "https://refreshed.example.test" {
			t.Fatalf("prepared URL = %q, want refreshed context URL", prepared.URL)
		}
		if len(factory.configs) != 1 || factory.configs[0].User.EncryptUserInfo != "new-encrypted-user" || factory.configs[0].User.Key != "new-key" {
			t.Fatalf("refreshed context configs = %#v", factory.configs)
		}
		if generator.calls != 1 {
			t.Fatalf("runtime Generate() call count = %d, want 1", generator.calls)
		}
		if codec.encryptCalls != 1 {
			t.Fatalf("credential Encrypt() call count = %d, want 1", codec.encryptCalls)
		}
		var savedUI userInfo
		if len(codec.encryptPlains) != 1 || json.Unmarshal([]byte(codec.encryptPlains[0]), &savedUI) != nil {
			t.Fatalf("encrypted plaintexts = %#v, want one credential JSON", codec.encryptPlains)
		}
		if savedUI.SecurityOAuthToken != "synthetic-new-token" || savedUI.RefreshToken != "synthetic-new-refresh" {
			t.Fatalf("saved tokens = (%q, %q), want refreshed tokens", savedUI.SecurityOAuthToken, savedUI.RefreshToken)
		}
		if saved, err := os.ReadFile(authFile); err != nil || string(saved) != "synthetic-saved-credential" {
			t.Fatalf("saved credential = %q, %v; want refreshed credential", saved, err)
		}
	})

	t.Run("generator failure preserves active token-bound fields and refresh rotation", func(t *testing.T) {
		server := newRefreshServer(t)
		old := &fakeProtocolContext{}
		newCtx := &fakeProtocolContext{}
		generator := &fakeRuntimeFieldGenerator{err: errors.New("synthetic generator failure")}
		factory := &fakeProtocolContextFactory{contexts: []protocolContext{newCtx}}
		codec := &fakeCredentialCodec{encrypted: "synthetic-saved-credential"}
		a := syntheticAuthManager(t, &authManager{
			protocol: &protocolServices{credentials: codec, runtimeFields: generator, contextFactory: factory},
			authFile: filepath.Join(t.TempDir(), "user"), machineID: "synthetic-machine", openapiBase: server.URL,
			httpc: server.Client(), protoCtx: old, logf: func(string, ...any) {},
			ui: &userInfo{
				UID: "synthetic-user", RefreshToken: "synthetic-old-refresh",
				SecurityOAuthToken: "synthetic-old-token", AccessToken: "synthetic-old-token",
				EncryptUserInfo: "old-encrypted-user", Key: "old-key",
			},
		})

		if err := a.forceRefresh(context.Background()); err == nil {
			t.Fatal("forceRefresh() accepted new token with old token-bound fields")
		}
		a.mu.Lock()
		gotToken := a.ui.SecurityOAuthToken
		gotFields := runtimeFieldOutput{EncryptUserInfo: a.ui.EncryptUserInfo, Key: a.ui.Key}
		a.mu.Unlock()
		if gotToken != "synthetic-old-token" || a.ui.RefreshToken != "synthetic-new-refresh" {
			t.Fatal("active token or preserved refresh rotation is incorrect")
		}
		if gotFields != (runtimeFieldOutput{EncryptUserInfo: "old-encrypted-user", Key: "old-key"}) {
			t.Fatalf("runtime fields = %#v, want preserved old fields", gotFields)
		}
		if len(factory.configs) != 0 {
			t.Fatal("failed runtime generation built a candidate context")
		}
		if closes, _ := old.state(); closes != 0 {
			t.Fatalf("old context Close() count = %d, want 0", closes)
		}
	})

	t.Run("generator failure with no old fields blocks invalid context", func(t *testing.T) {
		server := newRefreshServer(t)
		old := &fakeProtocolContext{}
		generator := &fakeRuntimeFieldGenerator{err: errors.New("synthetic generator failure")}
		factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
		codec := &fakeCredentialCodec{}
		authFile := filepath.Join(t.TempDir(), "user")
		a := syntheticAuthManager(t, &authManager{
			protocol: &protocolServices{credentials: codec, runtimeFields: generator, contextFactory: factory},
			authFile: authFile, machineID: "synthetic-machine", openapiBase: server.URL,
			httpc: server.Client(), protoCtx: old, logf: func(string, ...any) {},
			ui: &userInfo{
				UID: "synthetic-user", RefreshToken: "synthetic-old-refresh",
				SecurityOAuthToken: "synthetic-old-token", AccessToken: "synthetic-old-token",
			},
		})

		if err := a.forceRefresh(context.Background()); err == nil {
			t.Fatal("forceRefresh() error = nil, want final runtime field generation failure")
		}
		if generator.calls != 1 {
			t.Fatalf("runtime Generate() call count = %d, want one authoritative generation", generator.calls)
		}
		if len(factory.configs) != 0 {
			t.Fatalf("context factory call count = %d, want 0 for incomplete fields", len(factory.configs))
		}
		if closes, _ := old.state(); closes != 0 {
			t.Fatalf("old context Close() count = %d, want 0", closes)
		}
		if codec.encryptCalls != 1 {
			t.Fatalf("credential Encrypt() call count = %d, want 1 for refresh rotation persistence", codec.encryptCalls)
		}
		persistedBytes, err := os.ReadFile(authFile)
		if err != nil {
			t.Fatalf("ReadFile(persisted rotation) error = %v", err)
		}
		var persisted userInfo
		if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
			t.Fatalf("Unmarshal(persisted rotation) error = %v", err)
		}
		if persisted.RefreshToken != "synthetic-new-refresh" || persisted.SecurityOAuthToken != "synthetic-old-token" {
			t.Fatalf("persisted failed rebuild state = refresh %q access %q, want rotated refresh with old access", persisted.RefreshToken, persisted.SecurityOAuthToken)
		}
	})
}

func TestAuthManagerRefreshCandidateRetriesAfterContextBuildFailure(t *testing.T) {
	var serverMu sync.Mutex
	var requestedRefreshTokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid synthetic request", http.StatusBadRequest)
			return
		}
		serverMu.Lock()
		requestedRefreshTokens = append(requestedRefreshTokens, request.RefreshToken)
		call := len(requestedRefreshTokens)
		serverMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			_, _ = w.Write([]byte(`{"device_token":"candidate-token-1","refresh_token":"rotated-refresh-1","expires_in":7200,"refresh_token_expires_in":14400}`))
			return
		}
		_, _ = w.Write([]byte(`{"device_token":"candidate-token-2","refresh_token":"rotated-refresh-2","expires_in":7200,"refresh_token_expires_in":14400}`))
	}))
	defer server.Close()

	factoryErr := errors.New("synthetic first context build failure")
	old := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://old.example.test"}}
	newCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://new.example.test"}}
	factory := &fakeProtocolContextFactory{
		errs:     []error{factoryErr, nil},
		contexts: []protocolContext{newCtx},
	}
	expiredAt := time.Now().Add(-2 * time.Hour).Unix()
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    &fakeCredentialCodec{encrypted: "synthetic-saved-credential"},
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "candidate-fields", Key: "candidate-key"}},
			contextFactory: factory,
		},
		authFile:    filepath.Join(t.TempDir(), "user"),
		machineID:   "synthetic-machine",
		openapiBase: server.URL,
		httpc:       server.Client(),
		ui: &userInfo{
			UID:                    "synthetic-user",
			SecurityOAuthToken:     "synthetic-old-token",
			AccessToken:            "synthetic-old-token",
			RefreshToken:           "synthetic-old-refresh",
			ExpireTime:             expiredAt,
			RefreshTokenExpireTime: time.Now().Add(time.Hour).Unix(),
			EncryptUserInfo:        "synthetic-old-fields",
			Key:                    "synthetic-old-key",
			OrgTags:                []string{"old-tag"},
		},
		protoCtx: old,
		logf:     func(string, ...any) {},
	})

	if prepared, err := a.PrepareInferRequest(context.Background(), inferRequestInput{}); prepared != nil || protocolErrorKindOf(err) != protocolAuthUnavailable {
		t.Fatalf("first PrepareInferRequest() = (%#v, %v), want context build failure wrapped as auth-unavailable", prepared, err)
	}
	a.mu.Lock()
	firstToken := a.ui.SecurityOAuthToken
	firstExpiry := a.ui.ExpireTime
	firstRefresh := a.ui.RefreshToken
	firstRefreshExpiry := a.ui.RefreshTokenExpireTime
	firstFields := runtimeFieldOutput{EncryptUserInfo: a.ui.EncryptUserInfo, Key: a.ui.Key}
	firstTags := append([]string(nil), a.ui.OrgTags...)
	a.mu.Unlock()
	if firstToken != "synthetic-old-token" || firstExpiry != expiredAt {
		t.Fatalf("active access state after failed build = token %q expiry %d, want old token and expiry %d", firstToken, firstExpiry, expiredAt)
	}
	if firstFields != (runtimeFieldOutput{EncryptUserInfo: "synthetic-old-fields", Key: "synthetic-old-key"}) {
		t.Fatalf("active runtime fields after failed build = %#v, want old fields", firstFields)
	}
	if !reflect.DeepEqual(firstTags, []string{"old-tag"}) {
		t.Fatalf("active tags after failed build = %#v, want old tags", firstTags)
	}
	if firstRefresh != "rotated-refresh-1" || firstRefreshExpiry <= time.Now().Unix() {
		t.Fatalf("preserved refresh rotation = token %q expiry %d, want rotated retry credentials", firstRefresh, firstRefreshExpiry)
	}
	if closes, _ := old.state(); closes != 0 {
		t.Fatalf("old context Close() count after failed build = %d, want 0", closes)
	}

	prepared, err := a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("second PrepareInferRequest() error = %v", err)
	}
	if prepared.URL != "https://new.example.test" {
		t.Fatalf("second prepared URL = %q, want new context", prepared.URL)
	}
	serverMu.Lock()
	gotRefreshTokens := append([]string(nil), requestedRefreshTokens...)
	serverMu.Unlock()
	if !reflect.DeepEqual(gotRefreshTokens, []string{"synthetic-old-refresh", "rotated-refresh-1"}) {
		t.Fatalf("refresh request tokens = %#v, want original then rotated token", gotRefreshTokens)
	}
	a.mu.Lock()
	finalToken := a.ui.SecurityOAuthToken
	finalRefresh := a.ui.RefreshToken
	finalExpiry := a.ui.ExpireTime
	a.mu.Unlock()
	if finalToken != "candidate-token-2" || finalRefresh != "rotated-refresh-2" || finalExpiry <= time.Now().Unix() {
		t.Fatalf("final active state = token %q refresh %q expiry %d, want second candidate", finalToken, finalRefresh, finalExpiry)
	}
	if closes, _ := old.state(); closes != 1 {
		t.Fatalf("old context Close() count after retry = %d, want 1", closes)
	}
	if len(factory.configs) != 2 {
		t.Fatalf("context factory calls = %d, want 2", len(factory.configs))
	}
}

func TestAuthManagerRefreshRotationPersistsAcrossRestartAfterContextBuildFailure(t *testing.T) {
	var serverMu sync.Mutex
	var requestedRefreshTokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid synthetic request", http.StatusBadRequest)
			return
		}
		serverMu.Lock()
		requestedRefreshTokens = append(requestedRefreshTokens, request.RefreshToken)
		call := len(requestedRefreshTokens)
		serverMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			_, _ = w.Write([]byte(`{"device_token":"candidate-token-1","refresh_token":"rotated-refresh-1","expires_in":7200,"refresh_token_expires_in":14400}`))
			return
		}
		_, _ = w.Write([]byte(`{"device_token":"candidate-token-2","refresh_token":"rotated-refresh-2","expires_in":7200,"refresh_token_expires_in":14400}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	expiredAt := time.Now().Add(-2 * time.Hour).Unix()
	oldCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://old.example.test"}}
	firstFactoryErr := errors.New("synthetic first context build failure")
	firstCodec := &fakeCredentialCodec{}
	first := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    firstCodec,
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "candidate-fields-1", Key: "candidate-key-1"}},
			contextFactory: &fakeProtocolContextFactory{err: firstFactoryErr},
		},
		authFile:    authFile,
		machineID:   "synthetic-machine",
		openapiBase: server.URL,
		httpc:       server.Client(),
		ui: &userInfo{
			UID:                    "synthetic-user",
			SecurityOAuthToken:     "synthetic-old-token",
			AccessToken:            "synthetic-old-token",
			RefreshToken:           "synthetic-old-refresh",
			ExpireTime:             expiredAt,
			RefreshTokenExpireTime: time.Now().Add(time.Hour).Unix(),
			EncryptUserInfo:        "synthetic-old-fields",
			Key:                    "synthetic-old-key",
			OrgTags:                []string{"old-tag"},
		},
		protoCtx: oldCtx,
		logf:     func(string, ...any) {},
	})
	if prepared, err := first.PrepareInferRequest(context.Background(), inferRequestInput{}); prepared != nil || protocolErrorKindOf(err) != protocolAuthUnavailable {
		t.Fatalf("first PrepareInferRequest() = (%#v, %v), want context build failure", prepared, err)
	}
	persistedBytes, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("ReadFile(persisted credential) error = %v", err)
	}
	var persisted userInfo
	if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
		t.Fatalf("Unmarshal(persisted credential) error = %v", err)
	}
	if persisted.RefreshToken != "rotated-refresh-1" || persisted.RefreshTokenExpireTime <= time.Now().Unix() {
		t.Fatalf("persisted refresh state = token %q expiry %d, want rotated retry credentials", persisted.RefreshToken, persisted.RefreshTokenExpireTime)
	}
	if persisted.SecurityOAuthToken != "synthetic-old-token" || persisted.AccessToken != "synthetic-old-token" || persisted.ExpireTime != expiredAt {
		t.Fatalf("persisted access state = security %q access %q expiry %d, want old active state", persisted.SecurityOAuthToken, persisted.AccessToken, persisted.ExpireTime)
	}
	if persisted.EncryptUserInfo != "synthetic-old-fields" || persisted.Key != "synthetic-old-key" || !reflect.DeepEqual(persisted.OrgTags, []string{"old-tag"}) {
		t.Fatalf("persisted runtime state = fields %q key %q tags %#v, want old active state", persisted.EncryptUserInfo, persisted.Key, persisted.OrgTags)
	}
	if firstCodec.encryptCalls != 1 {
		t.Fatalf("first credential Encrypt() call count = %d, want 1", firstCodec.encryptCalls)
	}
	if closes, _ := oldCtx.state(); closes != 0 {
		t.Fatalf("old context Close() count after failed build = %d, want 0", closes)
	}

	loadedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://loaded.example.test"}}
	refreshedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://restarted.example.test"}}
	secondFactory := &fakeProtocolContextFactory{contexts: []protocolContext{loadedCtx, refreshedCtx}}
	second, err := newAuthManager(&protocolServices{
		credentials:    &fakeCredentialCodec{},
		runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "candidate-fields-2", Key: "candidate-key-2"}},
		contextFactory: secondFactory,
	}, dir, server.URL, "", "", nil)
	if err != nil {
		t.Fatalf("newAuthManager(second) error = %v", err)
	}
	second.httpc = server.Client()
	t.Cleanup(func() { _ = second.Close() })
	if err := second.load(context.Background()); err != nil {
		t.Fatalf("second load() error = %v", err)
	}
	prepared, err := second.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("second PrepareInferRequest() error = %v", err)
	}
	if prepared.URL != "https://restarted.example.test" {
		t.Fatalf("second prepared URL = %q, want refreshed restart context", prepared.URL)
	}
	serverMu.Lock()
	gotRefreshTokens := append([]string(nil), requestedRefreshTokens...)
	serverMu.Unlock()
	if !reflect.DeepEqual(gotRefreshTokens, []string{"synthetic-old-refresh", "rotated-refresh-1"}) {
		t.Fatalf("refresh request tokens = %#v, want original then persisted rotated token", gotRefreshTokens)
	}
	second.mu.Lock()
	finalToken := second.ui.SecurityOAuthToken
	finalRefresh := second.ui.RefreshToken
	second.mu.Unlock()
	if finalToken != "candidate-token-2" || finalRefresh != "rotated-refresh-2" {
		t.Fatalf("restarted active state = token %q refresh %q, want second candidate", finalToken, finalRefresh)
	}
	if len(secondFactory.configs) != 2 {
		t.Fatalf("second context factory calls = %d, want load and refresh", len(secondFactory.configs))
	}
}

func TestAuthManagerRefreshRotationSaveFailurePreservesBothErrors(t *testing.T) {
	const rotatedSecret = "synthetic-rotated-secret-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_token":"candidate-token","refresh_token":"` + rotatedSecret + `","expires_in":7200,"refresh_token_expires_in":14400}`))
	}))
	defer server.Close()

	contextErr := errors.New("synthetic context build failure")
	saveErr := errors.New("synthetic credential persistence failure")
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    &fakeCredentialCodec{encryptErr: saveErr},
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "candidate-fields", Key: "candidate-key"}},
			contextFactory: &fakeProtocolContextFactory{err: contextErr},
		},
		authFile:    filepath.Join(t.TempDir(), "user"),
		machineID:   "synthetic-machine",
		openapiBase: server.URL,
		httpc:       server.Client(),
		ui: &userInfo{
			UID:                "synthetic-user",
			SecurityOAuthToken: "synthetic-old-token",
			AccessToken:        "synthetic-old-token",
			RefreshToken:       "synthetic-old-refresh",
			ExpireTime:         time.Now().Add(-time.Hour).Unix(),
			EncryptUserInfo:    "synthetic-old-fields",
			Key:                "synthetic-old-key",
		},
		protoCtx: &fakeProtocolContext{},
		logf:     func(string, ...any) {},
	})

	_, err := a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err == nil {
		t.Fatal("PrepareInferRequest() error = nil, want context and persistence failures")
	}
	internal := protocolInternalError(err)
	if !errors.Is(internal, contextErr) {
		t.Fatalf("internal error = %v, want context failure", internal)
	}
	if !errors.Is(internal, saveErr) {
		t.Fatalf("internal error = %v, want persistence failure", internal)
	}
	if strings.Contains(err.Error(), rotatedSecret) || strings.Contains(fmt.Sprint(internal), rotatedSecret) {
		t.Fatalf("error leaked rotated refresh token: public=%q internal=%q", err, internal)
	}
	a.mu.Lock()
	gotRefresh := a.ui.RefreshToken
	gotAccess := a.ui.SecurityOAuthToken
	a.mu.Unlock()
	if gotRefresh != rotatedSecret || gotAccess != "synthetic-old-token" {
		t.Fatalf("memory state after save failure = refresh %q access %q, want rotated refresh and old access", gotRefresh, gotAccess)
	}
}

func TestAuthManagerRefreshCommitUsesBoundedDetachedContext(t *testing.T) {
	newCancelingClient := func(cancel context.CancelFunc, responseJSON string) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if err := request.Context().Err(); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &cancelAfterReadCloser{payload: []byte(responseJSON), cancel: cancel},
				Request:    request,
			}, nil
		})}
	}

	t.Run("successful candidate commits after caller cancellation", func(t *testing.T) {
		callerCtx, cancel := context.WithCancel(context.Background())
		generator := &fakeRuntimeFieldGenerator{
			output:         runtimeFieldOutput{EncryptUserInfo: "detached-fields", Key: "detached-key"},
			respectContext: true,
		}
		newCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://detached.example.test"}}
		factory := &fakeProtocolContextFactory{contexts: []protocolContext{newCtx}, respectContext: true}
		codec := &fakeCredentialCodec{respectContext: true}
		authFile := filepath.Join(t.TempDir(), "user")
		a := syntheticAuthManager(t, &authManager{
			protocol: &protocolServices{credentials: codec, runtimeFields: generator, contextFactory: factory},
			authFile: authFile, machineID: "synthetic-machine", openapiBase: "https://refresh.example.test",
			httpc: newCancelingClient(cancel, `{"device_token":"detached-token","refresh_token":"detached-refresh","expires_in":7200,"refresh_token_expires_in":14400}`),
			ui: &userInfo{
				UID:                "synthetic-user",
				SecurityOAuthToken: "synthetic-old-token",
				AccessToken:        "synthetic-old-token",
				RefreshToken:       "synthetic-old-refresh",
				ExpireTime:         time.Now().Add(-time.Hour).Unix(),
				EncryptUserInfo:    "synthetic-old-fields",
				Key:                "synthetic-old-key",
			},
			protoCtx: &fakeProtocolContext{},
			logf:     func(string, ...any) {},
		})

		prepared, err := a.PrepareInferRequest(callerCtx, inferRequestInput{})
		if err != nil {
			t.Fatalf("PrepareInferRequest() error = %v (internal: %v)", err, protocolInternalError(err))
		}
		if prepared.URL != "https://detached.example.test" {
			t.Fatalf("prepared URL = %q, want detached candidate context", prepared.URL)
		}
		if !errors.Is(callerCtx.Err(), context.Canceled) {
			t.Fatalf("caller context error = %v, want canceled", callerCtx.Err())
		}
		if generator.calls != 1 {
			t.Fatalf("runtime Generate() calls = %d, want 1", generator.calls)
		}
		if len(factory.configs) != 1 || factory.configs[0].User.EncryptUserInfo != "detached-fields" || factory.configs[0].User.Key != "detached-key" {
			t.Fatalf("candidate context configs = %#v, want detached runtime fields", factory.configs)
		}
		persistedBytes, err := os.ReadFile(authFile)
		if err != nil {
			t.Fatalf("ReadFile(persisted credential) error = %v", err)
		}
		var persisted userInfo
		if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
			t.Fatalf("Unmarshal(persisted credential) error = %v", err)
		}
		if persisted.SecurityOAuthToken != "detached-token" || persisted.RefreshToken != "detached-refresh" {
			t.Fatalf("persisted detached state = access %q refresh %q, want committed candidate", persisted.SecurityOAuthToken, persisted.RefreshToken)
		}
	})

	t.Run("failed candidate persists rotation after caller cancellation", func(t *testing.T) {
		callerCtx, cancel := context.WithCancel(context.Background())
		contextErr := errors.New("synthetic detached context build failure")
		codec := &fakeCredentialCodec{respectContext: true}
		authFile := filepath.Join(t.TempDir(), "user")
		expiredAt := time.Now().Add(-time.Hour).Unix()
		a := syntheticAuthManager(t, &authManager{
			protocol: &protocolServices{
				credentials:    codec,
				runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "candidate-fields", Key: "candidate-key"}, respectContext: true},
				contextFactory: &fakeProtocolContextFactory{err: contextErr, respectContext: true},
			},
			authFile: authFile, machineID: "synthetic-machine", openapiBase: "https://refresh.example.test",
			httpc: newCancelingClient(cancel, `{"device_token":"candidate-token","refresh_token":"detached-rotated-refresh","expires_in":7200,"refresh_token_expires_in":14400}`),
			ui: &userInfo{
				UID:                "synthetic-user",
				SecurityOAuthToken: "synthetic-old-token",
				AccessToken:        "synthetic-old-token",
				RefreshToken:       "synthetic-old-refresh",
				ExpireTime:         expiredAt,
				EncryptUserInfo:    "synthetic-old-fields",
				Key:                "synthetic-old-key",
			},
			protoCtx: &fakeProtocolContext{},
			logf:     func(string, ...any) {},
		})

		_, err := a.PrepareInferRequest(callerCtx, inferRequestInput{})
		if err == nil {
			t.Fatal("PrepareInferRequest() error = nil, want candidate build failure")
		}
		if !errors.Is(protocolInternalError(err), contextErr) {
			t.Fatalf("internal error = %v, want context build failure", protocolInternalError(err))
		}
		if !errors.Is(callerCtx.Err(), context.Canceled) {
			t.Fatalf("caller context error = %v, want canceled", callerCtx.Err())
		}
		persistedBytes, readErr := os.ReadFile(authFile)
		if readErr != nil {
			t.Fatalf("ReadFile(persisted rotation) error = %v", readErr)
		}
		var persisted userInfo
		if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
			t.Fatalf("Unmarshal(persisted rotation) error = %v", err)
		}
		if persisted.RefreshToken != "detached-rotated-refresh" || persisted.SecurityOAuthToken != "synthetic-old-token" || persisted.ExpireTime != expiredAt {
			t.Fatalf("persisted failed candidate state = refresh %q access %q expiry %d, want rotated refresh with old active state", persisted.RefreshToken, persisted.SecurityOAuthToken, persisted.ExpireTime)
		}
	})
}

func TestAuthManagerRefreshPersistenceGetsFreshBudgetAfterBuildDeadline(t *testing.T) {
	const testCommitTimeout = 50 * time.Millisecond

	t.Run("failed build persists rotation before returning", func(t *testing.T) {
		const rotatedSecret = "synthetic-deadline-rotated-refresh"
		var serverMu sync.Mutex
		var requestedRefreshTokens []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "invalid synthetic request", http.StatusBadRequest)
				return
			}
			serverMu.Lock()
			requestedRefreshTokens = append(requestedRefreshTokens, request.RefreshToken)
			call := len(requestedRefreshTokens)
			serverMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if call == 1 {
				_, _ = w.Write([]byte(`{"device_token":"deadline-candidate-1","refresh_token":"` + rotatedSecret + `","expires_in":7200,"refresh_token_expires_in":14400}`))
				return
			}
			_, _ = w.Write([]byte(`{"device_token":"deadline-candidate-2","refresh_token":"deadline-rotated-2","expires_in":7200,"refresh_token_expires_in":14400}`))
		}))
		defer server.Close()

		dir := t.TempDir()
		codec := &fakeCredentialCodec{respectContext: true}
		deadlineFactory := &deadlineConsumingContextFactory{}
		a, err := newAuthManager(&protocolServices{
			credentials:    codec,
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "deadline-fields-1", Key: "deadline-key-1"}},
			contextFactory: deadlineFactory,
		}, dir, server.URL, "", "", nil)
		if err != nil {
			t.Fatalf("newAuthManager() error = %v", err)
		}
		a.commitTimeout = testCommitTimeout
		a.httpc = server.Client()
		oldCtx := &fakeProtocolContext{}
		expiredAt := time.Now().Add(-time.Hour).Unix()
		a.ui = &userInfo{
			UID:                "synthetic-user",
			SecurityOAuthToken: "synthetic-old-token",
			AccessToken:        "synthetic-old-token",
			RefreshToken:       "synthetic-old-refresh",
			ExpireTime:         expiredAt,
			EncryptUserInfo:    "synthetic-old-fields",
			Key:                "synthetic-old-key",
		}
		a.protoCtx = oldCtx

		prepared, refreshErr := a.PrepareInferRequest(context.Background(), inferRequestInput{})
		if prepared != nil || protocolErrorKindOf(refreshErr) != protocolAuthUnavailable || !errors.Is(protocolInternalError(refreshErr), context.DeadlineExceeded) {
			t.Fatalf("PrepareInferRequest() = (%#v, %v), want deadline build failure", prepared, refreshErr)
		}
		if strings.Contains(refreshErr.Error(), rotatedSecret) || strings.Contains(fmt.Sprint(protocolInternalError(refreshErr)), rotatedSecret) {
			t.Fatalf("deadline refresh error leaked rotated token: public=%q internal=%q", refreshErr, protocolInternalError(refreshErr))
		}
		persistedBytes, err := os.ReadFile(a.authFile)
		if err != nil {
			t.Fatalf("ReadFile(rotation persisted after deadline) error = %v", err)
		}
		var persisted userInfo
		if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
			t.Fatalf("Unmarshal(rotation persisted after deadline) error = %v", err)
		}
		if persisted.RefreshToken != rotatedSecret || persisted.SecurityOAuthToken != "synthetic-old-token" || persisted.ExpireTime != expiredAt {
			t.Fatalf("persisted deadline state = refresh %q access %q expiry %d, want rotated refresh with old active state", persisted.RefreshToken, persisted.SecurityOAuthToken, persisted.ExpireTime)
		}
		a.mu.Lock()
		dirty := a.credentialDirty
		a.mu.Unlock()
		if dirty {
			t.Fatal("credentialDirty = true after fresh-budget rotation save, want false")
		}
		if err := a.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if closes, _ := oldCtx.state(); closes != 1 {
			t.Fatalf("old context Close() count = %d, want 1", closes)
		}

		loadedCtx := &fakeProtocolContext{}
		refreshedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://deadline-restart.example.test"}}
		restartedFactory := &fakeProtocolContextFactory{contexts: []protocolContext{loadedCtx, refreshedCtx}}
		restarted, err := newAuthManager(&protocolServices{
			credentials:    &fakeCredentialCodec{},
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "deadline-fields-2", Key: "deadline-key-2"}},
			contextFactory: restartedFactory,
		}, dir, server.URL, "", "", nil)
		if err != nil {
			t.Fatalf("newAuthManager(restart) error = %v", err)
		}
		restarted.httpc = server.Client()
		t.Cleanup(func() { _ = restarted.Close() })
		if err := restarted.load(context.Background()); err != nil {
			t.Fatalf("restart load() error = %v", err)
		}
		prepared, err = restarted.PrepareInferRequest(context.Background(), inferRequestInput{})
		if err != nil {
			t.Fatalf("restart PrepareInferRequest() error = %v", err)
		}
		if prepared.URL != "https://deadline-restart.example.test" {
			t.Fatalf("restart prepared URL = %q, want refreshed context", prepared.URL)
		}
		serverMu.Lock()
		gotTokens := append([]string(nil), requestedRefreshTokens...)
		serverMu.Unlock()
		if !reflect.DeepEqual(gotTokens, []string{"synthetic-old-refresh", rotatedSecret}) {
			t.Fatalf("refresh request tokens = %#v, want original then deadline-persisted rotation", gotTokens)
		}
	})

	t.Run("accepted context persists candidate with a fresh budget", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_token":"deadline-success-token","refresh_token":"deadline-success-refresh","expires_in":7200,"refresh_token_expires_in":14400}`))
		}))
		defer server.Close()

		acceptedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://deadline-success.example.test"}}
		deadlineFactory := &deadlineConsumingContextFactory{next: acceptedCtx}
		codec := &fakeCredentialCodec{respectContext: true}
		a := syntheticAuthManager(t, &authManager{
			protocol: &protocolServices{
				credentials:    codec,
				runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "deadline-success-fields", Key: "deadline-success-key"}},
				contextFactory: deadlineFactory,
			},
			authFile: filepath.Join(t.TempDir(), "user"), machineID: "synthetic-machine", openapiBase: server.URL,
			httpc: server.Client(), protoCtx: &fakeProtocolContext{}, commitTimeout: testCommitTimeout, logf: func(string, ...any) {},
			ui: &userInfo{
				UID:                "synthetic-user",
				SecurityOAuthToken: "synthetic-old-token",
				AccessToken:        "synthetic-old-token",
				RefreshToken:       "synthetic-old-refresh",
				ExpireTime:         time.Now().Add(-time.Hour).Unix(),
				EncryptUserInfo:    "synthetic-old-fields",
				Key:                "synthetic-old-key",
			},
		})

		if err := a.forceRefresh(context.Background()); err != nil {
			t.Fatalf("forceRefresh() error = %v (internal: %v)", err, protocolInternalError(err))
		}
		persistedBytes, err := os.ReadFile(a.authFile)
		if err != nil {
			t.Fatalf("ReadFile(deadline-success credential) error = %v", err)
		}
		var persisted userInfo
		if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
			t.Fatalf("Unmarshal(deadline-success credential) error = %v", err)
		}
		if persisted.SecurityOAuthToken != "deadline-success-token" || persisted.RefreshToken != "deadline-success-refresh" {
			t.Fatalf("persisted accepted state = token %q refresh %q, want deadline-success candidate", persisted.SecurityOAuthToken, persisted.RefreshToken)
		}
		a.mu.Lock()
		dirty := a.credentialDirty
		a.mu.Unlock()
		if dirty {
			t.Fatal("credentialDirty = true after fresh-budget candidate save, want false")
		}
		prepared, err := a.prepareWithCurrentContext(context.Background(), inferRequestInput{})
		if err != nil || prepared.URL != "https://deadline-success.example.test" {
			t.Fatalf("accepted context prepare = (%#v, %v), want deadline-success context", prepared, err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
}

func TestAuthManagerDirtyCredentialPersistenceIsBestEffortAndRateLimited(t *testing.T) {
	saveErr := errors.New("synthetic credential persistence failure")
	codec := &fakeCredentialCodec{encryptErr: saveErr}
	var logs strings.Builder
	manager := syntheticAuthManager(t, &authManager{
		protocol:  &protocolServices{credentials: codec},
		authFile:  filepath.Join(t.TempDir(), "user"),
		machineID: "synthetic-machine",
		ui: &userInfo{
			UID:                "synthetic-user",
			SecurityOAuthToken: "synthetic-token",
			ExpireTime:         time.Now().Add(2 * time.Hour).Unix(),
		},
		credentialDirty: true,
		protoCtx:        &fakeProtocolContext{prepared: &preparedRequest{URL: "https://prepared.example.test"}},
		logf: func(format string, args ...any) {
			fmt.Fprintf(&logs, format+"\n", args...)
		},
	})
	t.Cleanup(func() { _ = manager.Close() })

	prepared, err := manager.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil || prepared == nil || prepared.URL != "https://prepared.example.test" {
		t.Fatalf("first PrepareInferRequest() = (%#v, %v), want admitted request", prepared, err)
	}
	manager.mu.Lock()
	firstRetryAt := manager.credentialPersistRetryAt
	firstDirty := manager.credentialDirty
	manager.mu.Unlock()
	if !firstDirty || !firstRetryAt.After(time.Now()) {
		t.Fatalf("dirty/retry state = %v/%v, want dirty with future retry", firstDirty, firstRetryAt)
	}
	if !strings.Contains(logs.String(), "persist pending credentials") || !strings.Contains(logs.String(), saveErr.Error()) {
		t.Fatalf("persistence diagnostic = %q", logs.String())
	}

	prepared, err = manager.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil || prepared == nil {
		t.Fatalf("second PrepareInferRequest() = (%#v, %v), want admitted request", prepared, err)
	}
	codec.mu.Lock()
	callsBeforeDeadline := codec.encryptCalls
	codec.encryptErr = nil
	codec.mu.Unlock()
	if callsBeforeDeadline != 1 {
		t.Fatalf("Encrypt() calls before deadline = %d, want 1", callsBeforeDeadline)
	}

	manager.mu.Lock()
	manager.credentialPersistRetryAt = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	prepared, err = manager.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil || prepared == nil {
		t.Fatalf("retry PrepareInferRequest() = (%#v, %v)", prepared, err)
	}
	manager.mu.Lock()
	finalDirty := manager.credentialDirty
	finalRetryAt := manager.credentialPersistRetryAt
	manager.mu.Unlock()
	if finalDirty || !finalRetryAt.IsZero() {
		t.Fatalf("final dirty/retry state = %v/%v, want clear", finalDirty, finalRetryAt)
	}
}

func TestAuthManagerAcceptedRefreshRetriesDirtyCredentialWithoutRefetch(t *testing.T) {
	const rotatedSecret = "synthetic-accepted-rotated-refresh"
	var refreshCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_token":"synthetic-accepted-token","refresh_token":"` + rotatedSecret + `","expires_in":7200,"refresh_token_expires_in":14400}`))
	}))
	defer server.Close()

	saveErr := errors.New("synthetic first credential save failure")
	codec := &fakeCredentialCodec{encryptErrs: []error{saveErr, nil}}
	acceptedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://accepted.example.test"}}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{acceptedCtx}}
	dir := t.TempDir()
	a, err := newAuthManager(&protocolServices{
		credentials:    codec,
		runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "accepted-fields", Key: "accepted-key"}},
		contextFactory: factory,
	}, dir, server.URL, "", "", nil)
	if err != nil {
		t.Fatalf("newAuthManager() error = %v", err)
	}
	a.httpc = server.Client()
	oldCtx := &fakeProtocolContext{}
	a.ui = &userInfo{
		UID:                "synthetic-user",
		SecurityOAuthToken: "synthetic-old-token",
		AccessToken:        "synthetic-old-token",
		RefreshToken:       "synthetic-old-refresh",
		ExpireTime:         time.Now().Add(-time.Hour).Unix(),
		EncryptUserInfo:    "synthetic-old-fields",
		Key:                "synthetic-old-key",
	}
	a.protoCtx = oldCtx

	prepared, firstErr := a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if firstErr != nil || prepared == nil || prepared.URL != "https://accepted.example.test" {
		t.Fatalf("first PrepareInferRequest() = (%#v, %v), want accepted in-memory context", prepared, firstErr)
	}
	a.mu.Lock()
	firstDirty := a.credentialDirty
	firstRetryAt := a.credentialPersistRetryAt
	firstToken := a.ui.SecurityOAuthToken
	firstRefresh := a.ui.RefreshToken
	a.mu.Unlock()
	if !firstDirty || !firstRetryAt.After(time.Now()) {
		t.Fatalf("dirty/retry state = %v/%v, want dirty with future retry", firstDirty, firstRetryAt)
	}
	if firstToken != "synthetic-accepted-token" || firstRefresh != rotatedSecret {
		t.Fatalf("accepted in-memory state = token %q refresh %q, want accepted candidate", firstToken, firstRefresh)
	}
	if closes, _ := oldCtx.state(); closes != 1 {
		t.Fatalf("old context Close() count = %d, want 1 after accepted candidate", closes)
	}
	if closes, _ := acceptedCtx.state(); closes != 0 {
		t.Fatalf("accepted context Close() count = %d, want 0", closes)
	}

	prepared, err = a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil || prepared == nil || prepared.URL != "https://accepted.example.test" {
		t.Fatalf("second PrepareInferRequest() = (%#v, %v), want accepted context", prepared, err)
	}
	if codec.encryptCalls != 1 {
		t.Fatalf("credential Encrypt() calls before retry deadline = %d, want 1", codec.encryptCalls)
	}
	a.mu.Lock()
	if !a.credentialDirty {
		a.mu.Unlock()
		t.Fatal("credentialDirty = false before retry deadline")
	}
	a.credentialPersistRetryAt = time.Now().Add(-time.Second)
	a.mu.Unlock()

	prepared, err = a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if err != nil || prepared == nil || prepared.URL != "https://accepted.example.test" {
		t.Fatalf("retry PrepareInferRequest() = (%#v, %v)", prepared, err)
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Fatalf("refresh HTTP calls = %d, want 1", got)
	}
	a.mu.Lock()
	secondDirty := a.credentialDirty
	secondRetryAt := a.credentialPersistRetryAt
	a.mu.Unlock()
	if secondDirty || !secondRetryAt.IsZero() {
		t.Fatalf("dirty/retry state after save = %v/%v, want clear", secondDirty, secondRetryAt)
	}
	if codec.encryptCalls != 2 {
		t.Fatalf("credential Encrypt() calls = %d, want failed save plus delayed retry", codec.encryptCalls)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closes, _ := acceptedCtx.state(); closes != 1 {
		t.Fatalf("accepted context Close() count after Close = %d, want 1", closes)
	}

	loadedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://restart.example.test"}}
	restarted, err := newAuthManager(&protocolServices{
		credentials:    &fakeCredentialCodec{},
		runtimeFields:  &fakeRuntimeFieldGenerator{},
		contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{loadedCtx}},
	}, dir, server.URL, "", "", nil)
	if err != nil {
		t.Fatalf("newAuthManager(restart) error = %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.load(context.Background()); err != nil {
		t.Fatalf("restart load() error = %v", err)
	}
	restarted.mu.Lock()
	restartedToken := restarted.ui.SecurityOAuthToken
	restartedRefresh := restarted.ui.RefreshToken
	restartedDirty := restarted.credentialDirty
	restarted.mu.Unlock()
	if restartedToken != "synthetic-accepted-token" || restartedRefresh != rotatedSecret || restartedDirty {
		t.Fatalf("restarted state = token %q refresh %q dirty %v, want persisted accepted candidate", restartedToken, restartedRefresh, restartedDirty)
	}
}

func TestAuthManagerPersistentDirtyCredentialFailureIsVisibleAndCloseReportsIt(t *testing.T) {
	const rotatedSecret = "synthetic-persistent-rotated-refresh"
	var refreshCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_token":"synthetic-persistent-token","refresh_token":"` + rotatedSecret + `","expires_in":7200,"refresh_token_expires_in":14400}`))
	}))
	defer server.Close()

	saveErr := errors.New("synthetic persistent credential save failure")
	codec := &fakeCredentialCodec{encryptErr: saveErr}
	oldCtx := &fakeProtocolContext{}
	acceptedCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://persistent.example.test"}}
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    codec,
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "persistent-fields", Key: "persistent-key"}},
			contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{acceptedCtx}},
		},
		authFile: filepath.Join(t.TempDir(), "user"), machineID: "synthetic-machine", openapiBase: server.URL,
		httpc: server.Client(), protoCtx: oldCtx, logf: func(string, ...any) {},
		ui: &userInfo{
			UID:                "synthetic-user",
			SecurityOAuthToken: "synthetic-old-token",
			AccessToken:        "synthetic-old-token",
			RefreshToken:       "synthetic-old-refresh",
			ExpireTime:         time.Now().Add(-time.Hour).Unix(),
			EncryptUserInfo:    "synthetic-old-fields",
			Key:                "synthetic-old-key",
		},
	})

	if err := a.forceRefresh(context.Background()); err != nil {
		t.Fatalf("forceRefresh() error = %v, want accepted in-memory state", err)
	}
	a.mu.Lock()
	dirtyAfterRefresh := a.credentialDirty
	retryAtAfterRefresh := a.credentialPersistRetryAt
	acceptedToken := a.ui.SecurityOAuthToken
	a.mu.Unlock()
	if !dirtyAfterRefresh || !retryAtAfterRefresh.After(time.Now()) || acceptedToken != "synthetic-persistent-token" {
		t.Fatalf("accepted state after save failure = dirty %v retry %v token %q", dirtyAfterRefresh, retryAtAfterRefresh, acceptedToken)
	}
	if closes, _ := oldCtx.state(); closes != 1 {
		t.Fatalf("old context Close() count = %d, want 1", closes)
	}

	prepared, retryErr := a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if retryErr != nil || prepared == nil || prepared.URL != "https://persistent.example.test" {
		t.Fatalf("dirty retry PrepareInferRequest() = (%#v, %v), want admitted request", prepared, retryErr)
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Fatalf("refresh HTTP calls after dirty retry = %d, want 1", got)
	}
	if codec.encryptCalls != 1 {
		t.Fatalf("credential Encrypt() calls before retry deadline = %d, want 1", codec.encryptCalls)
	}

	closeErr := a.Close()
	if protocolErrorKindOf(closeErr) != protocolBackendFailure || !errors.Is(protocolInternalError(closeErr), saveErr) {
		t.Fatalf("Close() error = %v (internal: %v), want dirty persistence failure", closeErr, protocolInternalError(closeErr))
	}
	if strings.Contains(closeErr.Error(), rotatedSecret) || strings.Contains(fmt.Sprint(protocolInternalError(closeErr)), rotatedSecret) {
		t.Fatalf("Close error leaked rotated token: public=%q internal=%q", closeErr, protocolInternalError(closeErr))
	}
	if closes, _ := acceptedCtx.state(); closes != 1 {
		t.Fatalf("accepted context Close() count = %d, want 1", closes)
	}
	if codec.encryptCalls != 2 {
		t.Fatalf("credential Encrypt() calls = %d, want refresh and forced Close attempts", codec.encryptCalls)
	}
}

func TestAuthManagerSaveWritesCredentialOnceAtomically(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dir := t.TempDir()
		authFile := filepath.Join(dir, "nested", "user")
		codec := &fakeCredentialCodec{encrypted: "synthetic-ciphertext"}
		a := syntheticAuthManager(t, &authManager{
			protocol:  &protocolServices{credentials: codec},
			authFile:  authFile,
			machineID: "0123456789abcdef-extra",
			ui:        &userInfo{UID: "synthetic-user", SecurityOAuthToken: "synthetic-token"},
		})

		if err := a.save(context.Background()); err != nil {
			t.Fatalf("save() error = %v", err)
		}
		got, err := os.ReadFile(authFile)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(got) != "synthetic-ciphertext" {
			t.Fatalf("saved credential = %q, want encrypted payload", got)
		}
		assertCredentialFileMode(t, authFile)
		if _, err := os.Stat(authFile + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temporary credential still exists after rename: %v", err)
		}
		if codec.encryptCalls != 1 {
			t.Fatalf("Encrypt() call count = %d, want 1", codec.encryptCalls)
		}
		if gotKeys := codec.encryptKeys; !reflect.DeepEqual(gotKeys, []string{"0123456789abcdef"}) {
			t.Fatalf("Encrypt() keys = %#v, want first 16 machine ID characters", gotKeys)
		}
	})

	t.Run("ignores fixed temp symlink and cleans unique temp", func(t *testing.T) {
		dir := t.TempDir()
		authFile := filepath.Join(dir, "user")
		victimPath := filepath.Join(dir, "victim")
		if err := os.WriteFile(victimPath, []byte("synthetic-victim-content"), 0o600); err != nil {
			t.Fatalf("WriteFile(victim) error = %v", err)
		}
		fixedTemp := authFile + ".tmp"
		symlinkOrSkipWindows(t, victimPath, fixedTemp)
		codec := &fakeCredentialCodec{encrypted: "synthetic-safe-ciphertext"}
		a := syntheticAuthManager(t, &authManager{
			protocol:  &protocolServices{credentials: codec},
			authFile:  authFile,
			machineID: "synthetic-machine",
			ui:        &userInfo{UID: "synthetic-user"},
		})

		if err := a.save(context.Background()); err != nil {
			t.Fatalf("save() error = %v", err)
		}
		victim, err := os.ReadFile(victimPath)
		if err != nil {
			t.Fatalf("ReadFile(victim) error = %v", err)
		}
		if string(victim) != "synthetic-victim-content" {
			t.Fatalf("victim content = %q, want unchanged", victim)
		}
		fixedInfo, err := os.Lstat(fixedTemp)
		if err != nil {
			t.Fatalf("Lstat(fixed temp symlink) error = %v", err)
		}
		if fixedInfo.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("fixed temp path mode = %v, want untouched symlink", fixedInfo.Mode())
		}
		assertCredentialFileMode(t, authFile)
		final, err := os.ReadFile(authFile)
		if err != nil || string(final) != "synthetic-safe-ciphertext" {
			t.Fatalf("final credential = %q, %v; want complete ciphertext", final, err)
		}
		if leftovers, err := filepath.Glob(filepath.Join(dir, ".user-*")); err != nil || len(leftovers) != 0 {
			t.Fatalf("unique temp leftovers = %#v, %v; want none", leftovers, err)
		}
	})

	t.Run("concurrent writers publish one complete ciphertext", func(t *testing.T) {
		dir := t.TempDir()
		authFile := filepath.Join(dir, "user")
		const writers = 8
		release := make(chan struct{})
		managers := make([]*authManager, 0, writers)
		started := make([]<-chan struct{}, 0, writers)
		ciphertexts := make([]string, 0, writers)
		for i := 0; i < writers; i++ {
			ciphertext := strings.Repeat(string(rune('A'+i)), 64*1024)
			start := make(chan struct{})
			codec := &fakeCredentialCodec{encrypted: ciphertext, encryptStarted: start, encryptRelease: release}
			managers = append(managers, syntheticAuthManager(t, &authManager{
				protocol:  &protocolServices{credentials: codec},
				authFile:  authFile,
				machineID: "synthetic-machine",
				ui:        &userInfo{UID: "synthetic-user"},
			}))
			started = append(started, start)
			ciphertexts = append(ciphertexts, ciphertext)
		}
		errs := make(chan error, writers)
		go func() { errs <- managers[0].save(context.Background()) }()
		<-started[0]
		for _, manager := range managers[1:] {
			go func(a *authManager) { errs <- a.save(context.Background()) }(manager)
		}
		close(release)
		successes, conflicts := 0, 0
		for i := 0; i < writers; i++ {
			err := <-errs
			if err == nil {
				successes++
			} else if isAuthConflict(err) {
				conflicts++
			} else {
				t.Fatalf("concurrent save error = %v", err)
			}
		}
		if successes != 1 || conflicts != writers-1 {
			t.Fatalf("serialized writes: successes=%d conflicts=%d", successes, conflicts)
		}
		for _, start := range started[1:] {
			select {
			case <-start:
				t.Fatal("stale writer reached encryption")
			default:
			}
		}
		final, err := os.ReadFile(authFile)
		if err != nil {
			t.Fatalf("ReadFile(final credential) error = %v", err)
		}
		complete := false
		for _, ciphertext := range ciphertexts {
			if string(final) == ciphertext {
				complete = true
				break
			}
		}
		if !complete {
			t.Fatalf("final concurrent credential is not one complete ciphertext (length %d)", len(final))
		}
		if leftovers, err := filepath.Glob(filepath.Join(dir, ".user-*")); err != nil || len(leftovers) != 0 {
			t.Fatalf("unique temp leftovers = %#v, %v; want none", leftovers, err)
		}
	})

	t.Run("encryption failure", func(t *testing.T) {
		dir := t.TempDir()
		authFile := filepath.Join(dir, "user")
		codec := &fakeCredentialCodec{encryptErr: errors.New("synthetic encryption failure")}
		a := syntheticAuthManager(t, &authManager{
			protocol:  &protocolServices{credentials: codec},
			authFile:  authFile,
			machineID: "synthetic-machine",
			ui:        &userInfo{UID: "synthetic-user"},
		})

		if err := a.save(context.Background()); err == nil {
			t.Fatal("save() error = nil, want encryption failure")
		}
		if codec.encryptCalls != 1 {
			t.Fatalf("Encrypt() call count = %d, want 1", codec.encryptCalls)
		}
		if _, err := os.Stat(authFile); !os.IsNotExist(err) {
			t.Fatalf("credential file exists after encryption failure: %v", err)
		}
		if _, err := os.Stat(authFile + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temporary credential exists after encryption failure: %v", err)
		}
	})

	t.Run("rename failure", func(t *testing.T) {
		dir := t.TempDir()
		authFile := filepath.Join(dir, "user")
		codec := &fakeCredentialCodec{encrypted: "synthetic-ciphertext"}
		a := syntheticAuthManager(t, &authManager{
			protocol:  &protocolServices{credentials: codec},
			authFile:  authFile,
			machineID: "synthetic-machine",
			ui:        &userInfo{UID: "synthetic-user"},
		})

		if err := os.Mkdir(authFile, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := a.save(context.Background()); !isAuthConflict(err) {
			t.Fatalf("nonregular target should fail before encryption: %v", err)
		}
		if codec.encryptCalls != 0 {
			t.Fatalf("Encrypt() call count = %d, want 0", codec.encryptCalls)
		}
		if _, err := os.Stat(authFile + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temporary credential exists after rename failure: %v", err)
		}
		if info, err := os.Stat(authFile); err != nil || !info.IsDir() {
			t.Fatalf("rename target changed after failure: info=%v err=%v", info, err)
		}
	})
}

func TestAuthManagerLoadAcceptsPlainJSONWithoutDecrypt(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	plain := ` {"uid":"plain-user","organization_id":"plain-org","organization_tags":["plain-tag"],"data_policy_agreed":true,"security_oauth_token":"synthetic-token","encrypt_user_info":"synthetic-encrypted-user","key":"synthetic-key"} `
	if err := os.WriteFile(authFile, []byte(plain), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	codec := &fakeCredentialCodec{decryptErr: errors.New("decrypt must not be called")}
	built := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://plain.example.test"}}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{built}}
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    codec,
			runtimeFields:  &fakeRuntimeFieldGenerator{},
			contextFactory: factory,
		},
		authFile: authFile, machineID: "0123456789abcdef-extra", logf: func(string, ...any) {},
	})

	if err := a.load(context.Background()); err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if codec.decryptCalls != 0 {
		t.Fatalf("Decrypt() call count = %d, want 0", codec.decryptCalls)
	}
	if len(factory.configs) != 1 {
		t.Fatalf("context factory call count = %d, want 1", len(factory.configs))
	}
	if got := factory.configs[0].User.UID; got != "plain-user" {
		t.Fatalf("context UID = %q, want plain-user", got)
	}
	prepared, err := a.prepareWithCurrentContext(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("prepareWithCurrentContext() error = %v", err)
	}
	if prepared.URL != "https://plain.example.test" {
		t.Fatalf("prepared URL = %q, want built context URL", prepared.URL)
	}
}

func TestAuthManagerLoadDecryptsEncryptedCredentialWithMachineKey(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	if err := os.WriteFile(authFile, []byte("synthetic-ciphertext\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	codec := &fakeCredentialCodec{decrypted: `{"uid":"encrypted-user","security_oauth_token":"synthetic-token","encrypt_user_info":"synthetic-encrypted-user","key":"synthetic-key"}`}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    codec,
			runtimeFields:  &fakeRuntimeFieldGenerator{},
			contextFactory: factory,
		},
		authFile: authFile, machineID: "0123456789abcdef-extra", logf: func(string, ...any) {},
	})

	if err := a.load(context.Background()); err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if codec.decryptCalls != 1 {
		t.Fatalf("Decrypt() call count = %d, want 1", codec.decryptCalls)
	}
	if got := codec.decryptKeys; !reflect.DeepEqual(got, []string{"0123456789abcdef"}) {
		t.Fatalf("Decrypt() keys = %#v, want first 16 machine ID characters", got)
	}
	if len(factory.configs) != 1 || factory.configs[0].User.UID != "encrypted-user" {
		t.Fatalf("built context configs = %#v, want decrypted user", factory.configs)
	}
}

func TestAuthManagerReplaceContextWaitsForReader(t *testing.T) {
	release := make(chan struct{})
	old := &fakeProtocolContext{prepareStarted: make(chan struct{}), prepareRelease: release}
	newCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://new.example.test"}}
	a := syntheticAuthManager(t, &authManager{protoCtx: old, logf: func(string, ...any) {}})

	prepareDone := make(chan error, 1)
	go func() {
		_, err := a.prepareWithCurrentContext(context.Background(), inferRequestInput{})
		prepareDone <- err
	}()
	<-old.prepareStarted

	replaceStarted := make(chan struct{})
	replaceDone := make(chan error, 1)
	go func() {
		close(replaceStarted)
		replaceDone <- a.replaceContext(newCtx)
	}()
	<-replaceStarted

	waitForAuthContextWriter(t, a)
	select {
	case err := <-replaceDone:
		t.Fatalf("replaceContext completed while PrepareInferRequest was active: %v", err)
	default:
	}

	close(release)
	if err := <-prepareDone; err != nil {
		t.Fatalf("prepareWithCurrentContext() error = %v", err)
	}
	if err := <-replaceDone; err != nil {
		t.Fatalf("replaceContext() error = %v", err)
	}
	if closes, _ := old.state(); closes != 1 {
		t.Fatalf("old context Close() count = %d, want 1", closes)
	}
	prepared, err := a.prepareWithCurrentContext(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("prepare with replacement context error = %v", err)
	}
	if prepared.URL != "https://new.example.test" {
		t.Fatalf("prepared URL = %q, want replacement context URL", prepared.URL)
	}
}

func TestAuthManagerCloseIsIdempotent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx := &fakeProtocolContext{}
		a := syntheticAuthManager(t, &authManager{protoCtx: ctx})
		if err := a.Close(); err != nil {
			t.Fatalf("first Close() error = %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("second Close() error = %v", err)
		}
		if closes, _ := ctx.state(); closes != 1 {
			t.Fatalf("context Close() count = %d, want 1", closes)
		}
	})

	t.Run("first close error is cached", func(t *testing.T) {
		closeErr := errors.New("synthetic first close failure")
		ctx := &fakeProtocolContext{closeErr: closeErr}
		a := syntheticAuthManager(t, &authManager{protoCtx: ctx})
		if err := a.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("first Close() error = %v, want %v", err, closeErr)
		}
		if err := a.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("second Close() error = %v, want cached %v", err, closeErr)
		}
		if closes, _ := ctx.state(); closes != 1 {
			t.Fatalf("context Close() count = %d, want 1", closes)
		}
	})
}

func TestAuthManagerClosedBlocksRefreshAndPreservesContextClosed(t *testing.T) {
	var refreshCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_token":"must-not-be-used","expires_in":7200}`))
	}))
	defer server.Close()

	factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}, &fakeProtocolContext{}}}
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    &fakeCredentialCodec{},
			runtimeFields:  &fakeRuntimeFieldGenerator{},
			contextFactory: factory,
		},
		openapiBase: server.URL,
		httpc:       server.Client(),
		ui: &userInfo{
			SecurityOAuthToken: "synthetic-old-token",
			RefreshToken:       "synthetic-refresh-token",
			ExpireTime:         time.Now().Add(-time.Hour).Unix(),
			EncryptUserInfo:    "synthetic-old-fields",
			Key:                "synthetic-old-key",
		},
		protoCtx: &fakeProtocolContext{},
		logf:     func(string, ...any) {},
	})
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := a.PrepareInferRequest(context.Background(), inferRequestInput{}); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatalf("PrepareInferRequest() error = %v, want context-closed", err)
	}
	if err := a.forceRefresh(context.Background()); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatalf("forceRefresh() error = %v, want context-closed", err)
	}
	if got := refreshCalls.Load(); got != 0 {
		t.Fatalf("refresh HTTP calls = %d, want 0", got)
	}
	if len(factory.configs) != 0 {
		t.Fatalf("context factory calls = %d, want 0", len(factory.configs))
	}
}

func TestAuthManagerClosedLoginOperationsDoNotCallNetwork(t *testing.T) {
	newClosedManager := func(t *testing.T, handler http.Handler) (*authManager, *atomic.Int32) {
		t.Helper()
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			handler.ServeHTTP(w, r)
		}))
		t.Cleanup(server.Close)
		a := syntheticAuthManager(t, &authManager{
			openapiBase: server.URL,
			webBase:     server.URL,
			machineID:   "synthetic-machine",
			httpc:       server.Client(),
			ui:          &userInfo{SecurityOAuthToken: "synthetic-token"},
			logf:        func(string, ...any) {},
		})
		if err := a.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		return a, &calls
	}

	t.Run("device login", func(t *testing.T) {
		a, calls := newClosedManager(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "must not be called", http.StatusInternalServerError)
		}))
		if err := a.deviceLogin(context.Background(), io.Discard); protocolErrorKindOf(err) != protocolContextClosed {
			t.Fatalf("deviceLogin() error = %v, want context-closed", err)
		}
		if got := calls.Load(); got != 0 {
			t.Fatalf("device login HTTP calls = %d, want 0", got)
		}
	})

	t.Run("PAT login", func(t *testing.T) {
		a, calls := newClosedManager(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "must not be called", http.StatusInternalServerError)
		}))
		if err := patLogin(context.Background(), a, "synthetic-pat"); protocolErrorKindOf(err) != protocolContextClosed {
			t.Fatalf("patLogin() error = %v, want context-closed", err)
		}
		if got := calls.Load(); got != 0 {
			t.Fatalf("PAT login HTTP calls = %d, want 0", got)
		}
	})

	t.Run("fetch user info", func(t *testing.T) {
		a, calls := newClosedManager(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uid":"must-not-apply"}`))
		}))
		a.fetchUserInfo(context.Background(), a.ui)
		if got := calls.Load(); got != 0 {
			t.Fatalf("userinfo HTTP calls = %d, want 0", got)
		}
	})
}

func TestAuthManagerPrepareWrapsRefreshFailureAsUnavailable(t *testing.T) {
	a := syntheticAuthManager(t, &authManager{
		ui: &userInfo{
			SecurityOAuthToken: "synthetic-token",
			ExpireTime:         time.Now().Add(-time.Minute).Unix(),
		},
		protoCtx: &fakeProtocolContext{},
	})
	prepared, err := a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if prepared != nil {
		t.Fatalf("prepared request = %#v, want nil", prepared)
	}
	if got := protocolErrorKindOf(err); got != protocolAuthUnavailable {
		t.Fatalf("error kind = %q, want %q (error: %v)", got, protocolAuthUnavailable, err)
	}
	if got := err.Error(); got != "Authentication is unavailable" {
		t.Fatalf("public error = %q, want safe auth-unavailable message", got)
	}
}

func TestAuthManagerPrepareReturnsUnavailableWithoutContext(t *testing.T) {
	a := syntheticAuthManager(t, &authManager{ui: &userInfo{SecurityOAuthToken: "synthetic-token"}})
	prepared, err := a.PrepareInferRequest(context.Background(), inferRequestInput{})
	if prepared != nil {
		t.Fatalf("prepared request = %#v, want nil", prepared)
	}
	if got := protocolErrorKindOf(err); got != protocolAuthUnavailable {
		t.Fatalf("error kind = %q, want %q (error: %v)", got, protocolAuthUnavailable, err)
	}
}

func TestAuthManagerConcurrentPrepareReplaceAndCloseAvoidsUseAfterClose(t *testing.T) {
	oldRelease := make(chan struct{})
	old := &fakeProtocolContext{prepareStarted: make(chan struct{}), prepareRelease: oldRelease}
	newRelease := make(chan struct{})
	newCtx := &fakeProtocolContext{prepareStarted: make(chan struct{}), prepareRelease: newRelease}
	a := syntheticAuthManager(t, &authManager{
		ui:       &userInfo{SecurityOAuthToken: "synthetic-token"},
		protoCtx: old,
		logf:     func(string, ...any) {},
	})

	oldPrepareDone := make(chan error, 1)
	go func() {
		_, err := a.PrepareInferRequest(context.Background(), inferRequestInput{})
		oldPrepareDone <- err
	}()
	<-old.prepareStarted

	replaceDone := make(chan error, 1)
	go func() { replaceDone <- a.replaceContext(newCtx) }()
	waitForAuthContextWriter(t, a)
	select {
	case err := <-replaceDone:
		t.Fatalf("replaceContext completed during old PrepareInferRequest: %v", err)
	default:
	}
	close(oldRelease)
	if err := <-oldPrepareDone; err != nil {
		t.Fatalf("old PrepareInferRequest() error = %v", err)
	}
	if err := <-replaceDone; err != nil {
		t.Fatalf("replaceContext() error = %v", err)
	}

	newPrepareDone := make(chan error, 1)
	go func() {
		_, err := a.PrepareInferRequest(context.Background(), inferRequestInput{})
		newPrepareDone <- err
	}()
	<-newCtx.prepareStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- a.Close() }()
	waitForAuthContextWriter(t, a)
	select {
	case err := <-closeDone:
		t.Fatalf("Close completed during new PrepareInferRequest: %v", err)
	default:
	}
	close(newRelease)
	if err := <-newPrepareDone; err != nil {
		t.Fatalf("new PrepareInferRequest() error = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if closes, afterClose := old.state(); closes != 1 || afterClose != 0 {
		t.Fatalf("old context state = closes %d, prepare-after-close %d; want 1, 0", closes, afterClose)
	}
	if closes, afterClose := newCtx.state(); closes != 1 || afterClose != 0 {
		t.Fatalf("new context state = closes %d, prepare-after-close %d; want 1, 0", closes, afterClose)
	}

	rejected := &fakeProtocolContext{}
	if err := a.replaceContext(rejected); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatalf("replace after Close() error = %v, want context-closed", err)
	}
	if closes, _ := rejected.state(); closes != 1 {
		t.Fatalf("rejected context Close() count = %d, want 1", closes)
	}
	if _, err := a.PrepareInferRequest(context.Background(), inferRequestInput{}); protocolErrorKindOf(err) != protocolContextClosed {
		t.Fatalf("PrepareInferRequest after Close() error = %v, want context-closed", err)
	}
}

func TestAuthManagerDoesNotCloseNewContextWhenOldCloseFails(t *testing.T) {
	old := &fakeProtocolContext{closeErr: errors.New("synthetic close failure")}
	newCtx := &fakeProtocolContext{prepared: &preparedRequest{URL: "https://new.example.test"}}
	var logs int
	a := syntheticAuthManager(t, &authManager{
		protoCtx: old,
		logf: func(string, ...any) {
			logs++
		},
	})

	if err := a.replaceContext(newCtx); err != nil {
		t.Fatalf("replaceContext() error = %v, want nil", err)
	}
	if closes, _ := old.state(); closes != 1 {
		t.Fatalf("old context Close() count = %d, want 1", closes)
	}
	if closes, _ := newCtx.state(); closes != 0 {
		t.Fatalf("new context Close() count = %d, want 0", closes)
	}
	if logs != 1 {
		t.Fatalf("safe log count = %d, want 1", logs)
	}
	prepared, err := a.prepareWithCurrentContext(context.Background(), inferRequestInput{})
	if err != nil {
		t.Fatalf("prepare with new context error = %v", err)
	}
	if prepared.URL != "https://new.example.test" {
		t.Fatalf("prepared URL = %q, want replacement context URL", prepared.URL)
	}
}

func TestAuthManagerBuildsTypedProtocolInputsWithCopiedTags(t *testing.T) {
	a := syntheticAuthManager(t, &authManager{
		machineID: "synthetic-machine",
		ui: &userInfo{
			UID: "synthetic-user", OrgID: "synthetic-org", OrgTags: []string{"one", "two"},
			DataPolicyAgreed: true, EncryptUserInfo: "synthetic-encrypted-user", Key: "synthetic-key",
		},
	})

	a.mu.Lock()
	runtimeInput := a.runtimeFieldInputLocked()
	config := a.contextConfigLocked()
	a.mu.Unlock()

	wantRuntime := runtimeFieldInput{
		UID: "synthetic-user", OrganizationID: "synthetic-org", OrganizationTags: []string{"one", "two"}, DataPolicyAgreed: true,
	}
	if !reflect.DeepEqual(runtimeInput, wantRuntime) {
		t.Fatalf("runtimeFieldInputLocked() = %#v, want %#v", runtimeInput, wantRuntime)
	}
	wantConfig := protocolContextConfig{
		MachineID: "synthetic-machine",
		Version:   qoderProtocolVersion,
		User: protocolUserInfo{
			UID: "synthetic-user", EncryptUserInfo: "synthetic-encrypted-user", Key: "synthetic-key",
			OrganizationID: "synthetic-org", OrganizationTags: []string{"one", "two"}, DataPolicyAgreed: true,
		},
		Scene: defaultProtocolScene(),
	}
	if !reflect.DeepEqual(config, wantConfig) {
		t.Fatalf("contextConfigLocked() = %#v, want %#v", config, wantConfig)
	}

	runtimeInput.OrganizationTags[0] = "runtime-mutated"
	config.User.OrganizationTags[1] = "config-mutated"
	if got := a.ui.OrgTags; !reflect.DeepEqual(got, []string{"one", "two"}) {
		t.Fatalf("typed input mutation changed auth tags: %#v", got)
	}
}

func TestMachineCredentialKeyUsesFirst16Characters(t *testing.T) {
	tests := []struct {
		name      string
		machineID string
		want      string
	}{
		{name: "long", machineID: "0123456789abcdef-extra", want: "0123456789abcdef"},
		{name: "short", machineID: "short-id", want: "short-id"},
		{name: "empty", machineID: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := machineCredentialKey(tt.machineID); got != tt.want {
				t.Fatalf("machineCredentialKey(%q) = %q, want %q", tt.machineID, got, tt.want)
			}
		})
	}
}

func TestAuthManagerNativeCredentialPlainJSONBypassesDecrypt(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	plain, err := json.Marshal(userInfo{
		UID:                "synthetic-native-plain-user",
		SecurityOAuthToken: "synthetic-native-plain-token",
		EncryptUserInfo:    "synthetic-native-runtime-field",
		Key:                "synthetic-native-runtime-key",
	})
	if err != nil {
		t.Fatal("marshal synthetic plaintext credential")
	}
	if err := os.WriteFile(authFile, plain, 0o600); err != nil {
		t.Fatalf("write plaintext credential: %v", err)
	}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    nativeCredentialCodec{},
			runtimeFields:  &fakeRuntimeFieldGenerator{},
			contextFactory: factory,
		},
		authFile:  authFile,
		machineID: "synthetic-machine",
		logf:      func(string, ...any) {},
	})

	if err := a.load(context.Background()); err != nil {
		t.Fatalf("load plaintext with native service returned error kind %q", protocolErrorKindOf(err))
	}
	if a.ui == nil || a.ui.UID != "synthetic-native-plain-user" {
		t.Fatal("plaintext native-service load did not preserve the synthetic user")
	}
	if len(factory.configs) != 1 {
		t.Fatalf("plaintext native-service context factory calls = %d, want 1", len(factory.configs))
	}
}

func TestAuthManagerNativeCredentialLoadsOfficialFixture(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "credential.json")
	var input credentialFixtureInput
	var expected credentialFixtureExpected
	decodeExactJSON(t, fixture.Input, &input)
	decodeExactJSON(t, fixture.Expected, &expected)

	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	if err := os.WriteFile(authFile, []byte(expected.Encrypted), 0o600); err != nil {
		t.Fatalf("write fixture credential length %d: %v", len(expected.Encrypted), err)
	}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
	a := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    nativeCredentialCodec{},
			runtimeFields:  &fakeRuntimeFieldGenerator{},
			contextFactory: factory,
		},
		authFile:  authFile,
		machineID: protocolFixtureMachineID,
		logf:      func(string, ...any) {},
	})

	if err := a.load(context.Background()); err != nil {
		t.Fatalf("load fixture ciphertext length %d returned error kind %q", len(expected.Encrypted), protocolErrorKindOf(err))
	}
	var fixtureUI userInfo
	if err := json.Unmarshal([]byte(input.Plain), &fixtureUI); err != nil {
		t.Fatalf("decode fixture plaintext length %d", len(input.Plain))
	}
	if a.ui == nil || a.ui.UID != fixtureUI.UID || a.ui.OrgID != fixtureUI.OrgID || a.ui.AccessToken != fixtureUI.AccessToken {
		t.Fatal("native fixture load did not preserve synthetic credential fields")
	}
	if len(factory.configs) != 1 {
		t.Fatalf("fixture native-service context factory calls = %d, want 1", len(factory.configs))
	}
}

func TestAuthManagerNativeCredentialSaveWritesDecryptableCompleteCiphertext(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	want := &userInfo{
		UID:                "synthetic-native-save-user",
		OrgID:              "synthetic-native-save-org",
		SecurityOAuthToken: "synthetic-native-save-token",
		AccessToken:        "synthetic-native-save-token",
		RefreshToken:       "synthetic-native-save-refresh",
		EncryptUserInfo:    "synthetic-native-save-runtime-field",
		Key:                "synthetic-native-save-runtime-key",
	}
	a := syntheticAuthManager(t, &authManager{
		protocol:  &protocolServices{credentials: nativeCredentialCodec{}},
		authFile:  authFile,
		machineID: "0123456789abcdef-extra",
		ui:        want,
	})

	if err := a.save(context.Background()); err != nil {
		t.Fatalf("native credential save returned error kind %q", protocolErrorKindOf(err))
	}
	ciphertext, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("read native-saved credential: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("native-saved credential is empty")
	}
	plain, err := (nativeCredentialCodec{}).Decrypt(context.Background(), string(ciphertext), machineCredentialKey(a.machineID))
	if err != nil {
		t.Fatalf("native decrypt of saved ciphertext length %d returned kind %q", len(ciphertext), protocolErrorKindOf(err))
	}
	var got userInfo
	if err := json.Unmarshal([]byte(plain), &got); err != nil {
		t.Fatalf("decode native-decrypted credential length %d", len(plain))
	}
	if got.UID != want.UID || got.OrgID != want.OrgID || got.SecurityOAuthToken != want.SecurityOAuthToken || got.RefreshToken != want.RefreshToken {
		t.Fatal("native save/decrypt did not preserve synthetic credential fields")
	}
	assertCredentialFileMode(t, authFile)
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".user-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("native save temp leftovers count = %d, error presence %t", len(leftovers), err != nil)
	}
}

func TestAuthManagerNativeCredentialFailurePrecedesFinalFileWrite(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	original := []byte("synthetic-existing-final-state")
	if err := os.WriteFile(authFile, original, 0o600); err != nil {
		t.Fatalf("write existing final state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "machine_id"), []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := newAuthManager(storeTestServices(), dir, "", "", "", nil)
	if !isAuthConflict(err) {
		t.Fatalf("invalid machine identity should be rejected before any credential write: %v", err)
	}
	final, readErr := os.ReadFile(authFile)
	if readErr != nil {
		t.Fatalf("read final state after codec failure: %v", readErr)
	}
	if !reflect.DeepEqual(final, original) {
		t.Fatalf("final state changed after codec failure: length %d, want %d", len(final), len(original))
	}
	if leftovers, globErr := filepath.Glob(filepath.Join(dir, ".user-*")); globErr != nil || len(leftovers) != 0 {
		t.Fatalf("codec failure temp leftovers count = %d, error presence %t", len(leftovers), globErr != nil)
	}
}

func TestAuthManagerTypedInputsNormalizeNilOrganizationTagsAtSemanticBoundary(t *testing.T) {
	for _, tt := range []struct {
		name string
		tags []string
	}{
		{name: "nil", tags: nil},
		{name: "non-nil empty", tags: []string{}},
		{name: "values", tags: []string{"one", "two"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ui := &userInfo{UID: "synthetic-tag-shape-user", OrgTags: tt.tags}
			manager := syntheticAuthManager(t, &authManager{machineID: "synthetic-machine", ui: ui})
			cloned := cloneUserInfo(ui)
			runtimeInput := manager.runtimeFieldInputForLocked(ui)
			config := manager.contextConfigForLocked(ui)
			if (cloned.OrgTags == nil) != (tt.tags == nil) {
				t.Fatalf("case %s: low-level clone did not preserve tag nilness", tt.name)
			}
			if runtimeInput.OrganizationTags == nil || config.User.OrganizationTags == nil {
				t.Fatalf("case %s: auth semantic boundary retained nil tags", tt.name)
			}
			want := tt.tags
			if want == nil {
				want = []string{}
			}
			if !reflect.DeepEqual(runtimeInput.OrganizationTags, want) || !reflect.DeepEqual(config.User.OrganizationTags, want) {
				t.Fatalf("case %s: normalized tag values/order differ", tt.name)
			}
			if len(tt.tags) > 0 {
				runtimeInput.OrganizationTags[0] = "runtime-mutated"
				config.User.OrganizationTags[0] = "config-mutated"
				if ui.OrgTags[0] != "one" {
					t.Fatalf("case %s: boundary output aliases source tags", tt.name)
				}
			}
		})
	}
}

func assertAuthProtocolInputsUseNonNilEmptyTags(t *testing.T, generator *fakeRuntimeFieldGenerator, factory *fakeProtocolContextFactory, wantFactoryCalls int) {
	t.Helper()
	if generator.calls != 1 || len(generator.inputs) != 1 {
		t.Fatalf("runtime generator calls/inputs = %d/%d, want 1/1", generator.calls, len(generator.inputs))
	}
	if generator.inputs[0].OrganizationTags == nil || len(generator.inputs[0].OrganizationTags) != 0 {
		t.Fatal("runtime generator did not receive non-nil empty organization tags")
	}
	if len(factory.configs) != wantFactoryCalls {
		t.Fatalf("context factory calls = %d, want %d", len(factory.configs), wantFactoryCalls)
	}
	for i, config := range factory.configs {
		if config.User.OrganizationTags == nil || len(config.User.OrganizationTags) != 0 {
			t.Fatalf("context factory call %d did not receive non-nil empty organization tags", i+1)
		}
	}
}

func TestAuthManagerDeviceLoginNormalizesNilOrganizationTagsBeforeContextBuild(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/deviceToken/poll":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"synthetic-device-token","user_id":"synthetic-device-user","user_name":"Synthetic User","expires_in":7200}`))
		case "/api/v1/userinfo":
			http.Error(w, "synthetic unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	generator := &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "synthetic-runtime-field", Key: "synthetic-runtime-key"}}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
	manager := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    &fakeCredentialCodec{encrypted: "synthetic-encrypted-credential"},
			runtimeFields:  generator,
			contextFactory: factory,
		},
		authFile:    filepath.Join(t.TempDir(), "user"),
		machineID:   "0123456789abcdef-extra",
		openapiBase: server.URL,
		webBase:     server.URL,
		httpc:       server.Client(),
		logf:        func(string, ...any) {},
	})

	if err := manager.deviceLogin(context.Background(), io.Discard); err != nil {
		t.Fatalf("deviceLogin() error = %v", err)
	}
	assertAuthProtocolInputsUseNonNilEmptyTags(t, generator, factory, 1)
	if manager.ui == nil || manager.ui.OrgTags != nil {
		t.Fatal("device login unexpectedly mutated persisted nil organization tags")
	}
}

type sequentialLoginCredentialCodec struct {
	mu    sync.Mutex
	calls int
}

func (c *sequentialLoginCredentialCodec) Encrypt(context.Context, string, string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return fmt.Sprintf("synthetic-login-ciphertext-%d", c.calls), nil
}

func (*sequentialLoginCredentialCodec) Decrypt(context.Context, string, string) (string, error) {
	return "", errors.New("synthetic decrypt must not run")
}

func (c *sequentialLoginCredentialCodec) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestAuthManagerStaleDeviceEnrichmentDoesNotMutateNewerLogin(t *testing.T) {
	profileStarted := make(chan struct{})
	profileRelease := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/deviceToken/poll":
			_, _ = w.Write([]byte(`{"token":"synthetic-login-a-token","user_id":"synthetic-login-a-user","user_name":"Initial A","expires_in":7200}`))
		case "/api/v1/jobToken/exchange":
			_, _ = w.Write([]byte(`{"token":"synthetic-login-b-token","refresh_token":"synthetic-login-b-refresh","expires_in":7200}`))
		case "/api/v1/userinfo":
			switch r.Header.Get("Authorization") {
			case "Bearer synthetic-login-a-token":
				close(profileStarted)
				<-profileRelease
				_, _ = w.Write([]byte(`{"uid":"synthetic-login-a-user","name":"Delayed A","organization_id":"synthetic-login-a-org","organization_tags":["synthetic-login-a-tag"]}`))
			case "Bearer synthetic-login-b-token":
				_, _ = w.Write([]byte(`{"uid":"synthetic-login-b-user","name":"Current B","organization_id":"synthetic-login-b-org","organization_tags":["synthetic-login-b-tag"]}`))
			default:
				http.Error(w, "synthetic authorization mismatch", http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	contextA := &fakeProtocolContext{}
	contextB := &fakeProtocolContext{}
	staleContext := &fakeProtocolContext{}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{contextA, contextB, staleContext}}
	codec := &sequentialLoginCredentialCodec{}
	manager := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials: codec,
			runtimeFields: &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{
				EncryptUserInfo: "synthetic-login-runtime", Key: "synthetic-login-runtime-key",
			}},
			contextFactory: factory,
		},
		authFile:    filepath.Join(t.TempDir(), "user"),
		machineID:   "0123456789abcdef-extra",
		openapiBase: server.URL,
		webBase:     server.URL,
		httpc:       server.Client(),
		logf:        func(string, ...any) {},
	})

	var deviceOutput bytes.Buffer
	deviceDone := make(chan error, 1)
	go func() {
		deviceDone <- manager.deviceLogin(context.Background(), &deviceOutput)
	}()
	<-profileStarted

	if err := patLogin(context.Background(), manager, "synthetic-login-b-pat"); err != nil {
		close(profileRelease)
		<-deviceDone
		t.Fatalf("concurrent PAT login error = %v", err)
	}
	manager.mu.Lock()
	activePointer := manager.ui
	activeSnapshot := cloneUserInfo(manager.ui)
	dirtyBefore := manager.credentialDirty
	manager.mu.Unlock()
	manager.ctxMu.RLock()
	activeContext := manager.protoCtx
	manager.ctxMu.RUnlock()
	fileBefore, err := os.ReadFile(manager.authFile)
	if err != nil {
		close(profileRelease)
		<-deviceDone
		t.Fatal("read current credential before stale response failed")
	}
	factory.mu.Lock()
	factoryCallsBefore := len(factory.configs)
	factory.mu.Unlock()
	codecCallsBefore := codec.callCount()

	close(profileRelease)
	if err := <-deviceDone; err != nil {
		t.Fatalf("device login A error = %v", err)
	}

	manager.mu.Lock()
	activePointerAfter := manager.ui
	activeSnapshotAfter := cloneUserInfo(manager.ui)
	dirtyAfter := manager.credentialDirty
	manager.mu.Unlock()
	manager.ctxMu.RLock()
	activeContextAfter := manager.protoCtx
	manager.ctxMu.RUnlock()
	fileAfter, err := os.ReadFile(manager.authFile)
	if err != nil {
		t.Fatal("read current credential after stale response failed")
	}
	factory.mu.Lock()
	factoryCallsAfter := len(factory.configs)
	factory.mu.Unlock()
	codecCallsAfter := codec.callCount()

	if activePointerAfter != activePointer || !reflect.DeepEqual(activeSnapshotAfter, activeSnapshot) {
		t.Fatal("stale device profile mutated or replaced the newer login UI")
	}
	if activeContext != contextB || activeContextAfter != contextB {
		t.Fatal("stale device profile replaced the newer login context")
	}
	if dirtyBefore || dirtyAfter {
		t.Fatal("stale device profile dirtied the newer login state")
	}
	if !bytes.Equal(fileAfter, fileBefore) {
		t.Fatal("stale device profile changed the newer login credential file")
	}
	if factoryCallsBefore != 2 || factoryCallsAfter != 2 {
		t.Fatalf("context factory calls before/after stale response = %d/%d, want 2/2", factoryCallsBefore, factoryCallsAfter)
	}
	if codecCallsBefore != 2 || codecCallsAfter != 2 {
		t.Fatalf("credential Encrypt() calls before/after stale response = %d/%d, want 2/2", codecCallsBefore, codecCallsAfter)
	}
	if !strings.Contains(deviceOutput.String(), "Login successful. uid=synthetic-login-a-user name=Initial A") {
		t.Fatal("device login A success output did not use its own candidate snapshot")
	}
	contextACloses, _ := contextA.state()
	contextBCloses, _ := contextB.state()
	staleCloses, _ := staleContext.state()
	if contextACloses != 1 || contextBCloses != 0 || staleCloses != 0 {
		t.Fatalf("context close counts A/B/stale = %d/%d/%d, want 1/0/0 before manager Close", contextACloses, contextBCloses, staleCloses)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("manager Close() error = %v", err)
	}
	contextBCloses, _ = contextB.state()
	if contextBCloses != 1 {
		t.Fatalf("newer login context Close() calls = %d, want 1", contextBCloses)
	}
}

func TestAuthManagerDeviceLoginPreservesTwoStageCredentialDurability(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/deviceToken/poll":
			_, _ = w.Write([]byte(`{"token":"synthetic-device-token","user_id":"synthetic-device-user","user_name":"Initial Name","expires_in":7200}`))
		case "/api/v1/userinfo":
			_, _ = w.Write([]byte(`{"uid":"synthetic-device-user","name":"Enriched Name","organization_id":"synthetic-device-org","organization_tags":["synthetic-device-tag"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	firstContext := &fakeProtocolContext{}
	secondContext := &fakeProtocolContext{}
	codec := &fakeCredentialCodec{encrypted: "synthetic-encrypted-credential"}
	manager := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials: codec,
			runtimeFields: &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{
				EncryptUserInfo: "synthetic-runtime-field", Key: "synthetic-runtime-key",
			}},
			contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{firstContext, secondContext}},
		},
		authFile:    filepath.Join(t.TempDir(), "user"),
		machineID:   "0123456789abcdef-extra",
		openapiBase: server.URL,
		webBase:     server.URL,
		httpc:       server.Client(),
		logf:        func(string, ...any) {},
	})

	if err := manager.deviceLogin(context.Background(), io.Discard); err != nil {
		t.Fatalf("deviceLogin() error = %v", err)
	}
	codec.mu.Lock()
	plains := append([]string(nil), codec.encryptPlains...)
	encryptCalls := codec.encryptCalls
	codec.mu.Unlock()
	if encryptCalls != 2 || len(plains) != 2 {
		t.Fatalf("device login credential saves/captured plains = %d/%d, want 2/2", encryptCalls, len(plains))
	}
	var initial, enriched userInfo
	if json.Unmarshal([]byte(plains[0]), &initial) != nil || json.Unmarshal([]byte(plains[1]), &enriched) != nil {
		t.Fatal("device login credential plaintext capture is not valid JSON")
	}
	if initial.Name != "Initial Name" || initial.OrgID != "" {
		t.Fatal("first device credential save was not the initial usable candidate")
	}
	if enriched.Name != "Enriched Name" || enriched.OrgID != "synthetic-device-org" || !reflect.DeepEqual(enriched.OrgTags, []string{"synthetic-device-tag"}) {
		t.Fatal("second device credential save did not contain best-effort enrichment")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() after successful device login error = %v", err)
	}
	codec.mu.Lock()
	encryptCalls = codec.encryptCalls
	codec.mu.Unlock()
	if encryptCalls != 2 {
		t.Fatalf("Close() added credential save %d after clean enrichment, want total 2", encryptCalls)
	}
	firstCloses, _ := firstContext.state()
	secondCloses, _ := secondContext.state()
	if firstCloses != 1 || secondCloses != 1 {
		t.Fatalf("device context close counts first/second = %d/%d, want 1/1", firstCloses, secondCloses)
	}
}

func TestAuthManagerPATLoginNormalizesEmptyUserInfoTagsBeforeContextBuild(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/jobToken/exchange":
			_, _ = w.Write([]byte(`{"token":"synthetic-pat-token","refresh_token":"synthetic-pat-refresh","expires_in":7200}`))
		case "/api/v1/userinfo":
			_, _ = w.Write([]byte(`{"uid":"synthetic-pat-user","organization_tags":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	generator := &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "synthetic-runtime-field", Key: "synthetic-runtime-key"}}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
	codec := &fakeCredentialCodec{encrypted: "synthetic-encrypted-credential"}
	manager := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    codec,
			runtimeFields:  generator,
			contextFactory: factory,
		},
		authFile:    filepath.Join(t.TempDir(), "user"),
		machineID:   "0123456789abcdef-extra",
		openapiBase: server.URL,
		httpc:       server.Client(),
		logf:        func(string, ...any) {},
	})

	if err := patLogin(context.Background(), manager, "synthetic-pat"); err != nil {
		t.Fatalf("patLogin() error = %v", err)
	}
	assertAuthProtocolInputsUseNonNilEmptyTags(t, generator, factory, 1)
	codec.mu.Lock()
	encryptCalls := codec.encryptCalls
	codec.mu.Unlock()
	if encryptCalls != 1 {
		t.Fatalf("PAT credential Encrypt() calls = %d, want one committed candidate save", encryptCalls)
	}
	if manager.ui == nil || manager.ui.UID != "synthetic-pat-user" || manager.ui.OrgTags != nil {
		t.Fatal("PAT login did not retain fetched identity with unpersisted empty tag shape")
	}
}

func TestAuthManagerLoadNormalizesAbsentOrNullOrganizationTagsBeforeContextBuild(t *testing.T) {
	for _, tt := range []struct {
		name string
		json string
	}{
		{name: "absent", json: `{"uid":"synthetic-load-user","security_oauth_token":"synthetic-load-token"}`},
		{name: "null", json: `{"uid":"synthetic-load-user","security_oauth_token":"synthetic-load-token","organization_tags":null}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			authFile := filepath.Join(dir, "user")
			if err := os.WriteFile(authFile, []byte(tt.json), 0o600); err != nil {
				t.Fatal("write synthetic credential failed")
			}
			generator := &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "synthetic-runtime-field", Key: "synthetic-runtime-key"}}
			factory := &fakeProtocolContextFactory{contexts: []protocolContext{&fakeProtocolContext{}}}
			manager := syntheticAuthManager(t, &authManager{
				protocol: &protocolServices{
					credentials:    &fakeCredentialCodec{},
					runtimeFields:  generator,
					contextFactory: factory,
				},
				authFile:  authFile,
				machineID: "0123456789abcdef-extra",
				logf:      func(string, ...any) {},
			})

			if err := manager.load(context.Background()); err != nil {
				t.Fatalf("load() error = %v", err)
			}
			assertAuthProtocolInputsUseNonNilEmptyTags(t, generator, factory, 1)
			if manager.ui == nil || manager.ui.OrgTags != nil {
				t.Fatal("load unexpectedly mutated stored nil organization tags")
			}
		})
	}
}

type loginReplacementFailureFactory struct {
	manager *authManager
	next    protocolContext
	calls   int
}

func (f *loginReplacementFailureFactory) New(context.Context, protocolContextConfig) (protocolContext, error) {
	f.calls++
	f.manager.ctxMu.Lock()
	f.manager.closed = true
	f.manager.ctxMu.Unlock()
	return f.next, nil
}

func assertFailedLoginTransactionPreserved(
	t *testing.T,
	manager *authManager,
	priorUI *userInfo,
	priorSnapshot *userInfo,
	priorContext *fakeProtocolContext,
	codec *fakeCredentialCodec,
	authFile string,
	original []byte,
	wantEncryptCalls int,
) {
	t.Helper()
	manager.mu.Lock()
	gotUI := manager.ui
	gotDirty := manager.credentialDirty
	manager.mu.Unlock()
	manager.ctxMu.RLock()
	gotContext := manager.protoCtx
	manager.ctxMu.RUnlock()

	closeErr := manager.Close()
	final, readErr := os.ReadFile(authFile)
	codec.mu.Lock()
	encryptCalls := codec.encryptCalls
	codec.mu.Unlock()
	priorCloses, _ := priorContext.state()

	if gotUI != priorUI || !reflect.DeepEqual(gotUI, priorSnapshot) {
		t.Fatal("failed login replaced or mutated prior in-memory credentials")
	}
	if gotDirty {
		t.Fatal("failed login left new credential state dirty")
	}
	if gotContext != priorContext {
		t.Fatal("failed login replaced the prior protocol context")
	}
	if closeErr != nil {
		t.Fatalf("Close() after failed login error = %v", closeErr)
	}
	if readErr != nil || !reflect.DeepEqual(final, original) {
		t.Fatalf("credential file changed after failed login cleanup: read error presence=%t", readErr != nil)
	}
	if encryptCalls != wantEncryptCalls {
		t.Fatalf("credential Encrypt() calls after failed login = %d, want %d", encryptCalls, wantEncryptCalls)
	}
	if priorCloses != 1 {
		t.Fatalf("prior protocol context Close() calls = %d, want 1 during final manager Close", priorCloses)
	}
}

func TestAuthManagerDeviceLoginFailureDoesNotCommitCandidate(t *testing.T) {
	for _, tt := range []struct {
		name               string
		configureFactory   func(*authManager) (protocolContextFactory, *fakeProtocolContext)
		resetAfterFailure  func(*authManager)
		wantCandidateClose int
	}{
		{
			name: "context build failure",
			configureFactory: func(*authManager) (protocolContextFactory, *fakeProtocolContext) {
				return &fakeProtocolContextFactory{err: errors.New("synthetic candidate context build failure")}, nil
			},
		},
		{
			name: "context replacement failure",
			configureFactory: func(manager *authManager) (protocolContextFactory, *fakeProtocolContext) {
				candidateContext := &fakeProtocolContext{}
				return &loginReplacementFailureFactory{manager: manager, next: candidateContext}, candidateContext
			},
			resetAfterFailure: func(manager *authManager) {
				manager.ctxMu.Lock()
				manager.closed = false
				manager.ctxMu.Unlock()
			},
			wantCandidateClose: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/deviceToken/poll" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"token":"synthetic-device-candidate","user_id":"synthetic-device-candidate-user","expires_in":7200}`))
			}))
			defer server.Close()

			dir := t.TempDir()
			authFile := filepath.Join(dir, "user")
			original := []byte("synthetic-existing-device-credential")
			if err := os.WriteFile(authFile, original, 0o600); err != nil {
				t.Fatal("write existing device credential failed")
			}
			priorUI := &userInfo{
				UID: "synthetic-prior-user", SecurityOAuthToken: "synthetic-prior-token",
				EncryptUserInfo: "synthetic-prior-runtime", Key: "synthetic-prior-key",
				OrgTags: []string{"synthetic-prior-tag"},
			}
			priorSnapshot := cloneUserInfo(priorUI)
			priorContext := &fakeProtocolContext{}
			codec := &fakeCredentialCodec{encrypted: "synthetic-candidate-ciphertext"}
			manager := syntheticAuthManager(t, &authManager{
				authFile: authFile, machineID: "0123456789abcdef-extra",
				openapiBase: server.URL, webBase: server.URL, httpc: server.Client(),
				ui: priorUI, protoCtx: priorContext, logf: func(string, ...any) {},
			})
			factory, candidateContext := tt.configureFactory(manager)
			manager.protocol = &protocolServices{
				credentials: codec,
				runtimeFields: &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{
					EncryptUserInfo: "synthetic-candidate-runtime", Key: "synthetic-candidate-key",
				}},
				contextFactory: factory,
			}

			if err := manager.deviceLogin(context.Background(), io.Discard); err == nil {
				t.Fatal("deviceLogin() error = nil, want candidate failure")
			}
			if tt.resetAfterFailure != nil {
				tt.resetAfterFailure(manager)
			}
			if candidateContext != nil {
				candidateCloses, _ := candidateContext.state()
				if candidateCloses != tt.wantCandidateClose {
					t.Fatalf("candidate context Close() calls = %d, want %d", candidateCloses, tt.wantCandidateClose)
				}
			}
			assertFailedLoginTransactionPreserved(t, manager, priorUI, priorSnapshot, priorContext, codec, authFile, original, 0)
		})
	}
}

func TestAuthManagerDeviceLoginPersistenceFailureDoesNotCommitOrRetryCandidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/deviceToken/poll" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"synthetic-device-candidate","user_id":"synthetic-device-candidate-user","expires_in":7200}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	original := []byte("synthetic-existing-device-credential")
	if err := os.WriteFile(authFile, original, 0o600); err != nil {
		t.Fatal("write existing device credential failed")
	}
	priorUI := &userInfo{
		UID: "synthetic-prior-user", SecurityOAuthToken: "synthetic-prior-token",
		EncryptUserInfo: "synthetic-prior-runtime", Key: "synthetic-prior-key",
		OrgTags: []string{"synthetic-prior-tag"},
	}
	priorSnapshot := cloneUserInfo(priorUI)
	priorContext := &fakeProtocolContext{}
	candidateContext := &fakeProtocolContext{}
	stageErr := errors.New("synthetic candidate credential stage failure")
	codec := &fakeCredentialCodec{
		encrypted:   "synthetic-device-candidate-ciphertext",
		encryptErrs: []error{stageErr, nil},
	}
	manager := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials: codec,
			runtimeFields: &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{
				EncryptUserInfo: "synthetic-candidate-runtime", Key: "synthetic-candidate-key",
			}},
			contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{candidateContext}},
		},
		authFile: authFile, machineID: "0123456789abcdef-extra",
		openapiBase: server.URL, webBase: server.URL, httpc: server.Client(),
		ui: priorUI, protoCtx: priorContext, logf: func(string, ...any) {},
	})

	if err := manager.deviceLogin(context.Background(), io.Discard); err == nil || !errors.Is(err, stageErr) {
		t.Fatalf("deviceLogin() error = %v, want candidate stage failure", err)
	}
	candidateCloses, _ := candidateContext.state()
	if candidateCloses != 1 {
		t.Fatalf("device candidate context Close() calls = %d, want 1", candidateCloses)
	}
	assertFailedLoginTransactionPreserved(t, manager, priorUI, priorSnapshot, priorContext, codec, authFile, original, 1)
}

func TestAuthManagerPATLoginPersistenceFailureDoesNotCommitOrRetryCandidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/jobToken/exchange":
			_, _ = w.Write([]byte(`{"token":"synthetic-pat-candidate","refresh_token":"synthetic-pat-refresh","expires_in":7200}`))
		case "/api/v1/userinfo":
			_, _ = w.Write([]byte(`{"uid":"synthetic-pat-candidate-user","organization_tags":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	authFile := filepath.Join(dir, "user")
	original := []byte("synthetic-existing-pat-credential")
	if err := os.WriteFile(authFile, original, 0o600); err != nil {
		t.Fatal("write existing PAT credential failed")
	}
	priorUI := &userInfo{
		UID: "synthetic-prior-user", SecurityOAuthToken: "synthetic-prior-token",
		EncryptUserInfo: "synthetic-prior-runtime", Key: "synthetic-prior-key",
		OrgTags: []string{"synthetic-prior-tag"},
	}
	priorSnapshot := cloneUserInfo(priorUI)
	priorContext := &fakeProtocolContext{}
	candidateContext := &fakeProtocolContext{}
	stageErr := errors.New("synthetic PAT candidate credential stage failure")
	codec := &fakeCredentialCodec{
		encrypted:   "synthetic-pat-candidate-ciphertext",
		encryptErrs: []error{stageErr, nil},
	}
	manager := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials: codec,
			runtimeFields: &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{
				EncryptUserInfo: "synthetic-pat-runtime", Key: "synthetic-pat-key",
			}},
			contextFactory: &fakeProtocolContextFactory{contexts: []protocolContext{candidateContext}},
		},
		authFile: authFile, machineID: "0123456789abcdef-extra",
		openapiBase: server.URL, httpc: server.Client(),
		ui: priorUI, protoCtx: priorContext, logf: func(string, ...any) {},
	})

	if err := patLogin(context.Background(), manager, "synthetic-pat"); err == nil || !errors.Is(err, stageErr) {
		t.Fatalf("patLogin() error = %v, want candidate stage failure", err)
	}
	candidateCloses, _ := candidateContext.state()
	if candidateCloses != 1 {
		t.Fatalf("PAT candidate context Close() calls = %d, want 1", candidateCloses)
	}
	assertFailedLoginTransactionPreserved(t, manager, priorUI, priorSnapshot, priorContext, codec, authFile, original, 1)
}

func TestAuthManagerPATLoginFailureDoesNotCommitCandidate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		userinfoStatus   int
		userinfoBody     string
		factoryErr       error
		wantFactoryCalls int
	}{
		{
			name:           "userinfo failure",
			userinfoStatus: http.StatusServiceUnavailable,
			userinfoBody:   `{"message":"synthetic unavailable"}`,
		},
		{
			name:             "context build failure",
			userinfoStatus:   http.StatusOK,
			userinfoBody:     `{"uid":"synthetic-pat-candidate-user","organization_tags":[]}`,
			factoryErr:       errors.New("synthetic PAT candidate context failure"),
			wantFactoryCalls: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v1/jobToken/exchange":
					_, _ = w.Write([]byte(`{"token":"synthetic-pat-candidate","refresh_token":"synthetic-pat-refresh","expires_in":7200}`))
				case "/api/v1/userinfo":
					w.WriteHeader(tt.userinfoStatus)
					_, _ = w.Write([]byte(tt.userinfoBody))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			dir := t.TempDir()
			authFile := filepath.Join(dir, "user")
			original := []byte("synthetic-existing-pat-credential")
			if err := os.WriteFile(authFile, original, 0o600); err != nil {
				t.Fatal("write existing PAT credential failed")
			}
			priorUI := &userInfo{
				UID: "synthetic-prior-user", SecurityOAuthToken: "synthetic-prior-token",
				EncryptUserInfo: "synthetic-prior-runtime", Key: "synthetic-prior-key",
				OrgTags: []string{"synthetic-prior-tag"},
			}
			priorSnapshot := cloneUserInfo(priorUI)
			priorContext := &fakeProtocolContext{}
			codec := &fakeCredentialCodec{encrypted: "synthetic-pat-candidate-ciphertext"}
			factory := &fakeProtocolContextFactory{err: tt.factoryErr}
			manager := syntheticAuthManager(t, &authManager{
				protocol: &protocolServices{
					credentials: codec,
					runtimeFields: &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{
						EncryptUserInfo: "synthetic-pat-runtime", Key: "synthetic-pat-key",
					}},
					contextFactory: factory,
				},
				authFile: authFile, machineID: "0123456789abcdef-extra",
				openapiBase: server.URL, httpc: server.Client(),
				ui: priorUI, protoCtx: priorContext, logf: func(string, ...any) {},
			})

			if err := patLogin(context.Background(), manager, "synthetic-pat"); err == nil {
				t.Fatal("patLogin() error = nil, want candidate failure")
			}
			if len(factory.configs) != tt.wantFactoryCalls {
				t.Fatalf("PAT candidate context factory calls = %d, want %d", len(factory.configs), tt.wantFactoryCalls)
			}
			assertFailedLoginTransactionPreserved(t, manager, priorUI, priorSnapshot, priorContext, codec, authFile, original, 0)
		})
	}
}

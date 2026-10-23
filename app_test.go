package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ flag.Value = (*trackedString)(nil)

type appEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *appEventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *appEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type appTestBackend struct {
	mu       sync.Mutex
	closes   int
	closeErr error
	onClose  func()
}

func (b *appTestBackend) Close(context.Context) error {
	b.mu.Lock()
	b.closes++
	err := b.closeErr
	onClose := b.onClose
	b.mu.Unlock()
	if onClose != nil {
		onClose()
	}
	return err
}

func (b *appTestBackend) closeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closes
}

type appTestProtocolContext struct {
	mu       sync.Mutex
	closes   int
	closeErr error
	onClose  func()
}

func (*appTestProtocolContext) PrepareInferRequest(context.Context, inferRequestInput) (*preparedRequest, error) {
	return &preparedRequest{URL: "https://synthetic.example.test", Header: make(http.Header), Body: []byte(`{}`)}, nil
}

func (c *appTestProtocolContext) Close() error {
	c.mu.Lock()
	c.closes++
	err := c.closeErr
	onClose := c.onClose
	c.mu.Unlock()
	if onClose != nil {
		onClose()
	}
	return err
}

func (c *appTestProtocolContext) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

type appTestTicker struct {
	ch      chan time.Time
	stopped atomic.Int32
}

func (t *appTestTicker) C() <-chan time.Time { return t.ch }
func (t *appTestTicker) Stop()               { t.stopped.Add(1) }

type appRunHarness struct {
	cfg            appConfig
	services       *protocolServices
	auth           *authManager
	backend        *appTestBackend
	protoCtx       *appTestProtocolContext
	ticker         *appTestTicker
	tickerDuration time.Duration
	deps           appDeps
}

func newAppRunHarness(t *testing.T) *appRunHarness {
	t.Helper()
	authDir := t.TempDir()
	backend := &appTestBackend{}
	protoCtx := &appTestProtocolContext{}
	services := &protocolServices{closeFn: backend.Close}
	auth := &authManager{
		authFile:  filepath.Join(authDir, "user"),
		inferBase: "https://infer.example.test",
		protoCtx:  protoCtx,
		ui: &userInfo{
			UID:                "synthetic-user",
			OrgName:            "Synthetic Org",
			SecurityOAuthToken: "synthetic-token",
			ExpireTime:         time.Now().Add(2 * time.Hour).Unix(),
		},
		logf: func(string, ...any) {},
	}
	ticker := &appTestTicker{ch: make(chan time.Time, 1)}
	h := &appRunHarness{
		cfg: appConfig{
			addr:         ":0",
			authDir:      authDir,
			defaultModel: "auto",
			oneMModel:    "ultimate",
		},
		services: services,
		auth:     auth,
		backend:  backend,
		protoCtx: protoCtx,
		ticker:   ticker,
	}
	h.deps = appDeps{
		newProtocolServices: func(protocolHostDeps) (*protocolServices, error) {
			return h.services, nil
		},
		newAuthManager: func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error) {
			return h.auth, nil
		},
		deviceLogin: func(context.Context, *authManager, io.Writer) error { return nil },
		patLogin:    func(context.Context, *authManager, string) error { return nil },
		loadCredentials: func(context.Context, *authManager) error {
			return nil
		},
		ensureFresh: func(context.Context, *authManager) error { return nil },
		newTicker: func(interval time.Duration) appTicker {
			h.tickerDuration = interval
			return h.ticker
		},
		listenAndServe: func(*http.Server) error { return http.ErrServerClosed },
		shutdown:       func(context.Context, *http.Server) error { return nil },
	}
	return h
}

func (h *appRunHarness) assertClosedOnce(t *testing.T) {
	t.Helper()
	if got := h.protoCtx.closeCount(); got != 1 {
		t.Fatalf("auth protocol context Close() count = %d, want 1", got)
	}
	if got := h.backend.closeCount(); got != 1 {
		t.Fatalf("protocol backend Close() count = %d, want 1", got)
	}
}

func envLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

type apiKeySecretCase struct {
	name      string
	value     string
	fragments []string
}

func apiKeySecretCases() []apiKeySecretCase {
	return []apiKeySecretCase{
		{name: "short", value: "QK7!zP", fragments: []string{"QK7", "!zP"}},
		{name: "long", value: "LEAKME-super-sensitive-ZZ", fragments: []string{"LEAKME", "sensitive", "ZZ"}},
	}
}

func assertNoAPIKeyLeak(t *testing.T, output string, secret apiKeySecretCase) {
	t.Helper()
	for _, forbidden := range append([]string{secret.value}, secret.fragments...) {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains API key material %q:\n%s", forbidden, output)
		}
	}
}

func TestTrackedStringRecordsExplicitSetIncludingEmpty(t *testing.T) {
	tracked := trackedString{value: "default"}
	if tracked.set || tracked.String() != "default" {
		t.Fatalf("initial tracked string = %#v, want unset default", tracked)
	}
	if err := tracked.Set(""); err != nil {
		t.Fatalf("Set(\"\") error = %v", err)
	}
	if !tracked.set || tracked.String() != "" {
		t.Fatalf("tracked string after empty Set = %#v, want explicitly set empty", tracked)
	}
}

func TestParseAppConfigDefaultsMatchCurrentCLI(t *testing.T) {
	cfg, err := parseAppConfig(nil, envLookup(nil), io.Discard)
	if err != nil {
		t.Fatalf("parseAppConfig() error = %v", err)
	}
	want := appConfig{
		region:      "global",
		webEndpoint: defaultBase, openapiEndpoint: defaultOpenapi, inferEndpoint: defaultInfer,
		addr:         ":8377",
		authDir:      filepath.Join(homeDir(), ".qoder", ".auth"),
		defaultModel: "auto",
		oneMModel:    "ultimate",
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("parseAppConfig() = %#v, want %#v", cfg, want)
	}
}

func TestParseAppConfigUsesCurrentEnvironmentVariables(t *testing.T) {
	env := map[string]string{
		"QODER2API_ADDR":             ":env",
		"QODER2API_SK":               "env-sk",
		"QODER2API_AUTH_DIR":         "/env/auth",
		"QODER2API_INFER_ENDPOINT":   "https://env-infer.example.test",
		"QODER2API_OPENAPI_ENDPOINT": "https://env-openapi.example.test",
		"QODER2API_WEB_ENDPOINT":     "https://env-web.example.test",
		"QODER2API_MODEL_MAP":        `{"env":"auto"}`,
		"QODER2API_DEFAULT_MODEL":    "env-default",
		"QODER2API_MODEL_1M":         "env-1m",
		"QODER2API_CATALOG":          "/env/catalog.json",
		"QODER2API_DUMP_DIR":         "/env/dumps",
		"QODER2API_LOG":              "debug",
	}
	cfg, err := parseAppConfig(nil, envLookup(env), io.Discard)
	if err != nil {
		t.Fatalf("parseAppConfig() error = %v", err)
	}
	if cfg.addr != ":env" || cfg.sk != "env-sk" || cfg.authDir != "/env/auth" ||
		cfg.inferEndpoint != "https://env-infer.example.test" || cfg.openapiEndpoint != "https://env-openapi.example.test" ||
		cfg.webEndpoint != "https://env-web.example.test" || cfg.modelMapJSON != `{"env":"auto"}` ||
		cfg.defaultModel != "env-default" || cfg.oneMModel != "env-1m" || cfg.catalogPath != "/env/catalog.json" ||
		cfg.dumpDir != "/env/dumps" || !cfg.verbose || cfg.login || cfg.loginPAT != "" {
		t.Fatalf("environment config = %#v", cfg)
	}
}

func TestParseAppConfigFlagsOverrideEnvironment(t *testing.T) {
	env := map[string]string{
		"QODER2API_ADDR":             ":env",
		"QODER2API_SK":               "env-sk",
		"QODER2API_AUTH_DIR":         "/env/auth",
		"QODER2API_INFER_ENDPOINT":   "https://env-infer.example.test",
		"QODER2API_OPENAPI_ENDPOINT": "https://env-openapi.example.test",
		"QODER2API_WEB_ENDPOINT":     "https://env-web.example.test",
		"QODER2API_MODEL_MAP":        `{"env":"auto"}`,
		"QODER2API_DEFAULT_MODEL":    "env-default",
		"QODER2API_MODEL_1M":         "env-1m",
		"QODER2API_CATALOG":          "/env/catalog.json",
		"QODER2API_DUMP_DIR":         "/env/dumps",
		"QODER2API_LOG":              "debug",
	}
	args := []string{
		"-addr=:flag",
		"-sk=flag-sk",
		"-auth-dir=/flag/auth",
		"-endpoint=https://flag-infer.example.test",
		"-openapi-endpoint=https://flag-openapi.example.test",
		"-web-endpoint=https://flag-web.example.test",
		`-model-map={"flag":"ultimate"}`,
		"-default-model=flag-default",
		"-model-1m=flag-1m",
		"-catalog=/flag/catalog.json",
		"-dump-dir=/flag/dumps",
		"-login-pat=flag-pat",
		"-v=false",
	}
	cfg, err := parseAppConfig(args, envLookup(env), io.Discard)
	if err != nil {
		t.Fatalf("parseAppConfig() error = %v", err)
	}
	if cfg.addr != ":flag" || cfg.sk != "flag-sk" || cfg.authDir != "/flag/auth" ||
		cfg.inferEndpoint != "https://flag-infer.example.test" || cfg.openapiEndpoint != "https://flag-openapi.example.test" ||
		cfg.webEndpoint != "https://flag-web.example.test" || cfg.modelMapJSON != `{"flag":"ultimate"}` ||
		cfg.defaultModel != "flag-default" || cfg.oneMModel != "flag-1m" || cfg.catalogPath != "/flag/catalog.json" ||
		cfg.dumpDir != "/flag/dumps" || cfg.login || cfg.loginPAT != "flag-pat" || cfg.verbose {
		t.Fatalf("flag config = %#v", cfg)
	}
}

func TestParseAppConfigAPIKeyPrecedencePreservesExplicitEmpty(t *testing.T) {
	const envSecret = "environment-secret-value"
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{name: "environment", env: map[string]string{"QODER2API_SK": envSecret}, want: envSecret},
		{name: "flag overrides environment", args: []string{"-sk=flag-secret-value"}, env: map[string]string{"QODER2API_SK": envSecret}, want: "flag-secret-value"},
		{name: "explicit empty flag disables environment key", args: []string{"-sk="}, env: map[string]string{"QODER2API_SK": envSecret}, want: ""},
		{name: "empty environment", env: map[string]string{"QODER2API_SK": ""}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseAppConfig(tt.args, envLookup(tt.env), io.Discard)
			if err != nil {
				t.Fatalf("parseAppConfig() error = %v", err)
			}
			if cfg.sk != tt.want {
				t.Fatalf("cfg.sk = %q, want %q", cfg.sk, tt.want)
			}
		})
	}
}

func TestParseAppConfigNeverPrintsEnvironmentAPIKey(t *testing.T) {
	scenarios := []struct {
		name string
		args []string
	}{
		{name: "help", args: []string{"-h"}},
		{name: "unknown flag", args: []string{"-definitely-unknown"}},
		{name: "malformed boolean", args: []string{"-v=not-bool"}},
	}
	for _, secret := range apiKeySecretCases() {
		secret := secret
		t.Run(secret.name, func(t *testing.T) {
			for _, scenario := range scenarios {
				scenario := scenario
				t.Run(scenario.name, func(t *testing.T) {
					var output bytes.Buffer
					_, err := parseAppConfig(scenario.args, envLookup(map[string]string{"QODER2API_SK": secret.value}), &output)
					if err == nil {
						t.Fatal("parseAppConfig() error = nil, want early parse exit")
					}
					assertNoAPIKeyLeak(t, output.String(), secret)
				})
			}
		})
	}
}

func TestParseAppConfigOrdinaryEmptyEnvironmentFallsBack(t *testing.T) {
	env := map[string]string{
		"QODER2API_ADDR":          "",
		"QODER2API_SK":            "",
		"QODER2API_AUTH_DIR":      "",
		"QODER2API_DEFAULT_MODEL": "",
		"QODER2API_MODEL_1M":      "",
		"QODER2API_LOG":           "",
	}
	cfg, err := parseAppConfig(nil, envLookup(env), io.Discard)
	if err != nil {
		t.Fatalf("parseAppConfig() error = %v", err)
	}
	if cfg.addr != ":8377" || cfg.sk != "" || cfg.authDir != filepath.Join(homeDir(), ".qoder", ".auth") ||
		cfg.defaultModel != "auto" || cfg.oneMModel != "ultimate" || cfg.verbose {
		t.Fatalf("empty environment config = %#v, want ordinary fallbacks", cfg)
	}
}

func TestParseAppConfigHelpReturnsErrHelpAndWritesUsage(t *testing.T) {
	var output bytes.Buffer
	_, err := parseAppConfig([]string{"-h"}, envLookup(nil), &output)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseAppConfig(-h) error = %v, want flag.ErrHelp", err)
	}
	usage := output.String()
	if !strings.Contains(usage, "-addr") {
		t.Fatalf("help output missing -addr:\n%s", usage)
	}
	for _, removed := range []string{"-protocol-mode", "-shadow-capabilities"} {
		if strings.Contains(usage, removed) {
			t.Fatalf("help output still contains removed flag %s:\n%s", removed, usage)
		}
	}
}

func TestParseAppConfigDoesNotPolluteGlobalFlagSet(t *testing.T) {
	for _, name := range []string{"addr"} {
		if flag.CommandLine.Lookup(name) != nil {
			t.Fatalf("global flag set already contains application flag %q", name)
		}
	}
	before := make([]string, 0)
	flag.CommandLine.VisitAll(func(f *flag.Flag) { before = append(before, f.Name) })
	if _, err := parseAppConfig([]string{"-addr=:synthetic"}, envLookup(nil), io.Discard); err != nil {
		t.Fatalf("parseAppConfig() error = %v", err)
	}
	after := make([]string, 0)
	flag.CommandLine.VisitAll(func(f *flag.Flag) { after = append(after, f.Name) })
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("global flags changed from %#v to %#v", before, after)
	}
}

func TestMainParseExitBehavior(t *testing.T) {
	const helperEnv = "QODER2API_TEST_MAIN_HELPER"
	const argsEnv = "QODER2API_TEST_MAIN_ARGS"
	if os.Getenv(helperEnv) == "1" {
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv(argsEnv)), &args); err != nil {
			t.Fatalf("decode helper args: %v", err)
		}
		os.Args = append([]string{"qodercli2api"}, args...)
		main()
		return
	}

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		diagnostic string
	}{
		{name: "help", args: []string{"-h"}, wantStatus: 0},
		{name: "unknown flag", args: []string{"-definitely-unknown"}, wantStatus: 2, diagnostic: "flag provided but not defined: -definitely-unknown"},
		{name: "malformed boolean", args: []string{"-v=not-bool"}, wantStatus: 2, diagnostic: `invalid boolean value "not-bool" for -v: parse error`},
		{name: "removed protocol mode", args: []string{"-protocol-mode=native"}, wantStatus: 2, diagnostic: "flag provided but not defined: -protocol-mode"},
		{name: "removed shadow capabilities", args: []string{"-shadow-capabilities=infer"}, wantStatus: 2, diagnostic: "flag provided but not defined: -shadow-capabilities"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedArgs, err := json.Marshal(tt.args)
			if err != nil {
				t.Fatalf("encode helper args: %v", err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainParseExitBehavior$")
			env := make([]string, 0, len(os.Environ())+2)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "QODER2API_") {
					env = append(env, entry)
				}
			}
			cmd.Env = append(env, helperEnv+"=1", argsEnv+"="+string(encodedArgs))
			output, runErr := cmd.CombinedOutput()
			status := 0
			if runErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("helper process error = %v", runErr)
				}
				status = exitErr.ExitCode()
			}
			if status != tt.wantStatus {
				t.Fatalf("exit status = %d, want %d; output:\n%s", status, tt.wantStatus, output)
			}
			text := string(output)
			if got := strings.Count(text, "Usage of qodercli2api:"); got != 1 {
				t.Fatalf("usage count = %d, want 1; output:\n%s", got, text)
			}
			if tt.diagnostic != "" {
				if got := strings.Count(text, tt.diagnostic); got != 1 {
					t.Fatalf("diagnostic %q count = %d, want 1; output:\n%s", tt.diagnostic, got, text)
				}
			}
		})
	}
}

func TestRunClosesContextBeforeProtocolBackendOnDeviceLoginExit(t *testing.T) {
	events := &appEventLog{}
	backend := &appTestBackend{onClose: func() { events.add("backend") }}
	services := &protocolServices{closeFn: backend.Close}
	protoCtx := &appTestProtocolContext{}
	var child context.Context
	protoCtx.onClose = func() {
		select {
		case <-child.Done():
			events.add("cancel")
		default:
			events.add("context-before-cancel")
		}
		events.add("context")
	}
	auth := &authManager{protoCtx: protoCtx}
	deps := appDeps{
		newProtocolServices: func(protocolHostDeps) (*protocolServices, error) {
			return services, nil
		},
		newAuthManager: func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error) {
			return auth, nil
		},
		deviceLogin: func(ctx context.Context, _ *authManager, _ io.Writer) error {
			child = ctx
			return nil
		},
	}
	cfg := appConfig{login: true}
	if err := run(context.Background(), cfg, deps, io.Discard, nil, nil); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	want := []string{"cancel", "context", "backend"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle events = %#v, want %#v", got, want)
	}
	if protoCtx.closeCount() != 1 || backend.closeCount() != 1 {
		t.Fatalf("close counts = context %d backend %d, want 1 each", protoCtx.closeCount(), backend.closeCount())
	}
}

func TestRunClosesProtocolBackendWhenAuthConstructionFails(t *testing.T) {
	initErr := errors.New("synthetic auth construction failure")
	backend := &appTestBackend{}
	services := &protocolServices{closeFn: backend.Close}
	deps := appDeps{
		newProtocolServices: func(protocolHostDeps) (*protocolServices, error) {
			return services, nil
		},
		newAuthManager: func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error) {
			return nil, initErr
		},
	}
	err := run(context.Background(), appConfig{}, deps, io.Discard, nil, nil)
	if !errors.Is(err, initErr) {
		t.Fatalf("run() error = %v, want auth construction failure", err)
	}
	if got := backend.closeCount(); got != 1 {
		t.Fatalf("backend Close() count = %d, want 1", got)
	}
}

func TestRunClosesAuthAndServicesExactlyOnceOnEveryExit(t *testing.T) {
	t.Run("device login", func(t *testing.T) {
		h := newAppRunHarness(t)
		h.cfg.login = true
		if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil); err != nil {
			t.Fatalf("run() error = %v", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("PAT login", func(t *testing.T) {
		h := newAppRunHarness(t)
		h.cfg.loginPAT = "synthetic-pat"
		if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil); err != nil {
			t.Fatalf("run() error = %v", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("credential load failure", func(t *testing.T) {
		h := newAppRunHarness(t)
		loadErr := errors.New("synthetic credential load failure")
		h.deps.loadCredentials = func(context.Context, *authManager) error { return loadErr }
		err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil)
		if !errors.Is(err, loadErr) {
			t.Fatalf("run() error = %v, want credential load failure", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("listen failure", func(t *testing.T) {
		h := newAppRunHarness(t)
		listenErr := errors.New("synthetic listen failure")
		h.deps.listenAndServe = func(*http.Server) error { return listenErr }
		err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil)
		if !errors.Is(err, listenErr) {
			t.Fatalf("run() error = %v, want listen failure", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("normal server closed", func(t *testing.T) {
		h := newAppRunHarness(t)
		if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil); err != nil {
			t.Fatalf("run() error = %v, want nil for http.ErrServerClosed", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("parent cancellation", func(t *testing.T) {
		h := newAppRunHarness(t)
		listenerStarted := make(chan struct{})
		listenerRelease := make(chan struct{})
		var releaseOnce sync.Once
		h.deps.listenAndServe = func(*http.Server) error {
			close(listenerStarted)
			<-listenerRelease
			return http.ErrServerClosed
		}
		h.deps.shutdown = func(context.Context, *http.Server) error {
			releaseOnce.Do(func() { close(listenerRelease) })
			return nil
		}
		parent, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- run(parent, h.cfg, h.deps, io.Discard, nil, nil) }()
		<-listenerStarted
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("run() error = %v, want nil after parent cancellation", err)
		}
		h.assertClosedOnce(t)
	})
}

func TestRunWaitsForRefreshAndShutdownGoroutinesBeforeClosingAuth(t *testing.T) {
	h := newAppRunHarness(t)
	events := &appEventLog{}
	h.protoCtx.onClose = func() { events.add("context") }
	h.backend.onClose = func() { events.add("backend") }

	refreshStarted := make(chan struct{})
	refreshRelease := make(chan struct{})
	refreshExited := make(chan struct{})
	var refreshCalls atomic.Int32
	h.deps.ensureFresh = func(ctx context.Context, _ *authManager) error {
		if refreshCalls.Add(1) == 1 {
			return nil
		}
		close(refreshStarted)
		<-ctx.Done()
		<-refreshRelease
		events.add("refresh-exit")
		close(refreshExited)
		return ctx.Err()
	}

	listenerStarted := make(chan struct{})
	listenerRelease := make(chan struct{})
	shutdownStarted := make(chan struct{})
	shutdownRelease := make(chan struct{})
	shutdownWindow := make(chan time.Duration, 1)
	h.deps.listenAndServe = func(*http.Server) error {
		close(listenerStarted)
		<-listenerRelease
		return http.ErrServerClosed
	}
	h.deps.shutdown = func(ctx context.Context, _ *http.Server) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			shutdownWindow <- 0
		} else {
			shutdownWindow <- time.Until(deadline)
		}
		close(listenerRelease)
		close(shutdownStarted)
		<-shutdownRelease
		events.add("shutdown-exit")
		return nil
	}

	parent, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(parent, h.cfg, h.deps, io.Discard, nil, nil) }()
	<-listenerStarted
	h.ticker.ch <- time.Now()
	<-refreshStarted
	cancel()
	<-shutdownStarted
	window := <-shutdownWindow
	if window <= 4*time.Second || window > 5*time.Second {
		t.Fatalf("shutdown timeout window = %v, want approximately 5s", window)
	}
	select {
	case err := <-done:
		t.Fatalf("run returned before blocked goroutines exited: %v", err)
	default:
	}
	if h.protoCtx.closeCount() != 0 || h.backend.closeCount() != 0 {
		t.Fatalf("cleanup began while background goroutines were blocked: context %d backend %d", h.protoCtx.closeCount(), h.backend.closeCount())
	}

	close(refreshRelease)
	<-refreshExited
	select {
	case err := <-done:
		t.Fatalf("run returned while shutdown goroutine was blocked: %v", err)
	default:
	}
	if h.protoCtx.closeCount() != 0 || h.backend.closeCount() != 0 {
		t.Fatalf("cleanup began before shutdown goroutine exited: context %d backend %d", h.protoCtx.closeCount(), h.backend.closeCount())
	}

	close(shutdownRelease)
	if err := <-done; err != nil {
		t.Fatalf("run() error = %v", err)
	}
	h.assertClosedOnce(t)
	want := []string{"refresh-exit", "shutdown-exit", "context", "backend"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle events = %#v, want %#v", got, want)
	}
	if got := h.ticker.stopped.Load(); got != 1 {
		t.Fatalf("refresh ticker Stop() count = %d, want 1", got)
	}
	if got := h.tickerDuration; got != 30*time.Minute {
		t.Fatalf("refresh ticker interval = %v, want 30m", got)
	}
}

func TestRunDrainsAdmittedHandlersBeforeClosingAuthAndRejectsNewArrivals(t *testing.T) {
	h := newAppRunHarness(t)
	events := &appEventLog{}
	h.protoCtx.onClose = func() { events.add("context") }
	h.backend.onClose = func() { events.add("backend") }

	handlerStarted := make(chan struct{})
	handlerRelease := make(chan struct{})
	handlerExited := make(chan struct{})
	var handlerCalls atomic.Int32
	h.deps.serverHandler = func(*server) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if call := handlerCalls.Add(1); call != 1 {
				t.Errorf("base handler call count = %d, want only admitted first request", call)
			}
			close(handlerStarted)
			<-handlerRelease
			events.add("handler-exit")
			close(handlerExited)
			w.WriteHeader(http.StatusNoContent)
		})
	}

	listenerStarted := make(chan struct{})
	listenerRelease := make(chan struct{})
	firstRequestDone := make(chan struct{})
	var gotServer *http.Server
	h.deps.listenAndServe = func(srv *http.Server) error {
		gotServer = srv
		go func() {
			srv.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://synthetic.test/active", nil))
			close(firstRequestDone)
		}()
		<-handlerStarted
		close(listenerStarted)
		<-listenerRelease
		return http.ErrServerClosed
	}
	shutdownStarted := make(chan struct{})
	h.deps.shutdown = func(context.Context, *http.Server) error {
		events.add("shutdown")
		close(listenerRelease)
		close(shutdownStarted)
		return nil
	}
	var closeCalls atomic.Int32
	h.deps.closeServer = func(*http.Server) error {
		closeCalls.Add(1)
		return nil
	}

	parent, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(parent, h.cfg, h.deps, io.Discard, nil, nil) }()
	<-listenerStarted
	cancel()
	<-shutdownStarted

	rejected := httptest.NewRecorder()
	gotServer.Handler.ServeHTTP(rejected, httptest.NewRequest(http.MethodGet, "http://synthetic.test/rejected", nil))
	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-shutdown request status = %d, want 503", rejected.Code)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("base handler call count = %d, want 1 after rejected arrival", got)
	}
	if got := closeCalls.Load(); got != 0 {
		t.Fatalf("forced server Close() calls = %d, want 0 after successful shutdown", got)
	}
	select {
	case err := <-done:
		t.Fatalf("run returned while admitted handler was blocked: %v", err)
	default:
	}
	if h.protoCtx.closeCount() != 0 || h.backend.closeCount() != 0 {
		t.Fatalf("resources closed while admitted handler was blocked: context %d backend %d", h.protoCtx.closeCount(), h.backend.closeCount())
	}

	close(handlerRelease)
	<-handlerExited
	<-firstRequestDone
	if err := <-done; err != nil {
		t.Fatalf("run() error = %v", err)
	}
	h.assertClosedOnce(t)
	want := []string{"shutdown", "handler-exit", "context", "backend"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle events = %#v, want %#v", got, want)
	}
}

func TestRunShutdownErrorForcesCloseThenDrainsHandlers(t *testing.T) {
	h := newAppRunHarness(t)
	events := &appEventLog{}
	h.protoCtx.onClose = func() { events.add("context") }
	h.backend.onClose = func() { events.add("backend") }

	handlerStarted := make(chan struct{})
	handlerRelease := make(chan struct{})
	handlerExited := make(chan struct{})
	h.deps.serverHandler = func(*server) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			close(handlerStarted)
			<-handlerRelease
			events.add("handler-exit")
			close(handlerExited)
		})
	}

	listenerRelease := make(chan struct{})
	firstRequestDone := make(chan struct{})
	h.deps.listenAndServe = func(srv *http.Server) error {
		go func() {
			srv.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://synthetic.test/active", nil))
			close(firstRequestDone)
		}()
		<-handlerStarted
		<-listenerRelease
		return http.ErrServerClosed
	}
	shutdownErr := errors.New("secret shutdown timeout detail")
	closeErr := errors.New("secret forced close detail")
	shutdownCalled := make(chan struct{})
	h.deps.shutdown = func(context.Context, *http.Server) error {
		events.add("shutdown")
		close(shutdownCalled)
		return shutdownErr
	}
	closeCalled := make(chan struct{})
	var closeCalls atomic.Int32
	h.deps.closeServer = func(*http.Server) error {
		closeCalls.Add(1)
		events.add("close-server")
		close(listenerRelease)
		close(closeCalled)
		return closeErr
	}

	parent, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(parent, h.cfg, h.deps, io.Discard, nil, nil) }()
	<-handlerStarted
	cancel()
	<-shutdownCalled
	<-closeCalled
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("forced server Close() calls = %d, want 1", got)
	}
	select {
	case err := <-done:
		t.Fatalf("run returned while force-closed handler was still blocked: %v", err)
	default:
	}
	if h.protoCtx.closeCount() != 0 || h.backend.closeCount() != 0 {
		t.Fatalf("resources closed before forced handler drain: context %d backend %d", h.protoCtx.closeCount(), h.backend.closeCount())
	}

	close(handlerRelease)
	<-handlerExited
	<-firstRequestDone
	err := <-done
	if !errors.Is(err, shutdownErr) || !errors.Is(err, closeErr) {
		t.Fatalf("run() error = %v, want shutdown and forced-close errors", err)
	}
	if strings.Contains(err.Error(), "secret shutdown timeout detail") || strings.Contains(err.Error(), "secret forced close detail") {
		t.Fatalf("run() exposed shutdown internals: %q", err)
	}
	h.assertClosedOnce(t)
	want := []string{"shutdown", "close-server", "handler-exit", "context", "backend"}
	if got := events.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle events = %#v, want %#v", got, want)
	}
}

func TestRunReturnsSafeJoinedCleanupErrorsWithoutLosingPrimary(t *testing.T) {
	t.Run("with primary error", func(t *testing.T) {
		h := newAppRunHarness(t)
		h.cfg.login = true
		primaryErr := errors.New("synthetic primary failure")
		authCloseErr := errors.New("secret auth close detail")
		backendCloseErr := errors.New("secret backend close detail")
		h.protoCtx.closeErr = authCloseErr
		h.backend.closeErr = backendCloseErr
		h.deps.deviceLogin = func(context.Context, *authManager, io.Writer) error { return primaryErr }

		err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil)
		for name, want := range map[string]error{"primary": primaryErr, "auth cleanup": authCloseErr, "backend cleanup": backendCloseErr} {
			if !errors.Is(err, want) {
				t.Fatalf("run() error = %v, missing %s error %v", err, name, want)
			}
		}
		if strings.Contains(err.Error(), "secret auth close detail") || strings.Contains(err.Error(), "secret backend close detail") {
			t.Fatalf("run() exposed cleanup internals: %q", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("without primary error", func(t *testing.T) {
		h := newAppRunHarness(t)
		h.cfg.login = true
		authCloseErr := errors.New("secret auth-only close detail")
		backendCloseErr := errors.New("secret backend-only close detail")
		h.protoCtx.closeErr = authCloseErr
		h.backend.closeErr = backendCloseErr

		err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil)
		if !errors.Is(err, authCloseErr) || !errors.Is(err, backendCloseErr) {
			t.Fatalf("run() error = %v, want both cleanup errors", err)
		}
		if strings.Contains(err.Error(), "secret auth-only close detail") || strings.Contains(err.Error(), "secret backend-only close detail") {
			t.Fatalf("run() exposed cleanup internals: %q", err)
		}
		h.assertClosedOnce(t)
	})

	t.Run("shutdown error", func(t *testing.T) {
		h := newAppRunHarness(t)
		shutdownErr := errors.New("secret shutdown detail")
		h.deps.shutdown = func(context.Context, *http.Server) error { return shutdownErr }
		err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, nil)
		if !errors.Is(err, shutdownErr) {
			t.Fatalf("run() error = %v, want shutdown cleanup error", err)
		}
		if strings.Contains(err.Error(), "secret shutdown detail") {
			t.Fatalf("run() exposed shutdown internals: %q", err)
		}
		h.assertClosedOnce(t)
	})
}

func TestRunCredentialLoadedLogOmitsIdentity(t *testing.T) {
	h := newAppRunHarness(t)
	h.auth.ui.UID = "SENTINEL-UID"
	h.auth.ui.OrgName = "SENTINEL-ORG"
	logs := &appEventLog{}
	always := func(format string, args ...any) {
		logs.add(fmt.Sprintf(format, args...))
	}

	if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, always); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	joined := strings.Join(logs.snapshot(), "\n")
	if strings.Contains(joined, h.auth.ui.UID) {
		t.Fatal("credential-loaded startup log contains UID")
	}
	if strings.Contains(joined, h.auth.ui.OrgName) {
		t.Fatal("credential-loaded startup log contains organization name")
	}
	if !strings.Contains(joined, "credentials loaded: expiry=") {
		t.Fatal("startup logs omit safe credential expiry status")
	}
	h.assertClosedOnce(t)
}

func TestRunStartupLogsNeverExposeAPIKeyMaterial(t *testing.T) {
	for _, secret := range apiKeySecretCases() {
		secret := secret
		t.Run(secret.name, func(t *testing.T) {
			h := newAppRunHarness(t)
			h.cfg.sk = secret.value
			var logsMu sync.Mutex
			var logs []string
			always := func(format string, args ...any) {
				logsMu.Lock()
				defer logsMu.Unlock()
				logs = append(logs, fmt.Sprintf(format, args...))
			}
			if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, always); err != nil {
				t.Fatalf("run() error = %v", err)
			}
			logsMu.Lock()
			joinedLogs := strings.Join(logs, "\n")
			logsMu.Unlock()
			assertNoAPIKeyLeak(t, joinedLogs, secret)
			if !strings.Contains(joinedLogs, "api key auth=enabled") {
				t.Fatalf("startup logs missing enabled API key status:\n%s", joinedLogs)
			}
			if strings.Contains(joinedLogs, "sk=") {
				t.Fatalf("startup logs still format an API key value:\n%s", joinedLogs)
			}
			h.assertClosedOnce(t)
		})
	}

	t.Run("disabled", func(t *testing.T) {
		h := newAppRunHarness(t)
		var logsMu sync.Mutex
		var logs []string
		always := func(format string, args ...any) {
			logsMu.Lock()
			defer logsMu.Unlock()
			logs = append(logs, fmt.Sprintf(format, args...))
		}
		if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, always); err != nil {
			t.Fatalf("run() error = %v", err)
		}
		logsMu.Lock()
		joinedLogs := strings.Join(logs, "\n")
		logsMu.Unlock()
		if !strings.Contains(joinedLogs, "api key auth=disabled") {
			t.Fatalf("startup logs missing disabled API key status:\n%s", joinedLogs)
		}
		if strings.Contains(joinedLogs, "sk=") {
			t.Fatalf("startup logs still format an API key value:\n%s", joinedLogs)
		}
		h.assertClosedOnce(t)
	})
}

func TestRunBuildsServerThroughNativeProtocolServices(t *testing.T) {
	h := newAppRunHarness(t)
	defaultCfg, err := parseAppConfig(nil, envLookup(nil), io.Discard)
	if err != nil {
		t.Fatalf("parseAppConfig(default) error = %v", err)
	}
	h.cfg = defaultCfg
	h.cfg.addr = ":synthetic"
	var gotHost protocolHostDeps
	var gotServer *http.Server
	h.deps.newProtocolServices = func(host protocolHostDeps) (*protocolServices, error) {
		gotHost = host
		return h.services, nil
	}
	h.deps.listenAndServe = func(srv *http.Server) error {
		gotServer = srv
		return http.ErrServerClosed
	}
	var logsMu sync.Mutex
	var logs []string
	always := func(format string, args ...any) {
		logsMu.Lock()
		defer logsMu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	if err := run(context.Background(), h.cfg, h.deps, io.Discard, nil, always); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if gotHost.Clock == nil || gotHost.Entropy == nil {
		t.Fatal("native protocol services did not receive production host dependencies")
	}
	if gotServer == nil || gotServer.Addr != ":synthetic" || gotServer.Handler == nil {
		t.Fatalf("constructed HTTP server = %#v, want injected protocol-backed server", gotServer)
	}
	logsMu.Lock()
	joinedLogs := strings.Join(logs, "\n")
	logsMu.Unlock()
	if strings.Contains(strings.ToLower(joinedLogs), "protocol mode") {
		t.Fatalf("native-only startup logged a protocol mode:\n%s", joinedLogs)
	}
	h.assertClosedOnce(t)
}

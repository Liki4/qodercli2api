package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type trackedString struct {
	value string
	set   bool
}

func (s *trackedString) String() string {
	if s == nil {
		return ""
	}
	return s.value
}

func (s *trackedString) Set(value string) error {
	s.value = value
	s.set = true
	return nil
}

type appConfig struct {
	region          string
	envPAT          string
	addr            string
	sk              string
	authDir         string
	inferEndpoint   string
	openapiEndpoint string
	webEndpoint     string
	modelMapJSON    string
	defaultModel    string
	oneMModel       string
	catalogPath     string
	dumpDir         string
	login           bool
	loginPAT        string
	verbose         bool
}

func lookupEnvOr(lookupEnv func(string) (string, bool), key, fallback string) string {
	if lookupEnv == nil {
		return fallback
	}
	if value, ok := lookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func parseAppConfig(args []string, lookupEnv func(string) (string, bool), output io.Writer) (appConfig, error) {
	if output == nil {
		output = io.Discard
	}
	fs := flag.NewFlagSet("qodercli2api", flag.ContinueOnError)
	fs.SetOutput(output)

	var cfg appConfig
	skFlag := trackedString{}
	regionFlag := trackedString{}
	patFlag := trackedString{}
	inferFlag, openapiFlag, webFlag := trackedString{}, trackedString{}, trackedString{}
	fs.Var(&regionFlag, "region", "region: global or cn (default global)")
	fs.StringVar(&cfg.addr, "addr", lookupEnvOr(lookupEnv, "QODER2API_ADDR", ":8377"), "listen address")
	fs.Var(&skFlag, "sk", "api key (sk-...) clients must present; empty disables auth check")
	fs.StringVar(&cfg.authDir, "auth-dir", lookupEnvOr(lookupEnv, "QODER2API_AUTH_DIR", ""), "qoder auth dir (contains user + machine_id)")
	fs.Var(&inferFlag, "endpoint", "inference endpoint override")
	fs.Var(&openapiFlag, "openapi-endpoint", "openapi endpoint override")
	fs.Var(&webFlag, "web-endpoint", "web base endpoint override")
	fs.StringVar(&cfg.modelMapJSON, "model-map", lookupEnvOr(lookupEnv, "QODER2API_MODEL_MAP", ""), `JSON map anthropic-model -> qoder key, e.g. {"claude-sonnet-4-5":"auto","*":"auto"}`)
	fs.StringVar(&cfg.defaultModel, "default-model", lookupEnvOr(lookupEnv, "QODER2API_DEFAULT_MODEL", "auto"), "fallback qoder model key")
	fs.StringVar(&cfg.oneMModel, "model-1m", lookupEnvOr(lookupEnv, "QODER2API_MODEL_1M", "ultimate"), "qoder model key used when client requests 1M context via [1m] suffix")
	fs.StringVar(&cfg.catalogPath, "catalog", lookupEnvOr(lookupEnv, "QODER2API_CATALOG", ""), "path to decrypted model catalog json (v6 or v7 schema; optional)")
	fs.StringVar(&cfg.dumpDir, "dump-dir", lookupEnvOr(lookupEnv, "QODER2API_DUMP_DIR", ""), "when set, dump plaintext bodies of failing upstream requests here for debugging")
	fs.BoolVar(&cfg.login, "login", false, "run device flow login then exit")
	fs.Var(&patFlag, "login-pat", "login with a personal access token then exit")
	fs.BoolVar(&cfg.verbose, "v", lookupEnvOr(lookupEnv, "QODER2API_LOG", "") == "debug", "verbose logging")

	if err := fs.Parse(args); err != nil {
		return appConfig{}, err
	}
	if skFlag.set {
		cfg.sk = skFlag.value
	} else {
		cfg.sk = lookupEnvOr(lookupEnv, "QODER2API_SK", "")
	}

	for _, endpoint := range []struct {
		flag   trackedString
		target *string
		env    string
	}{
		{inferFlag, &cfg.inferEndpoint, "QODER2API_INFER_ENDPOINT"}, {openapiFlag, &cfg.openapiEndpoint, "QODER2API_OPENAPI_ENDPOINT"}, {webFlag, &cfg.webEndpoint, "QODER2API_WEB_ENDPOINT"},
	} {
		*endpoint.target = lookupEnvOr(lookupEnv, endpoint.env, "")
		if endpoint.flag.set {
			*endpoint.target = endpoint.flag.value
		}
	}
	invalidConfig := func(err error) (appConfig, error) { fmt.Fprintln(output, err); return appConfig{}, err }
	if cfg.login && patFlag.set {
		return invalidConfig(fmt.Errorf("-login and -login-pat are mutually exclusive"))
	}
	if patFlag.set && strings.TrimSpace(patFlag.value) == "" {
		return invalidConfig(fmt.Errorf("-login-pat must not be empty"))
	}
	cfg.loginPAT = patFlag.value
	cfg.region = lookupEnvOr(lookupEnv, "QODER2API_REGION", lookupEnvOr(lookupEnv, "QODER_REGION", "global"))
	if regionFlag.set {
		cfg.region = regionFlag.value
	}
	profile, err := resolveRegion(cfg.region)
	if err != nil {
		return invalidConfig(err)
	}
	if err := cfg.resolveProfile(lookupEnv); err != nil {
		return invalidConfig(err)
	}
	if !cfg.login && !patFlag.set {
		cfg.envPAT = lookupEnvOr(lookupEnv, profile.patEnv, "")
	}
	return cfg, nil
}

type appTicker interface {
	C() <-chan time.Time
	Stop()
}

type realAppTicker struct {
	ticker *time.Ticker
}

func (t realAppTicker) C() <-chan time.Time { return t.ticker.C }
func (t realAppTicker) Stop()               { t.ticker.Stop() }

type appDeps struct {
	newProtocolServices       func(protocolHostDeps) (*protocolServices, error)
	newAuthManager            func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error)
	newAuthManagerWithOptions func(*protocolServices, string, string, string, string, func(string, ...any), authManagerOptions) (*authManager, error)
	deviceLogin               func(context.Context, *authManager, io.Writer) error
	patLogin                  func(context.Context, *authManager, string) error
	loadCredentials           func(context.Context, *authManager) error
	ensureFresh               func(context.Context, *authManager) error
	newTicker                 func(time.Duration) appTicker
	serverHandler             func(*server) http.Handler
	listenAndServe            func(*http.Server) error
	shutdown                  func(context.Context, *http.Server) error
	closeServer               func(*http.Server) error
}

func defaultAppDeps() appDeps {
	return appDeps{
		newProtocolServices:       newProtocolServices,
		newAuthManagerWithOptions: newAuthManagerWithOptions,
		deviceLogin: func(ctx context.Context, manager *authManager, output io.Writer) error {
			return manager.deviceLogin(ctx, output)
		},
		patLogin: patLogin,
		loadCredentials: func(ctx context.Context, manager *authManager) error {
			return manager.load(ctx)
		},
		ensureFresh: func(ctx context.Context, manager *authManager) error {
			return manager.ensureFresh(ctx)
		},
		newTicker: func(interval time.Duration) appTicker {
			return realAppTicker{ticker: time.NewTicker(interval)}
		},
		serverHandler: func(server *server) http.Handler {
			return server.handler()
		},
		listenAndServe: func(server *http.Server) error {
			return server.ListenAndServe()
		},
		shutdown: func(ctx context.Context, server *http.Server) error {
			return server.Shutdown(ctx)
		},
		closeServer: func(server *http.Server) error {
			return server.Close()
		},
	}
}

func (deps appDeps) withDefaults() appDeps {
	defaults := defaultAppDeps()
	if deps.newProtocolServices == nil {
		deps.newProtocolServices = defaults.newProtocolServices
	}
	if deps.newAuthManagerWithOptions == nil {
		deps.newAuthManagerWithOptions = defaults.newAuthManagerWithOptions
	}
	if deps.deviceLogin == nil {
		deps.deviceLogin = defaults.deviceLogin
	}
	if deps.patLogin == nil {
		deps.patLogin = defaults.patLogin
	}
	if deps.loadCredentials == nil {
		deps.loadCredentials = defaults.loadCredentials
	}
	if deps.ensureFresh == nil {
		deps.ensureFresh = defaults.ensureFresh
	}
	if deps.newTicker == nil {
		deps.newTicker = defaults.newTicker
	}
	if deps.serverHandler == nil {
		deps.serverHandler = defaults.serverHandler
	}
	if deps.listenAndServe == nil {
		deps.listenAndServe = defaults.listenAndServe
	}
	if deps.shutdown == nil {
		deps.shutdown = defaults.shutdown
	}
	if deps.closeServer == nil {
		deps.closeServer = defaults.closeServer
	}
	return deps
}

type appCleanupError struct {
	public string
	cause  error
}

func (e *appCleanupError) Error() string { return e.public }
func (e *appCleanupError) Unwrap() error { return e.cause }

func safeCleanupError(public string, err error) error {
	if err == nil {
		return nil
	}
	return &appCleanupError{public: public, cause: err}
}

type handlerAdmissionGate struct {
	mu      sync.Mutex
	closing bool
	active  sync.WaitGroup
}

func (g *handlerAdmissionGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		g.mu.Lock()
		if g.closing {
			g.mu.Unlock()
			http.Error(response, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		g.active.Add(1)
		g.mu.Unlock()
		defer g.active.Done()
		next.ServeHTTP(response, request)
	})
}

func (g *handlerAdmissionGate) closeAdmission() {
	g.mu.Lock()
	g.closing = true
	g.mu.Unlock()
}

func (g *handlerAdmissionGate) wait() {
	g.active.Wait()
}

func run(parent context.Context, cfg appConfig, deps appDeps, stdout io.Writer, debugf, always func(string, ...any)) (err error) {
	if err := cfg.resolveProfile(nil); err != nil {
		return err
	}
	if parent == nil {
		parent = context.Background()
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if debugf == nil {
		debugf = func(string, ...any) {}
	}
	if always == nil {
		always = func(string, ...any) {}
	}
	deps = deps.withDefaults()

	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	var services *protocolServices
	var auth *authManager
	var backgroundCleanupMu sync.Mutex
	var backgroundCleanupErrors []error
	recordBackgroundCleanupError := func(cleanupErr error) {
		if cleanupErr == nil {
			return
		}
		backgroundCleanupMu.Lock()
		backgroundCleanupErrors = append(backgroundCleanupErrors, cleanupErr)
		backgroundCleanupMu.Unlock()
	}
	defer func() {
		cancel()
		wg.Wait()
		backgroundCleanupMu.Lock()
		for _, cleanupErr := range backgroundCleanupErrors {
			err = errors.Join(err, cleanupErr)
		}
		backgroundCleanupMu.Unlock()
		if auth != nil {
			err = errors.Join(err, safeCleanupError("close auth context failed", auth.Close()))
		}
		if services != nil {
			err = errors.Join(err, safeCleanupError("close protocol services failed", services.Close(context.Background())))
		}
	}()

	host := productionProtocolHostDeps()
	services, initErr := deps.newProtocolServices(host)
	if initErr != nil {
		return fmt.Errorf("init protocol services: %w", initErr)
	}
	ephemeralPAT := cfg.envPAT != "" && !cfg.login && cfg.loginPAT == ""
	if deps.newAuthManager != nil && !ephemeralPAT {
		auth, initErr = deps.newAuthManager(services, cfg.authDir, cfg.openapiEndpoint, cfg.inferEndpoint, cfg.webEndpoint, always)
	} else {
		auth, initErr = deps.newAuthManagerWithOptions(services, cfg.authDir, cfg.openapiEndpoint, cfg.inferEndpoint, cfg.webEndpoint, always, authManagerOptions{ctx: ctx, region: cfg.region, ephemeral: ephemeralPAT})
	}
	if initErr != nil {
		return fmt.Errorf("init auth: %w", initErr)
	}

	if cfg.login {
		if loginErr := deps.deviceLogin(ctx, auth, stdout); loginErr != nil {
			return fmt.Errorf("login: %w", loginErr)
		}
		return nil
	}
	if cfg.loginPAT != "" {
		if loginErr := deps.patLogin(ctx, auth, cfg.loginPAT); loginErr != nil {
			return fmt.Errorf("pat login: %w", loginErr)
		}
		always("PAT login successful")
		return nil
	}

	if ephemeralPAT {
		if loginErr := deps.patLogin(ctx, auth, cfg.envPAT); loginErr != nil {
			return fmt.Errorf("environment PAT authentication: %w", loginErr)
		}
	} else if loadErr := deps.loadCredentials(ctx, auth); loadErr != nil {
		return fmt.Errorf("no usable credentials in %s (%w). Run with -login to authenticate first.", cfg.authDir, loadErr)
	}
	auth.mu.Lock()
	expireTime := int64(0)
	if auth.ui != nil {
		expireTime = auth.ui.ExpireTime
	}
	auth.mu.Unlock()
	always("credentials loaded: expiry=%s", time.Unix(expireTime, 0).Format(time.RFC3339))

	if refreshErr := deps.ensureFresh(ctx, auth); refreshErr != nil {
		always("initial token refresh failed: %v (will retry on demand)", refreshErr)
	}
	ticker := deps.newTicker(30 * time.Minute)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ticker == nil {
			return
		}
		defer ticker.Stop()
		ticks := ticker.C()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticks:
				if refreshErr := deps.ensureFresh(ctx, auth); refreshErr != nil {
					always("background refresh: %v", refreshErr)
				}
			}
		}
	}()

	mapping := map[string]string{}
	if cfg.modelMapJSON != "" {
		if mappingErr := json.Unmarshal([]byte(cfg.modelMapJSON), &mapping); mappingErr != nil {
			return fmt.Errorf("invalid -model-map JSON: %w", mappingErr)
		}
	}
	auth.mu.Lock()
	authFile := auth.authFile
	uid := ""
	if auth.ui != nil {
		uid = auth.ui.UID
	}
	auth.mu.Unlock()
	catalog := loadCatalog(ctx, services.modelCache, authFile, uid, cfg.catalogPath, debugf)
	resolver := newModelResolver(catalog, mapping, cfg.defaultModel, cfg.oneMModel)

	if cfg.sk == "" {
		always("api key auth=disabled")
	} else {
		always("api key auth=enabled")
	}

	handlerServer := &server{
		auth: auth, sk: cfg.sk, models: resolver,
		httpc: &http.Client{Timeout: 0}, logf: always, dumpDir: cfg.dumpDir,
	}
	if cfg.dumpDir != "" {
		always("failing-request dumps enabled: %s", cfg.dumpDir)
	}
	always("model keys available: %s", strings.Join(resolver.keys(), ", "))
	always("listening on %s", cfg.addr)
	admission := &handlerAdmissionGate{}
	httpServer := &http.Server{Addr: cfg.addr, Handler: admission.wrap(deps.serverHandler(handlerServer))}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		admission.closeAdmission()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		shutdownErr := deps.shutdown(shutdownCtx, httpServer)
		shutdownCancel()
		if shutdownErr != nil {
			recordBackgroundCleanupError(safeCleanupError("shutdown HTTP server failed", shutdownErr))
			if closeErr := deps.closeServer(httpServer); closeErr != nil {
				recordBackgroundCleanupError(safeCleanupError("force close HTTP server failed", closeErr))
			}
		}
		admission.wait()
	}()

	listenErr := deps.listenAndServe(httpServer)
	if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
		return fmt.Errorf("server: %w", listenErr)
	}
	return nil
}

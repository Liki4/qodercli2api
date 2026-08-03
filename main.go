package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		addr        = flag.String("addr", envOr("QODER2API_ADDR", ":8377"), "listen address")
		sk          = flag.String("sk", envOr("QODER2API_SK", ""), "api key (sk-...) clients must present; empty disables auth check")
		authDir     = flag.String("auth-dir", envOr("QODER2API_AUTH_DIR", filepath.Join(homeDir(), ".qoder", ".auth")), "qoder auth dir (contains user + machine_id)")
		inferEP     = flag.String("endpoint", envOr("QODER2API_INFER_ENDPOINT", ""), "inference endpoint override")
		openapiEP   = flag.String("openapi-endpoint", envOr("QODER2API_OPENAPI_ENDPOINT", ""), "openapi endpoint override")
		webEP       = flag.String("web-endpoint", envOr("QODER2API_WEB_ENDPOINT", ""), "web base endpoint override")
		modelMapJS  = flag.String("model-map", envOr("QODER2API_MODEL_MAP", ""), `JSON map anthropic-model -> qoder key, e.g. {"claude-sonnet-4-5":"auto","*":"auto"}`)
		defaultMdl  = flag.String("default-model", envOr("QODER2API_DEFAULT_MODEL", "auto"), "fallback qoder model key")
		oneMMdl     = flag.String("model-1m", envOr("QODER2API_MODEL_1M", "ultimate"), "qoder model key used when client requests 1M context via [1m] suffix")
		catalogPath = flag.String("catalog", envOr("QODER2API_CATALOG", ""), "path to decrypted catalog-v6 json (optional)")
		dumpDir     = flag.String("dump-dir", envOr("QODER2API_DUMP_DIR", ""), "when set, dump plaintext bodies of failing upstream requests here for debugging")
		login       = flag.Bool("login", false, "run device flow login then exit")
		loginPAT    = flag.String("login-pat", "", "login with a personal access token then exit")
		verbose     = flag.Bool("v", envOr("QODER2API_LOG", "") == "debug", "verbose logging")
	)
	flag.Parse()

	logf := func(format string, args ...any) {
		if *verbose {
			log.Printf(format, args...)
		}
	}
	always := func(format string, args ...any) { log.Printf(format, args...) }

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w, err := newWasmAuth(ctx)
	if err != nil {
		log.Fatalf("init wasm: %v", err)
	}
	am, err := newAuthManager(w, *authDir, *openapiEP, *inferEP, *webEP, always)
	if err != nil {
		log.Fatalf("init auth: %v", err)
	}

	if *login {
		if err := am.deviceLogin(ctx, os.Stdout); err != nil {
			log.Fatalf("login: %v", err)
		}
		return
	}
	if *loginPAT != "" {
		if err := patLogin(ctx, am, *loginPAT); err != nil {
			log.Fatalf("pat login: %v", err)
		}
		always("PAT login successful")
		return
	}

	if err := am.load(); err != nil {
		log.Fatalf("no usable credentials in %s (%v). Run with -login to authenticate first.", *authDir, err)
	}
	always("credentials loaded: uid=%s org=%s expiry=%s", am.ui.UID, am.ui.OrgName, time.Unix(am.ui.ExpireTime, 0).Format(time.RFC3339))

	if err := am.ensureFresh(ctx); err != nil {
		always("initial token refresh failed: %v (will retry on demand)", err)
	}
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := am.ensureFresh(ctx); err != nil {
					always("background refresh: %v", err)
				}
			}
		}
	}()

	mapping := map[string]string{}
	if *modelMapJS != "" {
		if err := json.Unmarshal([]byte(*modelMapJS), &mapping); err != nil {
			log.Fatalf("invalid -model-map JSON: %v", err)
		}
	}
	catalog := loadCatalog(w, am, *catalogPath, logf)
	resolver := newModelResolver(catalog, mapping, *defaultMdl, *oneMMdl)

	skPrint := *sk
	if skPrint == "" {
		always("WARNING: -sk not set, api key check is DISABLED")
	} else {
		if len(skPrint) > 8 {
			skPrint = skPrint[:6] + "..." + skPrint[len(skPrint)-2:]
		}
	}

	s := &server{
		auth: am, wasm: w, sk: *sk, models: resolver,
		httpc: &http.Client{Timeout: 0}, logf: always, dumpDir: *dumpDir,
	}
	if *dumpDir != "" {
		always("failing-request dumps enabled: %s", *dumpDir)
	}
	always("model keys available: %s", strings.Join(resolver.keys(), ", "))
	always("listening on %s (sk=%s)", *addr, skPrint)
	srv := &http.Server{Addr: *addr, Handler: s.handler()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "~"
	}
	return h
}

func (r *modelResolver) keys() []string {
	out := make([]string, 0, len(r.byKey))
	for k := range r.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadCatalog builds the model catalog: built-in defaults, optionally overridden
// by a decrypted catalog file or the CLI's own cache.
func loadCatalog(w *wasmAuth, am *authManager, catalogPath string, logf func(string, ...any)) []*modelConfig {
	catalog := builtinCatalog()
	var raw []byte
	var err error
	if catalogPath != "" {
		raw, err = os.ReadFile(catalogPath)
		if err != nil {
			logf("catalog read %s: %v", catalogPath, err)
		}
	} else {
		cachePath := filepath.Join(filepath.Dir(am.authFile), "..", ".models", am.ui.UID, "catalog-v6")
		cachePath = filepath.Clean(cachePath)
		if b, rerr := os.ReadFile(cachePath); rerr == nil {
			dec, derr := w.modelCacheDecrypt(strings.TrimSpace(string(b)), am.ui.UID)
			if derr == nil {
				raw = []byte(dec)
			} else {
				logf("catalog decrypt: %v", derr)
			}
		}
	}
	if len(raw) > 0 {
		var cat struct {
			Chat []*modelConfig `json:"chat"`
		}
		if json.Unmarshal(raw, &cat) == nil && len(cat.Chat) > 0 {
			merged := map[string]*modelConfig{}
			for _, mc := range catalog {
				merged[mc.Key] = mc
			}
			for _, mc := range cat.Chat {
				if mc.Format == "" {
					mc.Format = "openai"
				}
				if mc.Source == "" {
					mc.Source = "system"
				}
				mc.Enable = true
				merged[mc.Key] = mc
			}
			catalog = catalog[:0]
			for _, mc := range merged {
				catalog = append(catalog, mc)
			}
			logf("catalog merged: %d models", len(catalog))
		}
	}
	return catalog
}

func builtinCatalog() []*modelConfig {
	type spec struct {
		key, name string
		reasoning bool
		maxIn     int
	}
	specs := []spec{
		{"auto", "Auto", false, 180000},
		{"ultimate", "Ultimate", true, 1000000},
		{"performance", "Performance", false, 1000000},
		{"efficient", "Efficient", false, 180000},
		{"lite", "Lite", false, 180000},
		{"cmodel", "Cantus", true, 180000},
		{"qmodel_38max", "Qwen3.8-Max", true, 180000},
		{"qmodel_latest", "Qwen3.7-Max", false, 1000000},
		{"qmodel", "Qwen3.7-Plus", false, 1000000},
		{"kmodel_latest", "Kimi-K3", false, 180000},
		{"kmodel", "Kimi-K2.7-Code", false, 256000},
		{"gm51model", "GLM-5.2", true, 1000000},
		{"dmodel", "DeepSeek-V4-Pro", true, 1000000},
		{"dfmodel", "DeepSeek-V4-Flash", true, 1000000},
		{"mmodel", "MiniMax-M3", false, 1000000},
	}
	out := make([]*modelConfig, 0, len(specs))
	for _, sp := range specs {
		out = append(out, &modelConfig{
			Key: sp.key, Format: "openai", Source: "system", Enable: true,
			DisplayName: sp.name, IsVL: true, IsReasoning: sp.reasoning,
			PriceFactor: 1.0, MaxInputTokens: sp.maxIn,
		})
	}
	return out
}

// patLogin exchanges a personal access token for a device token.
func patLogin(ctx context.Context, am *authManager, pat string) error {
	body, _ := json.Marshal(map[string]string{"personal_token": pat})
	req, err := http.NewRequestWithContext(ctx, "POST", am.openapiBase+"/api/v1/jobToken/exchange", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qoder/"+cliVersion)
	resp, err := am.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("jobToken/exchange status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var r struct {
		Token         string `json:"token"`
		DeviceToken   string `json:"device_token"`
		AccessToken   string `json:"access_token"`
		RefreshToken  string `json:"refresh_token"`
		ExpiresAt     string `json:"expires_at"`
		ExpiresIn     int64  `json:"expires_in"`
		RefreshExpAt  string `json:"refresh_token_expires_at"`
		RefreshExpIn  int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	tok := r.Token
	if tok == "" {
		tok = r.DeviceToken
	}
	if tok == "" {
		tok = r.AccessToken
	}
	if tok == "" {
		return fmt.Errorf("exchange response missing token")
	}
	am.mu.Lock()
	am.ui = &userInfo{
		SecurityOAuthToken: tok, AccessToken: tok,
		RefreshToken: r.RefreshToken, ExpireTime: parseExpiry(r.ExpiresAt, r.ExpiresIn),
		RefreshTokenExpireTime: parseExpiry(r.RefreshExpAt, r.RefreshExpIn),
		PersonalAccessToken: pat,
		LoginMethod: "token", LoginTimestamp: time.Now().Unix(),
	}
	am.mu.Unlock()
	am.fetchUserInfo(ctx)
	am.mu.Lock()
	if am.ui.UID == "" {
		am.mu.Unlock()
		return fmt.Errorf("could not fetch user info after exchange")
	}
	if err := am.rebuildContextLocked(); err != nil {
		am.mu.Unlock()
		return err
	}
	am.mu.Unlock()
	return am.save()
}

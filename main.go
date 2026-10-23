package main

import (
	"context"
	"encoding/json"
	"errors"
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

func main() {
	cfg, err := parseAppConfig(os.Args[1:], os.LookupEnv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	debugf := func(format string, args ...any) {
		if cfg.verbose {
			log.Printf(format, args...)
		}
	}
	always := func(format string, args ...any) { log.Printf(format, args...) }
	if err := run(ctx, cfg, defaultAppDeps(), os.Stdout, debugf, always); err != nil {
		log.Fatal(err)
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

func catalogReadErrorDetail(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && pathErr != nil {
		return fmt.Sprintf("%s: %v", pathErr.Op, pathErr.Err)
	}
	return fmt.Sprintf("%T", err)
}

func catalogDecryptErrorDetail(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded.Error()
	}
	if protocolErr := protocolErrorFrom(err); protocolErr != nil {
		return fmt.Sprintf("kind=%s: %v", protocolErr.kind, protocolInternalError(err))
	}
	return fmt.Sprintf("%T", err)
}

// loadCatalog builds the model catalog: built-in defaults, optionally overridden
// by a plaintext catalog file or the CLI's encrypted model cache. The encrypted
// cache is read from the parent root of the selected auth file; catalog-v7 is
// preferred and catalog-v6 is only consulted when v7 is absent.
func loadCatalog(ctx context.Context, decryptor modelCacheDecryptor, authFile, uid, catalogPath string, logf func(string, ...any)) []*modelConfig {
	catalog := builtinCatalog()
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var raw []byte
	if catalogPath != "" {
		var err error
		raw, err = os.ReadFile(catalogPath)
		if err != nil {
			logf("catalog read %s: %v", catalogPath, err)
		}
	} else {
		raw = readCatalogCache(ctx, decryptor, modelsCacheRoot(authFile), uid, logf)
	}
	if len(raw) > 0 {
		models, ok := parseCatalog(raw)
		if !ok {
			logf("catalog parse failed: invalid JSON")
			return catalog
		}
		if len(models) == 0 {
			return catalog
		}
		merged := map[string]*modelConfig{}
		for _, mc := range catalog {
			merged[mc.Key] = mc
		}
		occupied := map[string]bool{}
		for _, entry := range models {
			mc := entry.mc
			// Default-scene (chat) entries always win, including over earlier
			// same-key chat entries (official loop: later duplicate wins).
			// Non-default entries only fill unoccupied keys, so they never
			// override chat entries, earlier non-default groups, or earlier
			// duplicates; they may still replace a same-key builtin.
			if !entry.chatGroup && occupied[mc.Key] {
				continue
			}
			merged[mc.Key] = mc
			occupied[mc.Key] = true
		}
		catalog = catalog[:0]
		for _, mc := range merged {
			catalog = append(catalog, mc)
		}
		logf("catalog merged: %d models", len(catalog))
	}
	return catalog
}

// modelsCacheRoot returns the .models root directory derived from the selected
// auth file's parent root. It is the single path helper for cache location.
func modelsCacheRoot(authFile string) string {
	return filepath.Clean(filepath.Join(filepath.Dir(authFile), "..", ".models"))
}

// readCatalogCache reads the encrypted model cache. catalog-v7 is preferred;
// catalog-v6 is only read when v7 is absent (os.ErrNotExist). Any v7 read,
// decrypt, or parse-level failure keeps the builtin fallback and never reads
// v6 to hide the failure.
func readCatalogCache(ctx context.Context, decryptor modelCacheDecryptor, root, uid string, logf func(string, ...any)) []byte {
	for i, name := range []string{"catalog-v7", "catalog-v6"} {
		cachePath := filepath.Join(root, uid, name)
		blob, err := os.ReadFile(cachePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if i == 0 {
					continue
				}
				return nil
			}
			logf("catalog cache read failed: %s", catalogReadErrorDetail(err))
			return nil
		}
		if decryptor == nil {
			logf("catalog decrypt failed: decryptor unavailable")
			return nil
		}
		raw, err := decryptor.Decrypt(ctx, strings.TrimSpace(string(blob)), uid)
		if err != nil {
			logf("catalog decrypt failed: %s", catalogDecryptErrorDetail(err))
			return nil
		}
		if len(raw) == 0 {
			logf("catalog decrypt failed: empty cache payload")
			return nil
		}
		if _, ok := parseCatalog(raw); !ok {
			logf("catalog parse failed: invalid JSON")
			return nil
		}
		return raw
	}
	return nil
}

// supportedCatalogScenes lists the only catalog groups the resolver consumes,
// in merge order (chat first). Any other top-level scene is ignored.
var supportedCatalogScenes = []string{"chat", "byok_enterprise", "byok_teams"}

// catalogEntry is the private cache-entry parser mirroring the official 1.1.74
// CLI decoder: key=s.key ?? s.model_key, display_name=s.display_name ?? s.name,
// and enable defaults to true unless explicitly false or numeric zero. Key and
// display_name use JS nullish semantics: only a missing or null field falls
// back to the alias; an explicitly empty string stays empty (an empty key is
// then skipped instead of using model_key).
type catalogEntry struct {
	Key            *string `json:"key"`
	ModelKey       *string `json:"model_key"`
	DisplayName    *string `json:"display_name"`
	Name           *string `json:"name"`
	Format         string  `json:"format"`
	Source         string  `json:"source"`
	Enable         *any    `json:"enable"`
	IsVL           bool    `json:"is_vl"`
	IsReasoning    bool    `json:"is_reasoning"`
	IsDefault      bool    `json:"is_default"`
	PriceFactor    float64 `json:"price_factor"`
	MaxInputTokens int     `json:"max_input_tokens"`
	URL            string  `json:"url"`

	ContextConfig map[string]struct {
		TokenCount int `json:"token_count"`
	} `json:"context_config"`
}

// catalogGroupEntry pairs a parsed entry with the group it came from so
// cross-group collision handling can prefer default-scene (chat) entries.
type catalogGroupEntry struct {
	mc        *modelConfig
	chatGroup bool
}

// parseCatalog converts raw cache/override JSON into model entries. The
// top-level object maps scene names to arrays of entries; only the supported
// scenes are consumed in fixed order, and parsing one malformed entry or group
// never discards valid entries from other groups. A payload without any valid
// supported scene array (null, non-object, object-valued groups, wrapper
// documents, unsupported-scene-only documents) is rejected as a non-catalog
// shape so callers keep the builtin fallback.
func parseCatalog(raw []byte) ([]catalogGroupEntry, bool) {
	var groups map[string]json.RawMessage
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, false
	}
	if groups == nil {
		return nil, false
	}
	supportedPresent := false
	var models []catalogGroupEntry
	for _, name := range supportedCatalogScenes {
		group, ok := groups[name]
		if !ok || len(group) == 0 {
			continue
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(group, &entries); err != nil || entries == nil {
			// A supported scene present but not an array (including JSON
			// null, which unmarshals into a nil slice without error) is
			// ignored, matching the single-malformed-group resilience rule;
			// acceptance requires at least one valid supported scene array.
			continue
		}
		supportedPresent = true
		for i := range entries {
			entry := entries[i]
			if len(entry) == 0 || string(entry) == "null" {
				continue
			}
			mc, entryErr := parseCatalogEntry(entry)
			if entryErr != nil || mc == nil {
				continue
			}
			models = append(models, catalogGroupEntry{mc: mc, chatGroup: name == "chat"})
		}
	}
	if !supportedPresent {
		return nil, false
	}
	return models, true
}

func parseCatalogEntry(entry json.RawMessage) (*modelConfig, error) {
	var e catalogEntry
	if err := json.Unmarshal(entry, &e); err != nil {
		return nil, err
	}
	key := ""
	if e.Key != nil {
		key = *e.Key
	} else if e.ModelKey != nil {
		key = *e.ModelKey
	}
	if strings.TrimSpace(key) == "" {
		return nil, nil
	}
	displayName := ""
	if e.DisplayName != nil {
		displayName = *e.DisplayName
	} else if e.Name != nil {
		displayName = *e.Name
	}
	mc := &modelConfig{
		Key:            key,
		DisplayName:    displayName,
		Format:         e.Format,
		Source:         e.Source,
		IsVL:           e.IsVL,
		IsReasoning:    e.IsReasoning,
		IsDefault:      e.IsDefault,
		PriceFactor:    e.PriceFactor,
		MaxInputTokens: e.MaxInputTokens,
		URL:            e.URL,
		ContextConfig:  e.ContextConfig,
	}
	if mc.Format == "" {
		mc.Format = "openai"
	}
	if mc.Source == "" {
		mc.Source = "system"
	}
	mc.Enable = true
	if e.Enable != nil {
		switch v := (*e.Enable).(type) {
		case bool:
			mc.Enable = v
		case float64:
			mc.Enable = v != 0
		}
	}
	for _, tier := range mc.ContextConfig {
		if tier.TokenCount > mc.MaxInputTokens {
			mc.MaxInputTokens = tier.TokenCount
		}
	}
	return mc, nil
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
		{"cmodel", "Cantus", true, 1000000},
		{"qmodel_38max", "Qwen3.8-Max", true, 1000000},
		{"qmodel_latest", "Qwen3.7-Max", false, 1000000},
		{"qmodel", "Qwen3.7-Plus", false, 1000000},
		{"kmodel_latest", "Kimi-K3", false, 1000000},
		{"kmodel", "Kimi-K2.7-Code", false, 256000},
		{"gmodel", "GLM-5.3", true, 1000000},
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
	if err := am.credentialRequestPreflight(ctx); err != nil {
		return err
	}
	candidate, err := am.requestPATCandidate(ctx, pat, nil)
	if err != nil {
		return err
	}
	am.mu.Lock()
	defer am.mu.Unlock()
	if err := am.closedStateError(); err != nil {
		return err
	}
	return am.commitLoginCandidateLocked(ctx, candidate)
}

func (am *authManager) requestPATCandidate(ctx context.Context, pat string, previous *userInfo, held ...*credentialTxn) (*userInfo, error) {
	if strings.TrimSpace(pat) == "" {
		return nil, fmt.Errorf("personal access token is unavailable")
	}
	body, _ := json.Marshal(machineIdentityRequestFields(am.machineID, "personal_token", pat))
	req, err := http.NewRequestWithContext(ctx, "POST", am.openapiBase+"/api/v1/jobToken/exchange", strings.NewReader(string(body)))
	if err != nil {
		return nil, safeAuthRequestError("PAT exchange", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", qoderUserAgent())
	resp, err := am.doAuthRequest(req)
	if err != nil {
		return nil, safeAuthRequestError("PAT exchange", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jobToken/exchange status %d", resp.StatusCode)
	}
	var r struct {
		Token        string `json:"token"`
		DeviceToken  string `json:"device_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshExpAt string `json:"refresh_token_expires_at"`
		RefreshExpIn int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid PAT exchange response")
	}
	tok := r.Token
	if tok == "" {
		tok = r.DeviceToken
	}
	if tok == "" {
		tok = r.AccessToken
	}
	if tok == "" {
		return nil, fmt.Errorf("exchange response missing token")
	}
	candidate := cloneUserInfo(previous)
	if candidate == nil {
		candidate = &userInfo{LoginMethod: "token", LoginTimestamp: time.Now().Unix()}
	}
	candidate.SecurityOAuthToken, candidate.AccessToken, candidate.PersonalAccessToken = tok, tok, pat
	candidate.ExpireTime = parseExpiry(r.ExpiresAt, r.ExpiresIn)
	if r.RefreshToken != "" {
		candidate.RefreshToken = r.RefreshToken
	}
	if expiry := parseExpiry(r.RefreshExpAt, r.RefreshExpIn); expiry != 0 {
		candidate.RefreshTokenExpireTime = expiry
	}
	candidate.EncryptUserInfo, candidate.Key = "", ""
	profile, err := am.requestUserInfo(ctx, tok, held...)
	if err != nil {
		if isAuthConflict(err) {
			return nil, err
		}
		return nil, fmt.Errorf("could not fetch user info after exchange")
	}
	if profile.UID == "" {
		return nil, fmt.Errorf("could not fetch user info after exchange")
	}
	applyAuthUserInfoProfile(candidate, profile)
	return candidate, nil
}

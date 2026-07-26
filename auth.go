package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	prodClientID    = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	nonProdClientID = "e93fe488-5778-4c35-a6fc-0f54ed7b3139"
	defaultOpenapi  = "https://openapi.qoder.sh"
	defaultInfer    = "https://api2.qoder.sh"
	defaultBase     = "https://qoder.com"
	refreshSkewSec  = 3600
	cliVersion      = "1.1.5"
)

type userInfo struct {
	UID                    string   `json:"uid"`
	Name                   string   `json:"name,omitempty"`
	Email                  string   `json:"email,omitempty"`
	AvatarURL              string   `json:"avatar_url,omitempty"`
	OrgID                  string   `json:"organization_id,omitempty"`
	OrgName                string   `json:"organization_name,omitempty"`
	OrgTags                []string `json:"organization_tags,omitempty"`
	DataPolicyAgreed       bool     `json:"data_policy_agreed"`
	IsDataPolicyModifiable bool     `json:"is_data_policy_modifiable,omitempty"`
	SecurityOAuthToken     string   `json:"security_oauth_token"`
	AccessToken            string   `json:"access_token"`
	RefreshToken           string   `json:"refresh_token"`
	ExpireTime             int64    `json:"expire_time"`
	RefreshTokenExpireTime int64    `json:"refresh_token_expire_time,omitempty"`
	LoginMethod            string   `json:"login_method"`
	LoginTimestamp         int64    `json:"login_timestamp"`
	EncryptUserInfo        string   `json:"encrypt_user_info"`
	Key                    string   `json:"key"`
	PersonalAccessToken    string   `json:"personal_access_token,omitempty"`
}

type authManager struct {
	mu          sync.Mutex
	wasm        *wasmAuth
	authFile    string
	machineID   string
	openapiBase string
	inferBase   string
	webBase     string
	httpc       *http.Client
	ui          *userInfo
	ctx         uint32
	logf        func(string, ...any)
}

func newAuthManager(w *wasmAuth, authDir, openapiBase, inferBase, webBase string, logf func(string, ...any)) (*authManager, error) {
	mid, err := loadOrCreateMachineID(authDir)
	if err != nil {
		return nil, err
	}
	if openapiBase == "" {
		openapiBase = defaultOpenapi
	}
	if inferBase == "" {
		inferBase = defaultInfer
	}
	if webBase == "" {
		webBase = defaultBase
	}
	return &authManager{
		wasm: w, authFile: filepath.Join(authDir, "user"), machineID: mid,
		openapiBase: openapiBase, inferBase: inferBase, webBase: webBase,
		httpc: &http.Client{Timeout: 30 * time.Second}, logf: logf,
	}, nil
}

func loadOrCreateMachineID(dir string) (string, error) {
	p := filepath.Join(dir, "machine_id")
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	mid := newUUID()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(mid), 0o600); err != nil {
		return "", err
	}
	return mid, nil
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (a *authManager) loggedIn() bool { return a.ui != nil && a.ui.SecurityOAuthToken != "" }

func (a *authManager) load() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := os.ReadFile(a.authFile)
	if err != nil {
		return err
	}
	s := strings.TrimSpace(string(b))
	var plain []byte
	if strings.HasPrefix(s, "{") {
		plain = []byte(s)
	} else {
		key := a.machineID
		if len(key) > 16 {
			key = key[:16]
		}
		dec, err := a.wasm.credentialDecrypt(s, key)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", a.authFile, err)
		}
		plain = []byte(dec)
	}
	var ui userInfo
	if err := json.Unmarshal(plain, &ui); err != nil {
		return err
	}
	a.ui = &ui
	return a.rebuildContextLocked()
}

func (a *authManager) save() error {
	if a.ui == nil {
		return nil
	}
	plain, err := json.Marshal(a.ui)
	if err != nil {
		return err
	}
	key := a.machineID
	if len(key) > 16 {
		key = key[:16]
	}
	enc, err := a.wasm.credentialEncrypt(string(plain), key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.authFile), 0o755); err != nil {
		return err
	}
	tmp := a.authFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.authFile)
}

func (a *authManager) runtimeFieldsInput() string {
	m := map[string]any{
		"uid":                a.ui.UID,
		"organization_id":    a.ui.OrgID,
		"organization_tags":  a.ui.OrgTags,
		"data_policy_agreed": a.ui.DataPolicyAgreed,
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (a *authManager) authUserInfoJSON() string {
	m := map[string]any{
		"uid":                a.ui.UID,
		"encrypt_user_info":  a.ui.EncryptUserInfo,
		"key":                a.ui.Key,
		"organization_id":    a.ui.OrgID,
		"organization_tags":  a.ui.OrgTags,
		"data_policy_agreed": a.ui.DataPolicyAgreed,
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func sceneJSON() string {
	return `{"client_type":"5","business_product":"cli","business_type":"agent","scene":"assistant"}`
}

func (a *authManager) rebuildContextLocked() error {
	if a.ui.EncryptUserInfo == "" || a.ui.Key == "" {
		out, err := a.wasm.genRuntimeAuthFields(a.runtimeFieldsInput())
		if err != nil {
			return fmt.Errorf("generate_runtime_auth_fields: %w", err)
		}
		var rf struct {
			EncryptUserInfo string `json:"encrypt_user_info"`
			Key             string `json:"key"`
		}
		if err := json.Unmarshal([]byte(out), &rf); err != nil {
			return err
		}
		a.ui.EncryptUserInfo, a.ui.Key = rf.EncryptUserInfo, rf.Key
	}
	ctx, err := a.wasm.newContext(a.machineID, cliVersion, a.authUserInfoJSON(), sceneJSON())
	if err != nil {
		return err
	}
	a.ctx = ctx
	return nil
}

func (a *authManager) inferEndpoint() string { return a.inferBase }
func (a *authManager) wasmCtx() uint32       { return a.ctx }

// ensureFresh refreshes the device token when it expires within refreshSkewSec.
func (a *authManager) ensureFresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ui == nil {
		return fmt.Errorf("not authenticated")
	}
	now := time.Now().Unix()
	if a.ui.ExpireTime == 0 || a.ui.ExpireTime-refreshSkewSec >= now {
		return nil
	}
	if a.ui.RefreshTokenExpireTime != 0 && now > a.ui.RefreshTokenExpireTime {
		return fmt.Errorf("refresh token expired; please re-login")
	}
	return a.refreshLocked(ctx)
}

func (a *authManager) forceRefresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refreshLocked(ctx)
}

func (a *authManager) refreshLocked(ctx context.Context) error {
	if a.ui.RefreshToken == "" {
		return fmt.Errorf("no refresh_token")
	}
	body, _ := json.Marshal(map[string]string{"refresh_token": a.ui.RefreshToken})
	req, err := http.NewRequestWithContext(ctx, "POST", a.openapiBase+"/api/v1/deviceToken/refresh", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qoder/"+cliVersion)
	resp, err := a.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("deviceToken/refresh status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var r struct {
		DeviceToken   string `json:"device_token"`
		Token         string `json:"token"`
		RefreshToken  string `json:"refresh_token"`
		ExpiresAt     string `json:"expires_at"`
		ExpiresIn     int64  `json:"expires_in"`
		RefreshExpAt  string `json:"refresh_token_expires_at"`
		RefreshExpIn  int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	tok := r.DeviceToken
	if tok == "" {
		tok = r.Token
	}
	if tok == "" {
		return fmt.Errorf("refresh response missing token")
	}
	a.ui.SecurityOAuthToken, a.ui.AccessToken = tok, tok
	if r.RefreshToken != "" {
		a.ui.RefreshToken = r.RefreshToken
	}
	a.ui.ExpireTime = parseExpiry(r.ExpiresAt, r.ExpiresIn)
	if v := parseExpiry(r.RefreshExpAt, r.RefreshExpIn); v != 0 {
		a.ui.RefreshTokenExpireTime = v
	}
	out, err := a.wasm.genRuntimeAuthFields(a.runtimeFieldsInput())
	if err == nil {
		var rf struct {
			EncryptUserInfo string `json:"encrypt_user_info"`
			Key             string `json:"key"`
		}
		if json.Unmarshal([]byte(out), &rf) == nil && rf.Key != "" {
			a.ui.EncryptUserInfo, a.ui.Key = rf.EncryptUserInfo, rf.Key
		}
	}
	if err := a.rebuildContextLocked(); err != nil {
		return err
	}
	if err := a.save(); err != nil {
		a.logf("save credential: %v", err)
	}
	a.logf("device token refreshed, new expiry %d", a.ui.ExpireTime)
	return nil
}

func parseExpiry(iso string, inSec int64) int64 {
	if iso != "" {
		if t, err := time.Parse(time.RFC3339, iso); err == nil {
			return t.Unix()
		}
	}
	if inSec != 0 {
		return time.Now().Unix() + inSec
	}
	return 0
}

// ---- device flow login ----

func pkcePair() (verifier, challenge string) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	n := 43 + int(randBytes(1)[0]%86)
	rb := randBytes(n)
	vb := make([]byte, n)
	for i := range vb {
		vb[i] = charset[int(rb[i])%len(charset)]
	}
	verifier = string(vb)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// deviceLogin runs the full device authorization flow and persists credentials.
func (a *authManager) deviceLogin(ctx context.Context, out io.Writer) error {
	verifier, challenge := pkcePair()
	nonce := newUUID()
	authURL := fmt.Sprintf("%s/device/selectAccounts?challenge=%s&challenge_method=S256&nonce=%s&machine_id=%s&client_id=%s",
		a.webBase, challenge, nonce, a.machineID, prodClientID)
	fmt.Fprintf(out, "\nOpen this URL in your browser to authorize:\n\n  %s\n\nWaiting for authorization (up to 5 minutes)...\n", authURL)
	pollURL := fmt.Sprintf("%s/api/v1/deviceToken/poll?nonce=%s&verifier=%s&challenge_method=S256",
		a.openapiBase, nonce, verifier)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := a.httpc.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("poll status %d: %s", resp.StatusCode, truncate(string(raw), 200))
		}
		var dr struct {
			Token                string `json:"token"`
			RefreshToken         string `json:"refresh_token"`
			ExpiresAt            string `json:"expires_at"`
			ExpiresIn            int64  `json:"expires_in"`
			RefreshExpiresAt     string `json:"refresh_token_expires_at"`
			RefreshExpiresIn     int64  `json:"refresh_token_expires_in"`
			UserID               string `json:"user_id"`
			UserName             string `json:"user_name"`
		}
		if err := json.Unmarshal(raw, &dr); err != nil {
			return err
		}
		if dr.Token == "" {
			return fmt.Errorf("poll response missing token: %s", truncate(string(raw), 200))
		}
		a.mu.Lock()
		a.ui = &userInfo{
			UID: dr.UserID, Name: dr.UserName,
			SecurityOAuthToken: dr.Token, AccessToken: dr.Token,
			RefreshToken: dr.RefreshToken, ExpireTime: parseExpiry(dr.ExpiresAt, dr.ExpiresIn),
			RefreshTokenExpireTime: parseExpiry(dr.RefreshExpiresAt, dr.RefreshExpiresIn),
			LoginMethod: "browser", LoginTimestamp: time.Now().Unix(),
		}
		if err := a.rebuildContextLocked(); err != nil {
			a.mu.Unlock()
			return err
		}
		a.mu.Unlock()
		if err := a.save(); err != nil {
			return fmt.Errorf("save: %w", err)
		}
		// best-effort profile enrichment
		a.fetchUserInfo(ctx)
		fmt.Fprintf(out, "Login successful. uid=%s name=%s\n", a.ui.UID, a.ui.Name)
		return nil
	}
	return fmt.Errorf("device flow timed out after 5 minutes")
}

func (a *authManager) fetchUserInfo(ctx context.Context) {
	a.mu.Lock()
	tok := a.ui.SecurityOAuthToken
	a.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, "GET", a.openapiBase+"/api/v1/userinfo", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "qoder/"+cliVersion)
	resp, err := a.httpc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var p struct {
		UID     string   `json:"uid"`
		Name    string   `json:"name"`
		Email   string   `json:"email"`
		OrgID   string   `json:"organization_id"`
		OrgName string   `json:"organization_name"`
		OrgTags []string `json:"organization_tags"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.Email != "" {
		a.ui.Email = p.Email
	}
	if p.Name != "" {
		a.ui.Name = p.Name
	}
	if p.OrgID != "" {
		a.ui.OrgID, a.ui.OrgName = p.OrgID, p.OrgName
	}
	if len(p.OrgTags) > 0 {
		a.ui.OrgTags = p.OrgTags
	}
	a.rebuildContextLocked()
	a.save()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

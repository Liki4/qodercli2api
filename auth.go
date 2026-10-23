package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	prodClientID                = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	nonProdClientID             = "e93fe488-5778-4c35-a6fc-0f54ed7b3139"
	defaultOpenapi              = "https://openapi.qoder.sh"
	defaultInfer                = "https://api2.qoder.sh"
	defaultBase                 = "https://qoder.com"
	refreshSkewSec              = 3600
	defaultRefreshCommitTimeout = 30 * time.Second
	credentialPersistRetryDelay = 30 * time.Second
)

type userInfo struct {
	extra                  map[string]json.RawMessage
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

// Keep unknown official fields byte-exact at the JSON value level (including large
// numbers and nulls). Known fields are always controlled by the typed structure.
var userInfoJSONKeys = []string{"uid", "name", "email", "avatar_url", "organization_id", "organization_name", "organization_tags", "data_policy_agreed", "is_data_policy_modifiable", "security_oauth_token", "access_token", "refresh_token", "expire_time", "refresh_token_expire_time", "login_method", "login_timestamp", "encrypt_user_info", "key", "personal_access_token"}

func (u *userInfo) UnmarshalJSON(data []byte) error {
	type plainUserInfo userInfo
	var known plainUserInfo
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	var extra map[string]json.RawMessage
	if err := json.Unmarshal(data, &extra); err != nil {
		return err
	}
	for key := range extra {
		for _, knownKey := range userInfoJSONKeys {
			if strings.EqualFold(key, knownKey) {
				delete(extra, key)
				break
			}
		}
	}
	*u = userInfo(known)
	if len(extra) > 0 {
		u.extra = extra
	}
	return nil
}

func (u userInfo) MarshalJSON() ([]byte, error) {
	type plainUserInfo userInfo
	known, err := json.Marshal(plainUserInfo(u))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(known, &fields); err != nil {
		return nil, err
	}
	for key, value := range u.extra {
		isKnown := false
		for _, knownKey := range userInfoJSONKeys {
			if strings.EqualFold(key, knownKey) {
				isKnown = true
				break
			}
		}
		if !isKnown {
			fields[key] = value
		}
	}
	return json.Marshal(fields)
}

type authManager struct {
	mu       sync.Mutex
	protocol *protocolServices
	store    *authStore

	ctxMu     sync.RWMutex
	protoCtx  protocolContext
	closed    bool
	closeOnce sync.Once
	closeErr  error

	authFile                 string
	machineID                string
	openapiBase              string
	inferBase                string
	webBase                  string
	httpc                    *http.Client
	ui                       *userInfo
	credentialDirty          bool
	credentialPersistRetryAt time.Time
	commitTimeout            time.Duration
	pollInterval             time.Duration
	pollTimeout              time.Duration
	logf                     func(string, ...any)
}

type authManagerOptions struct {
	ctx          context.Context
	region       string
	ephemeral    bool
	leaseOptions credentialLeaseOptions
}

func newAuthManager(services *protocolServices, authDir, openapiBase, inferBase, webBase string, logf func(string, ...any)) (*authManager, error) {
	return newAuthManagerWithOptions(services, authDir, openapiBase, inferBase, webBase, logf, authManagerOptions{region: "global"})
}

func newAuthManagerWithOptions(services *protocolServices, authDir, openapiBase, inferBase, webBase string, logf func(string, ...any), options authManagerOptions) (_ *authManager, err error) {
	if services == nil || services.credentials == nil || services.runtimeFields == nil || services.contextFactory == nil {
		return nil, newProtocolError(
			protocolInvalidInput,
			"Protocol services are unavailable",
			fmt.Errorf("auth manager requires credentials, runtime fields, and context factory capabilities"),
		)
	}
	cfg := appConfig{region: options.region, authDir: authDir, openapiEndpoint: openapiBase, inferEndpoint: inferBase, webEndpoint: webBase}
	if err := cfg.resolveProfile(nil); err != nil {
		return nil, err
	}
	authDir, openapiBase, inferBase, webBase = cfg.authDir, cfg.openapiEndpoint, cfg.inferEndpoint, cfg.webEndpoint
	ctx := options.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store := &authStore{dir: authDir, ephemeral: options.ephemeral, leaseOptions: options.leaseOptions, expected: authBinding{Version: 1, Region: cfg.region, Issuer: openapiBase, ClientID: prodClientID}}
	if _, err := store.readBinding(); err != nil {
		return nil, err
	}
	mid := newUUID()
	if !options.ephemeral {
		if _, err := ensureAuthDirectory(authDir); err != nil {
			return nil, err
		}
		var lease *credentialLease
		lease, err = acquireCredentialLease(ctx, authDir, store.leaseOptions)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, lease.release()) }()
		mid, err = machineIDUnderLease(authDir, lease)
		if err != nil {
			return nil, err
		}
	}
	store.machineID = mid
	store.baseline, err = store.snapshot()
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	manager := &authManager{
		protocol: services, store: store, authFile: filepath.Join(authDir, "user"), machineID: mid,
		openapiBase: openapiBase, inferBase: inferBase, webBase: webBase,
		httpc: &http.Client{Timeout: 30 * time.Second}, logf: logf,
	}
	return manager, nil
}

func machineCredentialKey(machineID string) string {
	if len(machineID) > 16 {
		return machineID[:16]
	}
	return machineID
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func authManagerClosedError() error {
	return newProtocolError(
		protocolContextClosed,
		"Qoder protocol context is closed",
		fmt.Errorf("auth manager is closed"),
	)
}

func (a *authManager) closedStateError() error {
	a.ctxMu.RLock()
	defer a.ctxMu.RUnlock()
	if a.closed {
		return authManagerClosedError()
	}
	return nil
}

func (a *authManager) loggedIn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closedStateError() == nil && a.ui != nil && a.ui.SecurityOAuthToken != ""
}

func (a *authManager) safeLogf(format string, args ...any) {
	if a.logf != nil {
		a.logf(format, args...)
	}
}

func (a *authManager) replaceContext(next protocolContext) error {
	if next == nil {
		return newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("replacement protocol context is nil"),
		)
	}

	a.ctxMu.Lock()
	if a.closed {
		a.ctxMu.Unlock()
		if err := next.Close(); err != nil {
			a.safeLogf("close rejected protocol context failed")
		}
		return authManagerClosedError()
	}
	old := a.protoCtx
	a.protoCtx = next
	a.ctxMu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			a.safeLogf("close replaced protocol context failed")
		}
	}
	return nil
}

func (a *authManager) prepareWithCurrentContext(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	a.ctxMu.RLock()
	defer a.ctxMu.RUnlock()
	if a.closed {
		return nil, authManagerClosedError()
	}
	if a.protoCtx == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("protocol context is unavailable"),
		)
	}
	return a.protoCtx.PrepareInferRequest(ctx, input)
}

func (a *authManager) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	if err := a.closedStateError(); err != nil {
		return nil, err
	}
	if err := a.ensureFresh(ctx); err != nil {
		if protocolErrorKindOf(err) == protocolContextClosed {
			return nil, err
		}
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("refresh authentication: %w", protocolInternalError(err)),
		)
	}
	return a.prepareWithCurrentContext(ctx, input)
}

func (a *authManager) Close() error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		persistErr := a.persistDirtyCredentialLocked(context.Background())
		a.ctxMu.Lock()
		a.closed = true
		current := a.protoCtx
		a.protoCtx = nil
		a.ctxMu.Unlock()
		a.mu.Unlock()

		var contextErr error
		if current != nil {
			contextErr = current.Close()
		}
		a.closeErr = mergeProtocolErrors(persistErr, contextErr)
	})
	return a.closeErr
}

func (a *authManager) load(ctx context.Context) (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	tx, err := a.beginCredentialTxnLocked(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, tx.close()) }()
	b, revision, err := readAuthFile(a.authFile)
	if err != nil {
		return err
	}
	if !revision.exists {
		return fmt.Errorf("credentials are missing; use -login to authenticate")
	}
	if !sameAuthRevision(revision, a.store.baseline.user) {
		return authConflict("credentials changed while loading")
	}
	s := strings.TrimSpace(string(b))
	var plain []byte
	if strings.HasPrefix(s, "{") {
		plain = []byte(s)
	} else {
		dec, err := a.protocol.credentials.Decrypt(ctx, s, machineCredentialKey(a.machineID))
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", a.authFile, err)
		}
		plain = []byte(dec)
	}
	var ui userInfo
	if err := json.Unmarshal(plain, &ui); err != nil {
		return err
	}
	// 1.1.74 binds security_oauth_token inside these fields. Older nonempty
	// caches cannot be trusted. Regenerate in memory without labelling/saving a
	// legacy store merely because it was loaded; the next publication persists it.
	ui.EncryptUserInfo, ui.Key = "", ""
	next, err := a.buildContextForUserLocked(ctx, &ui)
	if err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	if err := tx.check(); err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	if err := a.replaceContext(next); err != nil {
		return err
	}
	a.ui = &ui
	a.store.baseline.login = loginIdentity(&ui)
	a.clearCredentialDirtyLocked()
	return nil
}

func credentialPersistenceError(action string, err error) error {
	if err == nil || isAuthConflict(err) {
		return err
	}
	return newProtocolError(
		protocolBackendFailure,
		"Authentication state could not be saved",
		fmt.Errorf("%s: %w", action, protocolInternalError(err)),
	)
}

type stagedCredential struct {
	tempPath  string
	finalPath string
	published bool
}

func (s *stagedCredential) discard() {
	if s == nil || s.published || s.tempPath == "" {
		return
	}
	_ = os.Remove(s.tempPath)
}

func (s *stagedCredential) publish() error {
	if s == nil || s.tempPath == "" || s.finalPath == "" {
		return fmt.Errorf("staged credential is incomplete")
	}
	if err := os.Rename(s.tempPath, s.finalPath); err != nil {
		return err
	}
	s.published = true
	return nil
}

func (a *authManager) stageCredentialForUserLocked(ctx context.Context, ui *userInfo, tx *credentialTxn) (*stagedCredential, error) {
	if ui == nil {
		return nil, nil
	}
	if a.protocol == nil || a.protocol.credentials == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("credential codec is unavailable"),
		)
	}
	plain, err := json.Marshal(ui)
	if err != nil {
		return nil, err
	}
	enc, err := a.protocol.credentials.Encrypt(ctx, string(plain), machineCredentialKey(a.machineID))
	if err != nil {
		return nil, err
	}
	if err := tx.check(); err != nil {
		return nil, err
	}
	dir := filepath.Dir(a.authFile)
	if _, err := checkedDirectory(dir); err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(dir, ".user-*")
	if err != nil {
		return nil, err
	}
	staged := &stagedCredential{tempPath: temp.Name(), finalPath: a.authFile}
	succeeded := false
	defer func() {
		_ = temp.Close()
		if !succeeded {
			staged.discard()
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return nil, err
	}
	written, err := io.Copy(temp, strings.NewReader(enc))
	if err != nil {
		return nil, err
	}
	if written != int64(len(enc)) {
		return nil, io.ErrShortWrite
	}
	if err := temp.Sync(); err != nil {
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	succeeded = true
	return staged, nil
}

func (a *authManager) markCredentialDirtyLocked() {
	a.credentialDirty = true
	a.credentialPersistRetryAt = time.Time{}
}

func (a *authManager) clearCredentialDirtyLocked() {
	a.credentialDirty = false
	a.credentialPersistRetryAt = time.Time{}
}

func (a *authManager) beginCredentialTxnLocked(ctx context.Context) (*credentialTxn, error) {
	if a.store == nil {
		return nil, authConflict("credential store is not initialized")
	}
	if a.machineID != a.store.machineID {
		return nil, authConflict("in-memory machine identity changed")
	}
	return a.store.begin(ctx)
}

func (a *authManager) saveLocked(ctx context.Context) (err error) {
	if err := a.closedStateError(); err != nil {
		return err
	}
	if a.ui == nil {
		return nil
	}
	a.markCredentialDirtyLocked()
	tx, err := a.beginCredentialTxnLocked(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, tx.close()) }()
	return a.saveInTxnLocked(ctx, tx)
}

func (a *authManager) saveInTxnLocked(ctx context.Context, tx *credentialTxn) error {
	if err := tx.check(); err != nil {
		return err
	}
	if tx.store.ephemeral {
		a.clearCredentialDirtyLocked()
		return nil
	}
	staged, err := a.stageCredentialForUserLocked(ctx, a.ui, tx)
	if err != nil {
		return err
	}
	defer staged.discard()
	if err := tx.publish(staged, a.ui); err != nil {
		return err
	}
	a.clearCredentialDirtyLocked()
	return nil
}

func (a *authManager) detachedCommitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := a.commitTimeout
	if timeout <= 0 {
		timeout = defaultRefreshCommitTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (a *authManager) persistDirtyCredentialLocked(ctx context.Context, held ...*credentialTxn) error {
	if !a.credentialDirty {
		return nil
	}
	persistCtx, cancel := a.detachedCommitContext(ctx)
	defer cancel()
	var err error
	if len(held) > 0 {
		err = a.saveInTxnLocked(persistCtx, held[0])
	} else {
		err = a.saveLocked(persistCtx)
	}
	return credentialPersistenceError("persist pending credentials", err)
}

func (a *authManager) persistDirtyCredentialBestEffortLocked(ctx context.Context, action string, force bool, held ...*credentialTxn) error {
	if !a.credentialDirty {
		return nil
	}
	if a.store != nil {
		if err := a.store.check(); err != nil {
			return err
		}
	}
	now := time.Now()
	if !force && !a.credentialPersistRetryAt.IsZero() && now.Before(a.credentialPersistRetryAt) {
		return nil
	}
	if err := a.persistDirtyCredentialLocked(ctx, held...); err != nil {
		if isAuthConflict(err) {
			return err
		}
		a.credentialPersistRetryAt = time.Now().Add(credentialPersistRetryDelay)
		a.safeLogf("%s: %v", action, protocolDiagnosticError(err))
	}
	return nil
}

func (a *authManager) save(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveLocked(ctx)
}

func cloneUserInfo(ui *userInfo) *userInfo {
	if ui == nil {
		return nil
	}
	cloned := *ui
	cloned.OrgTags = slices.Clone(ui.OrgTags)
	if ui.extra != nil {
		cloned.extra = make(map[string]json.RawMessage, len(ui.extra))
		for key, value := range ui.extra {
			cloned.extra[key] = slices.Clone(value)
		}
	}
	return &cloned
}

func normalizedOrganizationTags(tags []string) []string {
	normalized := make([]string, len(tags))
	copy(normalized, tags)
	return normalized
}

func (a *authManager) runtimeFieldInputForLocked(ui *userInfo) runtimeFieldInput {
	if ui == nil {
		return runtimeFieldInput{}
	}
	return runtimeFieldInput{
		UID:                ui.UID,
		SecurityOAuthToken: ui.SecurityOAuthToken,
		OrganizationID:     ui.OrgID,
		OrganizationTags:   normalizedOrganizationTags(ui.OrgTags),
		DataPolicyAgreed:   ui.DataPolicyAgreed,
	}
}

func (a *authManager) runtimeFieldInputLocked() runtimeFieldInput {
	return a.runtimeFieldInputForLocked(a.ui)
}

func (a *authManager) contextConfigForLocked(ui *userInfo) protocolContextConfig {
	if ui == nil {
		return protocolContextConfig{MachineID: a.machineID, Version: qoderProtocolVersion, Scene: defaultProtocolScene()}
	}
	return protocolContextConfig{
		MachineID: a.machineID,
		Version:   qoderProtocolVersion,
		User: protocolUserInfo{
			UID:              ui.UID,
			EncryptUserInfo:  ui.EncryptUserInfo,
			Key:              ui.Key,
			OrganizationID:   ui.OrgID,
			OrganizationTags: normalizedOrganizationTags(ui.OrgTags),
			DataPolicyAgreed: ui.DataPolicyAgreed,
		},
		Scene: defaultProtocolScene(),
	}
}

func (a *authManager) contextConfigLocked() protocolContextConfig {
	return a.contextConfigForLocked(a.ui)
}

func (a *authManager) buildContextForUserLocked(ctx context.Context, ui *userInfo) (protocolContext, error) {
	if err := a.closedStateError(); err != nil {
		return nil, err
	}
	if ui == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("user credentials are unavailable"),
		)
	}
	if a.protocol == nil || a.protocol.runtimeFields == nil || a.protocol.contextFactory == nil {
		return nil, newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("required protocol capabilities are unavailable"),
		)
	}
	if ui.EncryptUserInfo == "" || ui.Key == "" {
		fields, err := a.protocol.runtimeFields.Generate(ctx, a.runtimeFieldInputForLocked(ui))
		if err != nil {
			return nil, err
		}
		if fields.EncryptUserInfo == "" || fields.Key == "" {
			return nil, newProtocolError(
				protocolAuthUnavailable,
				"Authentication is unavailable",
				fmt.Errorf("generated runtime authentication fields are incomplete"),
			)
		}
		ui.EncryptUserInfo, ui.Key = fields.EncryptUserInfo, fields.Key
		if ui == a.ui {
			a.markCredentialDirtyLocked()
		}
	}
	return a.protocol.contextFactory.New(ctx, a.contextConfigForLocked(ui))
}

func (a *authManager) rebuildContextLocked(ctx context.Context) error {
	next, err := a.buildContextForUserLocked(ctx, a.ui)
	if err != nil {
		return err
	}
	return a.replaceContext(next)
}

func (a *authManager) closeRejectedLoginContext(candidate protocolContext) {
	if candidate == nil {
		return
	}
	if err := candidate.Close(); err != nil {
		a.safeLogf("close rejected login protocol context failed")
	}
}

func (a *authManager) commitLoginCandidateLocked(ctx context.Context, candidate *userInfo) (err error) {
	tx, err := a.beginCredentialTxnLocked(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, tx.close()) }()
	next, err := a.buildContextForUserLocked(ctx, candidate)
	if err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	if next == nil {
		return newProtocolError(
			protocolAuthUnavailable,
			"Authentication is unavailable",
			fmt.Errorf("candidate protocol context is unavailable"),
		)
	}
	if err := a.closedStateError(); err != nil {
		a.closeRejectedLoginContext(next)
		return err
	}
	var staged *stagedCredential
	if !a.store.ephemeral {
		staged, err = a.stageCredentialForUserLocked(ctx, candidate, tx)
		if err != nil {
			a.closeRejectedLoginContext(next)
			return err
		}
		defer staged.discard()
	}

	a.ctxMu.Lock()
	if a.closed {
		a.ctxMu.Unlock()
		a.closeRejectedLoginContext(next)
		return authManagerClosedError()
	}
	if err := tx.publish(staged, candidate); err != nil {
		a.ctxMu.Unlock()
		a.closeRejectedLoginContext(next)
		return err
	}
	old := a.protoCtx
	a.protoCtx = next
	a.ui = candidate
	a.clearCredentialDirtyLocked()
	a.ctxMu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			a.safeLogf("close replaced protocol context failed")
		}
	}
	return nil
}

func (a *authManager) inferEndpoint() string { return a.inferBase }

// ensureFresh refreshes the device token when it expires within refreshSkewSec.
func (a *authManager) ensureFresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	if a.store != nil {
		if err := a.store.check(); err != nil {
			return err
		}
	}
	if err := a.persistDirtyCredentialBestEffortLocked(ctx, "persist pending credentials", false); err != nil {
		return err
	}
	if a.ui == nil {
		return fmt.Errorf("not authenticated")
	}
	now := time.Now().Unix()
	if a.ui.ExpireTime == 0 || a.ui.ExpireTime-refreshSkewSec >= now {
		return nil
	}
	if a.ui.LoginMethod != "token" && a.ui.RefreshTokenExpireTime != 0 && now > a.ui.RefreshTokenExpireTime {
		return fmt.Errorf("refresh token expired; please re-login")
	}
	return a.refreshLocked(ctx)
}

func (a *authManager) forceRefresh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	if a.store != nil {
		if err := a.store.check(); err != nil {
			return err
		}
	}
	if err := a.persistDirtyCredentialBestEffortLocked(ctx, "persist pending credentials", false); err != nil {
		return err
	}
	return a.refreshLocked(ctx)
}

func (a *authManager) preserveRefreshRotationAndSaveLocked(ctx context.Context, refreshToken string, refreshExpiry int64, held ...*credentialTxn) error {
	if a.ui == nil {
		return nil
	}
	refreshChanged := refreshToken != "" && a.ui.RefreshToken != refreshToken
	expiryChanged := refreshExpiry != 0 && a.ui.RefreshTokenExpireTime != refreshExpiry
	if !refreshChanged && !expiryChanged {
		return nil
	}
	a.markCredentialDirtyLocked()
	if refreshChanged {
		a.ui.RefreshToken = refreshToken
	}
	if expiryChanged {
		a.ui.RefreshTokenExpireTime = refreshExpiry
	}
	return a.persistDirtyCredentialLocked(ctx, held...)
}

func (a *authManager) refreshLocked(ctx context.Context) (err error) {
	if err := a.closedStateError(); err != nil {
		return err
	}
	if a.ui == nil {
		return fmt.Errorf("not authenticated")
	}
	tx, err := a.beginCredentialTxnLocked(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, tx.close()) }()
	var candidate *userInfo
	if a.ui.LoginMethod == "token" {
		candidate, err = a.requestPATCandidate(ctx, a.ui.PersonalAccessToken, a.ui, tx)
		if err == nil && candidate.UID != a.ui.UID {
			return authConflict("PAT renewal returned a different account")
		}
	} else {
		candidate, err = a.requestDeviceRefreshLocked(ctx)
	}
	if err != nil {
		return err
	}
	commitCtx, cancelCommit := a.detachedCommitContext(ctx)
	defer cancelCommit()
	candidate.EncryptUserInfo, candidate.Key = "", ""
	next, err := a.buildContextForUserLocked(commitCtx, candidate)
	if err != nil {
		a.closeRejectedLoginContext(next)
		return mergeProtocolErrors(err, a.preserveRefreshRotationAndSaveLocked(commitCtx, candidate.RefreshToken, candidate.RefreshTokenExpireTime, tx))
	}
	if err := tx.check(); err != nil {
		a.closeRejectedLoginContext(next)
		if !isAuthConflict(err) {
			return mergeProtocolErrors(err, a.preserveRefreshRotationAndSaveLocked(commitCtx, candidate.RefreshToken, candidate.RefreshTokenExpireTime, tx))
		}
		return err
	}
	if err := a.replaceContext(next); err != nil {
		return mergeProtocolErrors(err, a.preserveRefreshRotationAndSaveLocked(commitCtx, candidate.RefreshToken, candidate.RefreshTokenExpireTime, tx))
	}
	a.markCredentialDirtyLocked()
	a.ui = candidate
	if err := a.persistDirtyCredentialBestEffortLocked(commitCtx, "persist refreshed credentials", true, tx); err != nil {
		return err
	}
	a.safeLogf("device token refreshed, new expiry %d", a.ui.ExpireTime)
	return nil
}

func (a *authManager) requestDeviceRefreshLocked(ctx context.Context) (*userInfo, error) {
	if a.ui.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh_token")
	}
	body, _ := json.Marshal(machineIdentityRequestFields(a.machineID, "refresh_token", a.ui.RefreshToken))
	req, err := http.NewRequestWithContext(ctx, "POST", a.openapiBase+"/api/v1/deviceToken/refresh", bytes.NewReader(body))
	if err != nil {
		return nil, safeAuthRequestError("device refresh", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", qoderUserAgent())
	resp, err := a.doAuthRequest(req)
	if err != nil {
		return nil, safeAuthRequestError("device refresh", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("deviceToken/refresh status %d", resp.StatusCode)
	}
	var r struct {
		DeviceToken  string `json:"device_token"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshExpAt string `json:"refresh_token_expires_at"`
		RefreshExpIn int64  `json:"refresh_token_expires_in"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid device refresh response")
	}
	tok := r.DeviceToken
	if tok == "" {
		tok = r.Token
	}
	if tok == "" {
		return nil, fmt.Errorf("refresh response missing token")
	}
	candidate := cloneUserInfo(a.ui)
	candidate.SecurityOAuthToken, candidate.AccessToken = tok, tok
	if r.RefreshToken != "" {
		candidate.RefreshToken = r.RefreshToken
	}
	candidate.ExpireTime = parseExpiry(r.ExpiresAt, r.ExpiresIn)
	refreshExpiry := parseExpiry(r.RefreshExpAt, r.RefreshExpIn)
	if refreshExpiry != 0 {
		candidate.RefreshTokenExpireTime = refreshExpiry
	}
	return candidate, nil
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

func machineIdentityRequestFields(machineID, key, value string) map[string]string {
	fields := map[string]string{key: value}
	if id := strings.TrimSpace(machineID); id != "" && id != "unknown" {
		fields["machine_id"] = id
	}
	return fields
}

func (a *authManager) credentialRequestPreflight(ctx context.Context) (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.closedStateError(); err != nil {
		return err
	}
	if _, err := normalizeBaseURL(a.openapiBase, "OpenAPI endpoint"); err != nil {
		return err
	}
	if _, err := normalizeBaseURL(a.webBase, "web endpoint"); err != nil {
		return err
	}
	tx, err := a.beginCredentialTxnLocked(ctx)
	if err != nil {
		return err
	}
	return tx.close()
}

// Never forward a PAT/refresh POST body (307/308), or an authorization header,
// outside the configured issuer. Preserve injectable transports and same-origin
// redirect hooks while retaining a finite redirect limit.
func (a *authManager) doAuthRequest(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header = applyCommonClientIdentity(req.Header)
	client := *a.httpc
	originalCheck := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("authentication redirect limit exceeded")
		}
		if len(via) > 0 && (next.URL.Scheme != via[0].URL.Scheme || !strings.EqualFold(next.URL.Host, via[0].URL.Host)) {
			return http.ErrUseLastResponse
		}
		if originalCheck != nil {
			return originalCheck(next, via)
		}
		return nil
	}
	return client.Do(req)
}

func safeAuthRequestError(action string, err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("%s request failed", action)
}

// deviceLogin runs the full device authorization flow and persists credentials.
func (a *authManager) deviceLogin(ctx context.Context, out io.Writer) error {
	if err := a.credentialRequestPreflight(ctx); err != nil {
		return err
	}
	if out == nil {
		out = io.Discard
	}
	interval, timeout := a.pollInterval, a.pollTimeout
	if interval <= 0 {
		interval = time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	verifier, challenge := pkcePair()
	nonce := newUUID()
	authURL := a.webBase + "/device/selectAccounts?" + url.Values{"challenge": {challenge}, "challenge_method": {"S256"}, "nonce": {nonce}, "machine_id": {a.machineID}, "client_id": {prodClientID}}.Encode()
	fmt.Fprintf(out, "\nOpen this URL in your browser to authorize:\n\n  %s\n\nWaiting for authorization (up to 5 minutes)...\n", authURL)
	pollURL := fmt.Sprintf("%s/api/v1/deviceToken/poll?nonce=%s&verifier=%s&challenge_method=S256",
		a.openapiBase, nonce, verifier)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.credentialRequestPreflight(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
		if err != nil {
			return safeAuthRequestError("device poll", err)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := a.doAuthRequest(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("poll status %d", resp.StatusCode)
		}
		var dr struct {
			Token            string `json:"token"`
			RefreshToken     string `json:"refresh_token"`
			ExpiresAt        string `json:"expires_at"`
			ExpiresIn        int64  `json:"expires_in"`
			RefreshExpiresAt string `json:"refresh_token_expires_at"`
			RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
			UserID           string `json:"user_id"`
			UserName         string `json:"user_name"`
		}
		if err := json.Unmarshal(raw, &dr); err != nil {
			return fmt.Errorf("invalid device poll response")
		}
		if dr.Token == "" {
			return fmt.Errorf("poll response missing token")
		}
		candidate := &userInfo{
			UID: dr.UserID, Name: dr.UserName,
			SecurityOAuthToken: dr.Token, AccessToken: dr.Token,
			RefreshToken: dr.RefreshToken, ExpireTime: parseExpiry(dr.ExpiresAt, dr.ExpiresIn),
			RefreshTokenExpireTime: parseExpiry(dr.RefreshExpiresAt, dr.RefreshExpiresIn),
			LoginMethod:            "browser", LoginTimestamp: time.Now().Unix(),
		}
		a.mu.Lock()
		if err := a.closedStateError(); err != nil {
			a.mu.Unlock()
			return err
		}
		if err := a.commitLoginCandidateLocked(ctx, candidate); err != nil {
			a.mu.Unlock()
			return err
		}
		a.mu.Unlock()
		// best-effort profile enrichment for this exact committed candidate.
		a.fetchUserInfo(ctx, candidate)
		a.mu.Lock()
		successUID, successName := candidate.UID, candidate.Name
		a.mu.Unlock()
		fmt.Fprintf(out, "Login successful. uid=%s name=%s\n", successUID, successName)
		return nil
	}
}

type authUserInfoProfile struct {
	DataPolicyAgreed       *bool    `json:"data_policy_agreed"`
	IsDataPolicyModifiable *bool    `json:"is_data_policy_modifiable"`
	UID                    string   `json:"uid"`
	Name                   string   `json:"name"`
	Email                  string   `json:"email"`
	OrgID                  string   `json:"organization_id"`
	OrgName                string   `json:"organization_name"`
	OrgTags                []string `json:"organization_tags"`
}

func (a *authManager) requestUserInfo(ctx context.Context, token string, held ...*credentialTxn) (authUserInfoProfile, error) {
	if len(held) > 0 {
		if err := held[0].check(); err != nil {
			return authUserInfoProfile{}, err
		}
	} else {
		a.mu.Lock()
		err := a.closedStateError()
		if err == nil && a.store != nil {
			err = a.store.check()
		}
		a.mu.Unlock()
		if err != nil {
			return authUserInfoProfile{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", a.openapiBase+"/api/v1/userinfo", nil)
	if err != nil {
		return authUserInfoProfile{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", qoderUserAgent())
	resp, err := a.doAuthRequest(req)
	if err != nil {
		return authUserInfoProfile{}, err
	}
	if resp == nil {
		return authUserInfoProfile{}, fmt.Errorf("userinfo response is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authUserInfoProfile{}, fmt.Errorf("userinfo status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return authUserInfoProfile{}, err
	}
	var profile authUserInfoProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return authUserInfoProfile{}, err
	}
	return profile, nil
}

func applyAuthUserInfoProfile(ui *userInfo, profile authUserInfoProfile) {
	if ui == nil {
		return
	}
	if profile.DataPolicyAgreed != nil {
		ui.DataPolicyAgreed = *profile.DataPolicyAgreed
	}
	if profile.IsDataPolicyModifiable != nil {
		ui.IsDataPolicyModifiable = *profile.IsDataPolicyModifiable
	}
	if profile.UID != "" {
		ui.UID = profile.UID
	}
	if profile.Email != "" {
		ui.Email = profile.Email
	}
	if profile.Name != "" {
		ui.Name = profile.Name
	}
	if profile.OrgID != "" {
		ui.OrgID, ui.OrgName = profile.OrgID, profile.OrgName
	}
	if profile.OrgTags != nil {
		ui.OrgTags = append([]string(nil), profile.OrgTags...)
	}
}

func (a *authManager) fetchUserInfo(ctx context.Context, target *userInfo) {
	if target == nil {
		return
	}
	a.mu.Lock()
	if a.closedStateError() != nil || a.ui != target {
		a.mu.Unlock()
		return
	}
	if a.store != nil {
		if err := a.store.check(); err != nil {
			a.safeLogf("profile enrichment skipped: %v", err)
			a.mu.Unlock()
			return
		}
	}
	tok := target.SecurityOAuthToken
	a.mu.Unlock()
	profile, err := a.requestUserInfo(ctx, tok)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closedStateError() != nil || a.ui != target {
		return
	}
	if profile.UID != "" && target.UID != "" && profile.UID != target.UID {
		a.safeLogf("profile enrichment skipped: account identity mismatch")
		return
	}
	tx, err := a.beginCredentialTxnLocked(ctx)
	if err != nil {
		a.safeLogf("profile enrichment skipped: %v", err)
		return
	}
	defer func() {
		if err := tx.close(); err != nil {
			a.safeLogf("profile enrichment transaction failed: %v", err)
		}
	}()
	enriched := cloneUserInfo(target)
	applyAuthUserInfoProfile(enriched, profile)
	enriched.EncryptUserInfo, enriched.Key = "", ""
	next, err := a.buildContextForUserLocked(ctx, enriched)
	if err != nil {
		a.closeRejectedLoginContext(next)
		return
	}
	if err := tx.check(); err != nil {
		a.closeRejectedLoginContext(next)
		a.safeLogf("profile enrichment skipped: %v", err)
		return
	}
	if err := a.replaceContext(next); err != nil {
		return
	}
	*target = *enriched
	a.markCredentialDirtyLocked()
	if err := a.persistDirtyCredentialBestEffortLocked(ctx, "persist profile enrichment", true, tx); err != nil {
		a.safeLogf("profile enrichment skipped: %v", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

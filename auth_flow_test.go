package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeJSONResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestRuntimeFieldsBindCurrentSecurityTokenAndUpgradeLegacyCache(t *testing.T) {
	dir := t.TempDir()
	services := storeTestServices()
	a, err := newAuthManager(services, dir, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.ui = &userInfo{UID: "synthetic", SecurityOAuthToken: "fake-current", EncryptUserInfo: "legacy-fields", Key: "legacy-key"}
	input := a.runtimeFieldInputLocked()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"uid":"synthetic","security_oauth_token":"fake-current","organization_id":"","organization_tags":[],"data_policy_agreed":false}`
	if string(raw) != want {
		t.Fatalf("runtime semantic input = %s", raw)
	}
	if err := a.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.Close()
	services = storeTestServices()
	b, err := newAuthManager(services, dir, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	generator := services.runtimeFields.(*fakeRuntimeFieldGenerator)
	if generator.calls != 1 || b.ui.EncryptUserInfo == "legacy-fields" {
		t.Fatal("legacy cached fields reused without token-bound regeneration")
	}
	raw, _ = json.Marshal(generator.inputs[0])
	if string(raw) != want {
		t.Fatal("load generated fields without current token")
	}
}

func TestProfileExplicitEmptyTagsClearPreviousOrganizationTags(t *testing.T) {
	ui := &userInfo{OrgTags: []string{"stale-tag"}}
	var profile authUserInfoProfile
	if err := json.Unmarshal([]byte(`{"organization_tags":[]}`), &profile); err != nil {
		t.Fatal(err)
	}
	applyAuthUserInfoProfile(ui, profile)
	if len(ui.OrgTags) != 0 {
		t.Fatal("explicit empty profile tags retained stale organization membership")
	}
}

func TestProfileEnrichmentRegeneratesTokenBoundOrganizationAndPolicy(t *testing.T) {
	for _, wantPolicy := range []bool{true, false} {
		t.Run(fmt.Sprint(wantPolicy), func(t *testing.T) {
			services := storeTestServices()
			a, err := newAuthManager(services, t.TempDir(), "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.ui = &userInfo{UID: "synthetic", SecurityOAuthToken: "fake-current", OrgID: "old-org", OrgTags: []string{"old-tag"}, DataPolicyAgreed: !wantPolicy, EncryptUserInfo: "old-bound-fields", Key: "old-key"}
			a.protoCtx = &fakeProtocolContext{}
			if err := a.save(context.Background()); err != nil {
				t.Fatal(err)
			}
			generator := services.runtimeFields.(*fakeRuntimeFieldGenerator)
			generator.output = runtimeFieldOutput{EncryptUserInfo: "new-bound-fields", Key: "new-key"}
			a.httpc = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return fakeJSONResponse(200, fmt.Sprintf(`{"uid":"synthetic","organization_id":"new-org","organization_tags":["new-tag"],"data_policy_agreed":%t}`, wantPolicy)), nil
			})}
			a.fetchUserInfo(context.Background(), a.ui)
			if generator.calls != 1 {
				t.Fatal("enrichment did not regenerate runtime fields")
			}
			input := generator.inputs[0]
			if input.SecurityOAuthToken != "fake-current" || input.OrganizationID != "new-org" || len(input.OrganizationTags) != 1 || input.OrganizationTags[0] != "new-tag" || input.DataPolicyAgreed != wantPolicy {
				t.Fatal("runtime fields regenerated from stale profile/token")
			}
			factory := services.contextFactory.(*fakeProtocolContextFactory)
			if len(factory.configs) != 1 || factory.configs[0].User.EncryptUserInfo != "new-bound-fields" || factory.configs[0].User.OrganizationID != "new-org" || factory.configs[0].User.DataPolicyAgreed != wantPolicy {
				t.Fatal("active context mixes old runtime fields with new profile")
			}
		})
	}
}

func TestRefreshPostBuildStoreCheckPreservesRotationOnlyForTemporaryIO(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		conflict, closeRecovery bool
	}{
		{name: "retry after temporary binding read failure"},
		{name: "Close after temporary binding read failure", closeRecovery: true},
		{name: "ownership conflict remains fail closed", conflict: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			services := storeTestServices()
			a, err := newAuthManager(services, t.TempDir(), "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			failRead := false
			defer func() { failRead = false; _ = a.Close() }()
			oldContext, candidateContext := &fakeProtocolContext{}, &fakeProtocolContext{}
			services.contextFactory = &fakeProtocolContextFactory{contexts: []protocolContext{candidateContext}}
			oldUI := &userInfo{UID: "synthetic", LoginMethod: "browser", LoginTimestamp: 123, SecurityOAuthToken: "fake-old-access", AccessToken: "fake-old-access", RefreshToken: "fake-old-refresh", ExpireTime: time.Now().Add(2 * time.Hour).Unix(), EncryptUserInfo: "old-bound-fields", Key: "old-key"}
			a.ui, a.protoCtx = oldUI, oldContext
			if err := a.save(context.Background()); err != nil {
				t.Fatal(err)
			}
			baseline := a.store.baseline
			readFailure := errors.New("synthetic temporary binding read failure")
			a.store.readBindingFile = func(path string) ([]byte, authFileRevision, error) {
				if failRead {
					if tt.conflict {
						return nil, authFileRevision{}, authConflict("synthetic binding ownership change")
					}
					return nil, authFileRevision{}, &os.PathError{Op: "open", Path: path, Err: readFailure}
				}
				return readAuthFile(path)
			}
			refreshCalls := 0
			a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				refreshCalls++
				failRead = true
				return fakeJSONResponse(http.StatusOK, `{"token":"fake-new-access","refresh_token":"fake-rotated-refresh","expires_in":7200,"refresh_token_expires_at":"2030-01-02T03:04:05Z"}`), nil
			})}
			err = a.forceRefresh(context.Background())
			if tt.conflict {
				if !isAuthConflict(err) {
					t.Fatalf("expected ownership conflict, got %v", err)
				}
			} else if err == nil || isAuthConflict(err) || !errors.Is(err, readFailure) {
				t.Fatalf("expected ordinary temporary store read failure, got %v", err)
			}
			if a.ui != oldUI || a.protoCtx != oldContext || a.ui.SecurityOAuthToken != "fake-old-access" || a.ui.AccessToken != "fake-old-access" || a.ui.EncryptUserInfo != "old-bound-fields" || a.ui.Key != "old-key" {
				t.Fatal("failed post-build check changed the active token/context")
			}
			if closes, _ := candidateContext.state(); closes != 1 {
				t.Fatalf("rejected candidate closed %d times, want once", closes)
			}
			if closes, _ := oldContext.state(); closes != 0 {
				t.Fatal("active context closed before replacement was accepted")
			}
			if !sameAuthRevision(a.store.baseline.user, baseline.user) || !sameAuthRevision(a.store.baseline.machine, baseline.machine) || !sameAuthRevision(a.store.baseline.binding, baseline.binding) || a.store.baseline.login != baseline.login {
				t.Fatal("failed check rebased the persisted baseline")
			}
			if tt.conflict {
				if a.credentialDirty || a.ui.RefreshToken != "fake-old-refresh" || a.ui.RefreshTokenExpireTime != 0 {
					t.Fatal("ownership conflict mutated or dirtied credential state")
				}
				return
			}
			wantExpiry := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC).Unix()
			if !a.credentialDirty || a.ui.RefreshToken != "fake-rotated-refresh" || a.ui.RefreshTokenExpireTime != wantExpiry {
				t.Fatal("temporary read failure discarded the refresh rotation or dirty retry state")
			}
			failRead = false
			if err := a.store.check(); err != nil {
				t.Fatalf("unchanged store failed after IO recovery: %v", err)
			}
			if tt.closeRecovery {
				if err := a.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := a.ensureFresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if refreshCalls != 1 || a.credentialDirty {
				t.Fatal("IO recovery refetched credentials or did not flush the pending rotation")
			}
			raw, err := os.ReadFile(a.authFile)
			if err != nil {
				t.Fatal(err)
			}
			var persisted userInfo
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatal("could not decode synthetic persisted credential")
			}
			if persisted.SecurityOAuthToken != "fake-old-access" || persisted.RefreshToken != "fake-rotated-refresh" || persisted.RefreshTokenExpireTime != wantExpiry {
				t.Fatal("recovered persistence did not retain old active token with rotated refresh credential")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if closes, _ := candidateContext.state(); closes != 1 {
				t.Fatal("Close closed the rejected candidate again")
			}
			if closes, _ := oldContext.state(); closes != 1 {
				t.Fatal("active context did not close exactly once")
			}
		})
	}
}

func TestRuntimeGenerationFailureRejectsRefreshButPreservesRotation(t *testing.T) {
	services := storeTestServices()
	a, err := newAuthManager(services, t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	old := &fakeProtocolContext{}
	a.protoCtx = old
	a.ui = &userInfo{UID: "synthetic", SecurityOAuthToken: "fake-old", AccessToken: "fake-old", RefreshToken: "fake-old-refresh", EncryptUserInfo: "old-bound-fields", Key: "old-key"}
	if err := a.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	services.runtimeFields.(*fakeRuntimeFieldGenerator).err = errors.New("synthetic field generation failure")
	a.httpc = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return fakeJSONResponse(200, `{"token":"fake-new","refresh_token":"fake-rotated","expires_in":7200}`), nil
	})}
	if err := a.forceRefresh(context.Background()); err == nil {
		t.Fatal("accepted new token with old token-bound fields")
	}
	if a.ui.SecurityOAuthToken != "fake-old" || a.ui.EncryptUserInfo != "old-bound-fields" || a.ui.RefreshToken != "fake-rotated" || a.protoCtx != old {
		t.Fatal("rotation preservation or active state consistency broken")
	}
	data, err := os.ReadFile(a.authFile)
	if err != nil {
		t.Fatal(err)
	}
	var disk userInfo
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.SecurityOAuthToken != "fake-old" || disk.RefreshToken != "fake-rotated" {
		t.Fatal("rotation was not durably preserved")
	}
}

func TestPATChecksBindingAgainBeforeSendingExchangedTokenToUserInfo(t *testing.T) {
	a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	userinfoCalls := 0
	a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v1/jobToken/exchange" {
			other := a.store.expected
			other.Region = "cn"
			raw, _ := json.Marshal(other)
			if err := os.WriteFile(filepath.Join(a.store.dir, authBindingName), raw, 0600); err != nil {
				t.Fatal(err)
			}
			return fakeJSONResponse(200, `{"token":"fake-exchanged"}`), nil
		}
		userinfoCalls++
		return fakeJSONResponse(200, `{"uid":"synthetic"}`), nil
	})}
	if err := patLogin(context.Background(), a, "fake-pat"); !isAuthConflict(err) {
		t.Fatalf("changed binding error = %v", err)
	}
	if userinfoCalls != 0 {
		t.Fatal("sent token after issuer binding changed")
	}
	if a.ui != nil || a.credentialDirty {
		t.Fatal("rejected login became dirty")
	}
}

func TestAuthRejectsCredentialRedirectToAnotherOrigin(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	a, err := newAuthManager(storeTestServices(), t.TempDir(), source.URL, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := patLogin(context.Background(), a, "fake-pat"); err == nil {
		t.Fatal("cross-origin redirect succeeded")
	}
	if leaked.Load() != 0 {
		t.Fatal("credential-bearing request followed cross-origin redirect")
	}
}

func TestPATRefreshPreservesAccountMetadataAndUnknownFields(t *testing.T) {
	a, err := newAuthManagerWithOptions(storeTestServices(), filepath.Join(t.TempDir(), "absent"), "", "", "", nil, authManagerOptions{ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.ui = &userInfo{UID: "same-user", LoginMethod: "token", LoginTimestamp: 123, PersonalAccessToken: "fake-pat", SecurityOAuthToken: "fake-old", DataPolicyAgreed: true, AvatarURL: "synthetic-avatar", extra: map[string]json.RawMessage{"future": []byte(`{"large":9007199254740993}`)}}
	a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v1/jobToken/exchange" {
			return fakeJSONResponse(200, `{"token":"fake-new"}`), nil
		}
		return fakeJSONResponse(200, `{"uid":"same-user","name":"Updated"}`), nil
	})}
	if err := a.forceRefresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.ui.DataPolicyAgreed || a.ui.AvatarURL != "synthetic-avatar" || a.ui.LoginTimestamp != 123 || a.ui.Name != "Updated" || string(a.ui.extra["future"]) != `{"large":9007199254740993}` {
		t.Fatal("PAT renewal dropped existing account metadata")
	}
}

func TestPATRefreshAppliesExplicitPolicyFromUserInfo(t *testing.T) {
	a, err := newAuthManagerWithOptions(storeTestServices(), filepath.Join(t.TempDir(), "absent"), "", "", "", nil, authManagerOptions{ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.ui = &userInfo{UID: "same-user", LoginMethod: "token", PersonalAccessToken: "fake-pat", SecurityOAuthToken: "fake-old", DataPolicyAgreed: true}
	a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v1/jobToken/exchange" {
			return fakeJSONResponse(200, `{"token":"fake-new"}`), nil
		}
		return fakeJSONResponse(200, `{"uid":"same-user","data_policy_agreed":false}`), nil
	})}
	if err := a.forceRefresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.ui.DataPolicyAgreed {
		t.Fatal("PAT renewal ignored explicit false policy")
	}
}

func TestPATRefreshRejectsAccountChangeWithoutReplacingActiveState(t *testing.T) {
	a, err := newAuthManagerWithOptions(storeTestServices(), filepath.Join(t.TempDir(), "absent"), "", "", "", nil, authManagerOptions{region: "cn", ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.ui = &userInfo{UID: "original", LoginMethod: "token", PersonalAccessToken: "fake-pat", SecurityOAuthToken: "fake-old", EncryptUserInfo: "old-fields", Key: "old-key"}
	prior := a.ui
	a.protoCtx = &fakeProtocolContext{}
	a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v1/jobToken/exchange" {
			return fakeJSONResponse(200, `{"token":"fake-new"}`), nil
		}
		return fakeJSONResponse(200, `{"uid":"other-account"}`), nil
	})}
	if err := a.forceRefresh(context.Background()); !isAuthConflict(err) {
		t.Fatalf("changed PAT UID = %v", err)
	}
	if a.ui != prior || a.ui.SecurityOAuthToken != "fake-old" || a.credentialDirty {
		t.Fatal("PAT account conflict replaced active state")
	}
}

func TestRegionDeviceFlowUsesOnePKCEIdentityAndIssuer(t *testing.T) {
	for _, region := range []string{"global", "cn"} {
		t.Run(region, func(t *testing.T) {
			a, err := newAuthManagerWithOptions(storeTestServices(), t.TempDir(), "", "", "", nil, authManagerOptions{region: region})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.pollInterval = time.Millisecond
			var output bytes.Buffer
			polls := 0
			a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				profile, _ := resolveRegion(region)
				if req.URL.Scheme+"://"+req.URL.Host != profile.openapi {
					t.Fatalf("wrong region API: %s", req.URL.Host)
				}
				switch req.URL.Path {
				case "/api/v1/deviceToken/poll":
					polls++
					var browser *url.URL
					for _, field := range strings.Fields(output.String()) {
						if strings.HasPrefix(field, "https://") {
							browser, _ = url.Parse(field)
							break
						}
					}
					if browser == nil || browser.Scheme+"://"+browser.Host != profile.web || browser.Path != "/device/selectAccounts" {
						t.Fatalf("browser URL wrong: %s", output.String())
					}
					q := browser.Query()
					p := req.URL.Query()
					sum := sha256.Sum256([]byte(p.Get("verifier")))
					if q.Get("nonce") == "" || q.Get("nonce") != p.Get("nonce") || q.Get("machine_id") != a.machineID || q.Get("client_id") != prodClientID || q.Get("challenge_method") != "S256" || q.Get("challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
						t.Fatal("PKCE identity/client mismatch")
					}
					// Browser wait must not own the official lease.
					if _, err := os.Stat(filepath.Join(a.store.dir, ".credential-transaction.lock")); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("lease held during browser wait")
					}
					if polls == 1 {
						return fakeJSONResponse(404, `{}`), nil
					}
					return fakeJSONResponse(200, `{"token":"fake-device","refresh_token":"fake-refresh","expires_in":7200,"user_id":"synthetic-user"}`), nil
				case "/api/v1/deviceToken/refresh":
					var body map[string]string
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if body["machine_id"] != a.machineID || body["refresh_token"] != "fake-refresh" || body["machine_type"] != "" || body["machine_token"] != "" {
						t.Fatal("browser refresh machine fields are incorrect")
					}
					return fakeJSONResponse(200, `{"token":"fake-refreshed","refresh_token":"fake-rotated","expires_in":7200}`), nil
				case "/api/v1/userinfo":
					return fakeJSONResponse(200, `{"uid":"synthetic-user","name":"Synthetic"}`), nil
				default:
					t.Fatalf("unexpected path: %s", req.URL.Path)
					return nil, nil
				}
			})}
			if err := a.deviceLogin(context.Background(), &output); err != nil {
				t.Fatal(err)
			}
			if err := a.forceRefresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			generator := a.protocol.runtimeFields.(*fakeRuntimeFieldGenerator)
			if generator.inputs[len(generator.inputs)-1].SecurityOAuthToken != "fake-refreshed" {
				t.Fatal("browser refresh regenerated fields with stale token")
			}
			profile, _ := resolveRegion(region)
			if a.inferEndpoint() != profile.infer || polls != 2 {
				t.Fatal("inference region or poll retry wrong")
			}
			if !a.store.baseline.binding.exists {
				t.Fatal("credentials published without binding")
			}
		})
	}
}

func TestDevicePollRevalidatesStoreBeforeEveryRequest(t *testing.T) {
	for _, changed := range []string{"binding", "machine_id", "user"} {
		t.Run(changed, func(t *testing.T) {
			a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.pollInterval = time.Millisecond
			a.pollTimeout = time.Second
			polls := 0
			a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/v1/deviceToken/poll" {
					t.Fatal("unexpected request")
				}
				if _, err := os.Stat(filepath.Join(a.store.dir, ".credential-transaction.lock")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("credential lease held across network poll")
				}
				polls++
				if polls == 1 {
					name, raw := changed, []byte(`{"uid":"synthetic-external-login"}`)
					switch changed {
					case "binding":
						name = authBindingName
						binding := a.store.expected
						binding.Region = "cn"
						var err error
						raw, err = json.Marshal(binding)
						if err != nil {
							t.Fatal(err)
						}
					case "machine_id":
						raw = []byte("synthetic-replaced-machine")
					}
					if err := os.WriteFile(filepath.Join(a.store.dir, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
					return fakeJSONResponse(http.StatusNotFound, `{}`), nil
				}
				return fakeJSONResponse(http.StatusOK, `{"token":"synthetic-browser-token","user_id":"synthetic-user"}`), nil
			})}
			if err := a.deviceLogin(context.Background(), io.Discard); !isAuthConflict(err) {
				t.Fatalf("store change must immediately return a conflict: %v", err)
			}
			if polls != 1 {
				t.Fatalf("issued %d polls after store changed; want only the first poll", polls)
			}
			if a.ui != nil || a.credentialDirty {
				t.Fatal("rejected poll flow mutated auth state")
			}
		})
	}
}

func TestDevicePollDecodeFailureDoesNotExposeResponseContent(t *testing.T) {
	a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	const responseValue = "31415926535897932384626433832795"
	a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return fakeJSONResponse(http.StatusOK, `{"token":"synthetic-browser-token","expires_in":`+responseValue+`}`), nil
	})}
	var output bytes.Buffer
	err = a.deviceLogin(context.Background(), &output)
	if err == nil {
		t.Fatal("malformed device poll response was accepted")
	}
	if strings.Contains(err.Error(), responseValue) || strings.Contains(protocolDiagnosticError(err).Error(), responseValue) || strings.Contains(output.String(), responseValue) {
		t.Fatal("device poll decode diagnostic exposed upstream response content")
	}
	if err.Error() != "invalid device poll response" {
		t.Fatal("device poll decode error is not the fixed content-silent diagnostic")
	}
	if a.ui != nil || a.credentialDirty {
		t.Fatal("malformed poll response mutated auth state")
	}
}

func TestDeviceFlowCancellationTimeoutAndErrors(t *testing.T) {
	for _, kind := range []string{"cancel", "timeout", "status", "missing token", "bad URL"} {
		t.Run(kind, func(t *testing.T) {
			a, err := newAuthManager(storeTestServices(), t.TempDir(), "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.pollInterval = time.Millisecond
			a.pollTimeout = 10 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch kind {
				case "cancel":
					cancel()
					return nil, ctx.Err()
				case "timeout":
					return fakeJSONResponse(404, `{}`), nil
				case "missing token":
					return fakeJSONResponse(200, `{"refresh_token":"synthetic-secret"}`), nil
				default:
					return fakeJSONResponse(403, `synthetic-secret`), nil
				}
			})}
			if kind == "bad URL" {
				a.openapiBase = "://synthetic-secret"
			}
			err = a.deviceLogin(ctx, io.Discard)
			if err == nil {
				t.Fatal("failed flow succeeded")
			}
			if strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("auth error leaked response or URL secret")
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error = %v", err)
			}
			if a.ui != nil || a.credentialDirty {
				t.Fatal("failed login mutated auth state")
			}
		})
	}
}

func TestEphemeralPATRefreshAndCloseNeverWriteStore(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), ".auth")
			original := map[string]string{"machine_id": "synthetic-existing-machine", "user": "synthetic-existing-ciphertext"}
			if existing {
				os.Mkdir(dir, 0700)
				for name, data := range original {
					os.WriteFile(filepath.Join(dir, name), []byte(data), 0600)
				}
			}
			a, err := newAuthManagerWithOptions(storeTestServices(), dir, "", "", "", nil, authManagerOptions{region: "cn", ephemeral: true})
			if err != nil {
				t.Fatal(err)
			}
			exchanges := 0
			a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "openapi.qoder.com.cn" {
					t.Fatal("PAT/refresh used wrong issuer")
				}
				if req.Method == "POST" {
					var body map[string]string
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if body["machine_id"] != a.machineID || body["machine_token"] != "" || body["machine_type"] != "" {
						t.Fatal("native machine identity request fields wrong")
					}
				}
				switch req.URL.Path {
				case "/api/v1/jobToken/exchange":
					exchanges++
					if exchanges > 1 {
						return fakeJSONResponse(200, `{"token":"fake-refreshed","expires_in":7200}`), nil
					}
					return fakeJSONResponse(200, `{"token":"fake-pat-token","expires_in":1}`), nil
				case "/api/v1/userinfo":
					return fakeJSONResponse(200, `{"uid":"pat-uid"}`), nil
				case "/api/v1/deviceToken/refresh":
					t.Fatal("PAT renewal incorrectly used device-token refresh")
					return nil, errors.New("wrong refresh strategy")
				default:
					t.Fatal("unexpected API")
					return nil, nil
				}
			})}
			if err := patLogin(context.Background(), a, "fake-pat"); err != nil {
				t.Fatal(err)
			}
			if a.ui.UID != "pat-uid" {
				t.Fatal("PAT UID not populated")
			}
			if err := a.ensureFresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if exchanges != 2 || a.ui.SecurityOAuthToken != "fake-refreshed" {
				t.Fatal("PAT was not re-exchanged on expiry")
			}
			if err := a.forceRefresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if exchanges != 3 {
				t.Fatal("PAT was not re-exchanged on forced/401 refresh")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if !existing {
				if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("ephemeral mode created auth directory")
				}
				return
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(original) {
				t.Fatalf("ephemeral files created: %v", entries)
			}
			for name, want := range original {
				data, _ := os.ReadFile(filepath.Join(dir, name))
				if string(data) != want {
					t.Fatal("ephemeral mode changed persistent bytes")
				}
			}
		})
	}
}

func TestRunEnvironmentPATStartsServerWithoutPersistentConstructor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cn-root", ".auth")
	cfg, err := parseAppConfig([]string{"-region=cn", "-auth-dir=" + dir}, envLookup(map[string]string{"QODERCN_PERSONAL_ACCESS_TOKEN": "fake-cn-pat"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	deps := appDeps{
		newProtocolServices: func(protocolHostDeps) (*protocolServices, error) { return storeTestServices(), nil },
		newAuthManager: func(*protocolServices, string, string, string, string, func(string, ...any)) (*authManager, error) {
			t.Fatal("persistent constructor used for environment PAT")
			return nil, nil
		},
		newAuthManagerWithOptions: func(s *protocolServices, dir, api, infer, web string, logf func(string, ...any), options authManagerOptions) (*authManager, error) {
			if !options.ephemeral || options.region != "cn" {
				t.Fatal("wrong auth mode/profile")
			}
			a, err := newAuthManagerWithOptions(s, dir, api, infer, web, logf, options)
			if err != nil {
				return nil, err
			}
			a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/api/v1/jobToken/exchange":
					return fakeJSONResponse(200, `{"token":"fake-token","expires_in":7200}`), nil
				case "/api/v1/userinfo":
					return fakeJSONResponse(200, `{"uid":"fake-pat-user"}`), nil
				default:
					t.Fatal("unexpected API")
					return nil, nil
				}
			})}
			return a, nil
		},
		loadCredentials: func(context.Context, *authManager) error {
			t.Fatal("environment PAT loaded persistent credentials")
			return nil
		},
		listenAndServe: func(*http.Server) error { started = true; return http.ErrServerClosed },
		shutdown:       func(context.Context, *http.Server) error { return nil },
	}
	if err := run(context.Background(), cfg, deps, io.Discard, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !started {
		t.Fatal("environment PAT exited instead of serving")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("environment PAT created store")
	}
}

func TestRefreshLeaseSpansRemoteRequestAndCommit(t *testing.T) {
	dir := t.TempDir()
	a, err := newAuthManager(storeTestServices(), dir, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.ui = &userInfo{UID: "synthetic", LoginMethod: "browser", LoginTimestamp: 1, SecurityOAuthToken: "fake-old", RefreshToken: "fake-refresh", ExpireTime: 1, EncryptUserInfo: "fake-runtime", Key: "fake-key"}
	if err := a.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := newAuthManager(storeTestServices(), dir, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	a.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(started)
		<-release
		return fakeJSONResponse(200, `{"token":"fake-new","refresh_token":"fake-rotated","expires_in":7200}`), nil
	})}
	b.httpc = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fakeJSONResponse(200, `{"token":"should-not-refresh"}`), nil
	})}
	done := make(chan error, 1)
	go func() { done <- a.forceRefresh(context.Background()) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = b.forceRefresh(ctx)
	close(release)
	if firstErr := <-done; firstErr != nil {
		t.Fatal(firstErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second refresh did not wait for lease: %v", err)
	}
	if err := b.forceRefresh(context.Background()); !isAuthConflict(err) {
		t.Fatalf("stale manager should fail closed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh token redeemed %d times", calls.Load())
	}
}

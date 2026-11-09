package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestAuthUserInfoProfileNormalizesCurrentGlobalShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/userinfo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"synthetic-openapi-id",
			"name":"Synthetic Display",
			"nick_name":"Synthetic Nick",
			"username":"synthetic-login",
			"avatar":"https://qoder.example/avatar",
			"email":"synthetic@example.invalid",
			"organization_id":"synthetic-org",
			"organization_name":"Synthetic Org",
			"is_privacy_policy_modifiable":false
		}`))
	}))
	defer server.Close()

	manager := &authManager{
		openapiBase: server.URL,
		httpc:       server.Client(),
		logf:        func(string, ...any) {},
	}
	profile, err := manager.requestUserInfo(context.Background(), "synthetic-token")
	if err != nil {
		t.Fatalf("requestUserInfo() error = %v", err)
	}
	if profile.UID != "synthetic-openapi-id" {
		t.Fatalf("profile UID = %q, want current-shape id", profile.UID)
	}
	if profile.Name != "Synthetic Display" {
		t.Fatalf("profile Name = %q, want name", profile.Name)
	}
	if profile.OrgID != "synthetic-org" || profile.OrgName != "Synthetic Org" {
		t.Fatalf("profile organization = %q/%q, want synthetic-org/Synthetic Org", profile.OrgID, profile.OrgName)
	}
	if profile.AvatarURL != "https://qoder.example/avatar" {
		t.Fatalf("profile AvatarURL = %q, want avatar fallback", profile.AvatarURL)
	}
	if profile.IsDataPolicyModifiable == nil || *profile.IsDataPolicyModifiable {
		t.Fatal("profile privacy-policy flag was not normalized to false")
	}

	ui := &userInfo{}
	applyAuthUserInfoProfile(ui, profile)
	if ui.UID != "synthetic-openapi-id" || ui.OrgID != "synthetic-org" || ui.AvatarURL != "https://qoder.example/avatar" {
		t.Fatalf("applied profile = %+v", ui)
	}
	if ui.IsDataPolicyModifiable {
		t.Fatal("applied privacy-policy flag = true, want false")
	}
}

func TestAuthUserInfoProfileKeepsLegacyShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/userinfo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"uid":"synthetic-legacy-uid",
			"name":"Legacy Name",
			"email":"legacy@example.invalid",
			"avatar_url":"https://qoder.example/legacy-avatar",
			"organization_id":"legacy-org",
			"organization_name":"Legacy Org",
			"organization_tags":["legacy-tag"],
			"data_policy_agreed":true,
			"is_data_policy_modifiable":true
		}`))
	}))
	defer server.Close()

	manager := &authManager{
		openapiBase: server.URL,
		httpc:       server.Client(),
		logf:        func(string, ...any) {},
	}
	profile, err := manager.requestUserInfo(context.Background(), "synthetic-token")
	if err != nil {
		t.Fatalf("requestUserInfo() error = %v", err)
	}
	if profile.UID != "synthetic-legacy-uid" || profile.OrgID != "legacy-org" {
		t.Fatalf("legacy profile = %+v", profile)
	}
	if profile.DataPolicyAgreed == nil || !*profile.DataPolicyAgreed {
		t.Fatal("legacy data_policy_agreed was not decoded")
	}
	if profile.IsDataPolicyModifiable == nil || !*profile.IsDataPolicyModifiable {
		t.Fatal("legacy is_data_policy_modifiable was not decoded")
	}
	if len(profile.OrgTags) != 1 || profile.OrgTags[0] != "legacy-tag" {
		t.Fatalf("legacy organization tags = %v", profile.OrgTags)
	}
}

func TestAuthManagerPATLoginAcceptsCurrentGlobalUserInfoShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/jobToken/exchange":
			_, _ = w.Write([]byte(`{"token":"synthetic-current-pat-token","refresh_token":"synthetic-current-pat-refresh","expires_in":7200}`))
		case "/api/v1/userinfo":
			_, _ = w.Write([]byte(`{
				"id":"synthetic-current-pat-user",
				"name":"Synthetic Current User",
				"username":"synthetic-current-login",
				"avatar":"https://qoder.example/current-avatar",
				"organization_id":"synthetic-current-org",
				"organization_name":"Synthetic Current Org",
				"is_privacy_policy_modifiable":false
			}`))
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
	if manager.ui == nil {
		t.Fatal("PAT login did not commit a user profile")
	}
	if manager.ui.UID != "synthetic-current-pat-user" {
		t.Fatalf("committed UID = %q, want current-shape id", manager.ui.UID)
	}
	if manager.ui.Name != "Synthetic Current User" || manager.ui.OrgID != "synthetic-current-org" {
		t.Fatalf("committed profile = %+v", manager.ui)
	}
	if generator.calls != 1 || len(factory.configs) != 1 {
		t.Fatalf("runtime field/context calls = %d/%d, want 1/1", generator.calls, len(factory.configs))
	}
}

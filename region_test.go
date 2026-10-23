package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegionConfigProfilesAndPrecedence(t *testing.T) {
	tests := []struct {
		name                 string
		args                 []string
		env                  map[string]string
		web, api, infer, dir string
	}{
		{name: "global default", web: "https://qoder.com", api: "https://openapi.qoder.sh", infer: "https://api2.qoder.sh", dir: filepath.Join(homeDir(), ".qoder", ".auth")},
		{name: "cn flag", args: []string{"-region=cn"}, web: "https://qoder.cn", api: "https://openapi.qoder.com.cn", infer: "https://gateway.qoder.com.cn", dir: filepath.Join(homeDir(), ".qoder-cn", ".auth")},
		{name: "adapter env wins alias", env: map[string]string{"QODER2API_REGION": "cn", "QODER_REGION": "global", "QODERCN_CONFIG_DIR": "/synthetic/cn-root", "QODER_CONFIG_DIR": "/synthetic/global-root"}, web: "https://qoder.cn", api: "https://openapi.qoder.com.cn", infer: "https://gateway.qoder.com.cn", dir: "/synthetic/cn-root/.auth"},
		{name: "alias", env: map[string]string{"QODER_REGION": "cn"}, web: "https://qoder.cn", api: "https://openapi.qoder.com.cn", infer: "https://gateway.qoder.com.cn", dir: filepath.Join(homeDir(), ".qoder-cn", ".auth")},
		{name: "flag wins env", args: []string{"-region=global"}, env: map[string]string{"QODER2API_REGION": "cn", "QODER_CONFIG_DIR": "/synthetic/root"}, web: "https://qoder.com", api: "https://openapi.qoder.sh", infer: "https://api2.qoder.sh", dir: "/synthetic/root/.auth"},
		{name: "auth env is complete directory", args: []string{"-region=cn"}, env: map[string]string{"QODER2API_AUTH_DIR": "/synthetic/auth", "QODERCN_CONFIG_DIR": "/ignored"}, web: "https://qoder.cn", api: "https://openapi.qoder.com.cn", infer: "https://gateway.qoder.com.cn", dir: "/synthetic/auth"},
		{name: "auth flag wins env", args: []string{"-region=cn", "-auth-dir=/synthetic/flag"}, env: map[string]string{"QODER2API_AUTH_DIR": "/ignored"}, web: "https://qoder.cn", api: "https://openapi.qoder.com.cn", infer: "https://gateway.qoder.com.cn", dir: "/synthetic/flag"},
		{name: "endpoint overrides", args: []string{"-region=cn", "-web-endpoint=https://flag.example.test/"}, env: map[string]string{"QODER2API_WEB_ENDPOINT": "https://ignored.example.test", "QODER2API_OPENAPI_ENDPOINT": "http://api.example.test/prefix/", "QODER2API_INFER_ENDPOINT": "https://infer.example.test"}, web: "https://flag.example.test", api: "http://api.example.test/prefix", infer: "https://infer.example.test", dir: filepath.Join(homeDir(), ".qoder-cn", ".auth")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseAppConfig(tt.args, envLookup(tt.env), io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.webEndpoint != tt.web || cfg.openapiEndpoint != tt.api || cfg.inferEndpoint != tt.infer || cfg.authDir != tt.dir {
				t.Fatalf("resolved profile = web %q api %q infer %q dir %q", cfg.webEndpoint, cfg.openapiEndpoint, cfg.inferEndpoint, cfg.authDir)
			}
		})
	}
}

func TestRegionInvalidConfigRejectedWithoutSecrets(t *testing.T) {
	for _, args := range [][]string{
		{"-region=other"}, {"-region="}, {"-endpoint=ftp://host"}, {"-web-endpoint=not-a-url"},
		{"-openapi-endpoint=https://user:synthetic-secret@example.test"},
		{"-endpoint=https://example.test/?token=synthetic-secret"},
		{"-endpoint=https://example.test/#synthetic-secret"},
		{"-endpoint=https://example.test:bad/synthetic-secret"},
		{"-login", "-login-pat=synthetic-secret"}, {"-login", "-login-pat="}, {"-login-pat="},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var output bytes.Buffer
			_, err := parseAppConfig(args, envLookup(nil), &output)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error()+output.String(), "synthetic-secret") {
				t.Fatal("configuration error disclosed secret")
			}
		})
	}
}

func TestRegionValidationWritesUsefulSafeDiagnostic(t *testing.T) {
	var output bytes.Buffer
	_, err := parseAppConfig([]string{"-region=invalid"}, envLookup(nil), &output)
	if err == nil || !strings.Contains(output.String(), "expected global or cn") {
		t.Fatal("invalid region exits without a useful diagnostic")
	}
}

func TestRegionEndpointEnvironmentNeverLeaksThroughHelp(t *testing.T) {
	var output bytes.Buffer
	_, _ = parseAppConfig([]string{"-h"}, envLookup(map[string]string{"QODER2API_OPENAPI_ENDPOINT": "https://user:synthetic-secret@example.test"}), &output)
	if strings.Contains(output.String(), "synthetic-secret") {
		t.Fatal("endpoint credentials leaked through flag defaults")
	}
}

func TestRegionPATSelectionIgnoresOtherRegionAndExplicitLogin(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{nil, "fake-global"}, {[]string{"-region=cn"}, "fake-cn"}, {[]string{"-login", "-region=cn"}, ""}, {[]string{"-login-pat=fake-explicit", "-region=cn"}, ""},
	} {
		cfg, err := parseAppConfig(tt.args, envLookup(map[string]string{"QODER_PERSONAL_ACCESS_TOKEN": "fake-global", "QODERCN_PERSONAL_ACCESS_TOKEN": "fake-cn"}), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.envPAT != tt.want {
			t.Fatal("wrong native PAT selected")
		}
	}
	cfg, err := parseAppConfig([]string{"-region=cn"}, envLookup(map[string]string{"QODER_PERSONAL_ACCESS_TOKEN": "other-region"}), io.Discard)
	if err != nil || cfg.envPAT != "" {
		t.Fatal("consumed other region's PAT")
	}
}

func TestRunRejectsInvalidURLsBeforeInitialization(t *testing.T) {
	for _, endpoint := range []string{"not-a-url", "https://user:synthetic-secret@example.test"} {
		called := false
		err := run(context.Background(), appConfig{inferEndpoint: endpoint}, appDeps{newProtocolServices: func(protocolHostDeps) (*protocolServices, error) { called = true; return nil, nil }}, io.Discard, nil, nil)
		if err == nil || called {
			t.Fatalf("invalid URL initialized services: called=%v err=%v", called, err)
		}
		if strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("run error disclosed secret")
		}
	}
}

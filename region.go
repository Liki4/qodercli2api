package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// regionProfile contains only verified production endpoints and official environment names.
// QODER_REGION is an adapter alias; it is not an official CLI setting.
type regionProfile struct {
	name, web, openapi, infer, configDirEnv, patEnv, root string
}

func resolveRegion(name string) (regionProfile, error) {
	switch name {
	case "global":
		return regionProfile{"global", defaultBase, defaultOpenapi, defaultInfer, "QODER_CONFIG_DIR", "QODER_PERSONAL_ACCESS_TOKEN", ".qoder"}, nil
	case "cn":
		return regionProfile{"cn", "https://qoder.cn", "https://openapi.qoder.com.cn", "https://gateway.qoder.com.cn", "QODERCN_CONFIG_DIR", "QODERCN_PERSONAL_ACCESS_TOKEN", ".qoder-cn"}, nil
	default:
		return regionProfile{}, fmt.Errorf("invalid region: expected global or cn")
	}
}

func normalizeBaseURL(value, label string) (string, error) {
	invalid := func() (string, error) {
		return "", fmt.Errorf("invalid %s: expected an http(s) base URL without credentials, query, or fragment", label)
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
		return invalid()
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") {
		return invalid()
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return invalid()
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return u.String(), nil
}

func (cfg *appConfig) resolveProfile(lookupEnv func(string) (string, bool)) error {
	if cfg.region == "" {
		cfg.region = "global"
	}
	profile, err := resolveRegion(cfg.region)
	if err != nil {
		return err
	}
	if cfg.login && cfg.loginPAT != "" {
		return fmt.Errorf("-login and -login-pat are mutually exclusive")
	}
	if cfg.authDir == "" {
		cfg.authDir = filepath.Join(lookupEnvOr(lookupEnv, profile.configDirEnv, filepath.Join(homeDir(), profile.root)), ".auth")
	}
	endpoints := []struct {
		value           *string
		fallback, label string
	}{
		{&cfg.webEndpoint, profile.web, "web endpoint"}, {&cfg.openapiEndpoint, profile.openapi, "OpenAPI endpoint"}, {&cfg.inferEndpoint, profile.infer, "inference endpoint"},
	}
	for _, endpoint := range endpoints {
		if *endpoint.value == "" {
			*endpoint.value = endpoint.fallback
		}
		normalized, err := normalizeBaseURL(*endpoint.value, endpoint.label)
		if err != nil {
			return err
		}
		*endpoint.value = normalized
	}
	return nil
}

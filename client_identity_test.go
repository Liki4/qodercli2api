package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Return the actual prepared object, not a clone of a seed: the ownership check
// must detect mutations to the object returned by PrepareInferRequest itself.
type identityProtocolContext struct{ prepared *preparedRequest }

func (c *identityProtocolContext) PrepareInferRequest(context.Context, inferRequestInput) (*preparedRequest, error) {
	return c.prepared, nil
}
func (*identityProtocolContext) Close() error { return nil }

func TestDoUpstreamFinalClientIdentity(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(strconv.FormatBool(explicit), func(t *testing.T) {
			headers := http.Header{
				"Cosy-Machinetoken": {"canonical-token"}, "cOsY-MaChInEtOkEn": {"mixed-token"}, "COSY-MACHINETOKEN": {"duplicate-token"},
				"Cosy-Machinetype": {"canonical-type"}, "cOsY-MaChInEtYpE": {"mixed-type"}, "COSY-MACHINETYPE": {"duplicate-type"},
				"Cosy-MachineId": {"synthetic-machine"}, "Authorization": {"unchanged-signature"},
				"X-Unrelated": {"first", "second"}, "Traceparent": {"explicit-unrelated"},
			}
			if explicit {
				headers["cOsY-vErSiOn"] = []string{""}
				headers["COSY-CLIENTTYPE"] = []string{"explicit", "second"}
				headers["cosy-machineos"] = nil
				headers["COSY-VERSION"] = []string{"duplicate"}
			}
			prepared := &preparedRequest{URL: "https://inference.invalid/signed?value=preserved", Header: headers, Body: []byte("prepared-wire-body")}
			before := headers.Clone()
			want := headers.Clone()
			for key := range want {
				if strings.EqualFold(key, "Cosy-MachineToken") || strings.EqualFold(key, "Cosy-MachineType") {
					delete(want, key)
				}
			}
			if !explicit {
				want.Set("Cosy-Version", qoderProtocolVersion)
				want.Set("Cosy-ClientType", defaultProtocolScene().ClientType)
				want.Set("Cosy-MachineOS", expectedRuntimeMachineOS())
			}
			ctx := context.WithValue(context.Background(), identityContextKey{}, "synthetic-context")
			calls := 0
			s := &server{auth: testAuthManager(&identityProtocolContext{prepared}, "https://inference.invalid"), httpc: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if !reflect.DeepEqual(req.Header, want) {
						t.Errorf("final inference headers = %#v, want %#v", req.Header, want)
					}
					body, err := io.ReadAll(req.Body)
					if err != nil || !bytes.Equal(body, prepared.Body) || req.URL.String() != prepared.URL || req.Method != http.MethodPost || req.Context() != ctx {
						t.Error("inference identity changed prepared body, URL, method, or context")
					}
					req.Header["X-Unrelated"][0] = "transport-mutation"
					return fakeJSONResponse(http.StatusOK, `{}`), nil
				}),
			}}
			resp, err := s.doUpstream(ctx, []byte("unprepared-body"), &modelConfig{Key: "auto", Source: "system"})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if calls != 1 || !reflect.DeepEqual(prepared.Header, before) || string(prepared.Body) != "prepared-wire-body" {
				t.Fatal("inference mutated actual prepared object or skipped transport")
			}
		})
	}
}

func TestCommonClientIdentityDefaults(t *testing.T) {
	got := applyCommonClientIdentity(nil)
	want := http.Header{}
	want.Set("Cosy-Version", qoderProtocolVersion)
	want.Set("Cosy-ClientType", "5")
	want.Set("Cosy-MachineOS", expectedRuntimeMachineOS())
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("common defaults = %#v, want %#v", got, want)
	}
	if twice := applyCommonClientIdentity(got); !reflect.DeepEqual(twice, want) {
		t.Fatal("common defaults are not idempotent")
	}
	for _, value := range [][]string{nil, {}, {""}, {"custom", "second"}} {
		headers := http.Header{"cOsY-vErSiOn": value, "COSY-CLIENTTYPE": value, "cosy-machineos": value, "X-Unrelated": {"explicit"}}
		before := headers.Clone()
		if got := applyCommonClientIdentity(headers); !reflect.DeepEqual(got, before) {
			t.Fatal("common defaults overwrote case-insensitive key presence")
		}
	}
}

func TestInferenceClientIdentityCleanup(t *testing.T) {
	if got := applyInferenceClientIdentity(nil); got == nil || len(got) != 0 {
		t.Fatal("inference cleanup must allocate a nil header without inventing identity")
	}
	headers := http.Header{"Cosy-MachineToken": {"token"}, "cOsY-MaChInEtYpE": {"type"}, "Cosy-MachineId": {"keep"}}
	want := http.Header{"Cosy-MachineId": {"keep"}}
	got := applyInferenceClientIdentity(headers)
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(applyInferenceClientIdentity(got), want) {
		t.Fatal("inference cleanup did not omit both fields idempotently")
	}
}

func TestClientMachineOSPortableMapping(t *testing.T) {
	for _, test := range []struct{ os, arch, want string }{
		{"linux", "amd64", "x86_64_linux"},
		{"linux", "arm64", "aarch64_linux"},
		{"darwin", "amd64", "x86_64_macos"},
		{"darwin", "arm64", "aarch64_macos"},
		{"windows", "amd64", "x86_64_windows"},
		{"windows", "386", "x86_windows"},
		{"linux", "arm", "arm_linux"},
		{"freebsd", "riscv64", "riscv64_freebsd"},
	} {
		if got := clientMachineOS(test.os, test.arch); got != test.want {
			t.Errorf("clientMachineOS(%q, %q) = %q, want %q", test.os, test.arch, got, test.want)
		}
	}
}

type identityContextKey struct{}

func expectedRuntimeMachineOS() string {
	arch, osName := runtime.GOARCH, runtime.GOOS
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	case "386":
		arch = "x86"
	}
	if osName == "darwin" {
		osName = "macos"
	}
	return arch + "_" + osName
}

func TestDoAuthRequestCommonClientIdentity(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(strconv.FormatBool(explicit), func(t *testing.T) {
			ctx := context.WithValue(context.Background(), identityContextKey{}, "synthetic-context")
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://issuer.invalid/exchange", strings.NewReader("synthetic-auth-body"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header = nil
			if explicit {
				req.Header = http.Header{
					"cosy-version": {""}, "Cosy-Version": {"duplicate"},
					"COSY-CLIENTTYPE": {"explicit", "second"}, "cOsY-mAcHiNeOs": {},
					"cosy-machinetoken": {"explicit-token"}, "Cosy-MachineType": {"explicit-type"},
					"Authorization": {"synthetic-auth"}, "X-Unrelated": {"first", "second"},
				}
			}
			before := req.Header.Clone()
			bodyBefore := req.Body
			want := before.Clone()
			if !explicit {
				want = http.Header{}
				want.Set("Cosy-Version", qoderProtocolVersion)
				want.Set("Cosy-ClientType", defaultProtocolScene().ClientType)
				want.Set("Cosy-MachineOS", expectedRuntimeMachineOS())
			}
			calls := 0
			a := &authManager{httpc: &http.Client{Transport: roundTripFunc(func(got *http.Request) (*http.Response, error) {
				calls++
				if got == req || !reflect.DeepEqual(got.Header, want) {
					t.Errorf("auth must clone request and apply common identity only: headers=%#v, want=%#v, same_request=%t", got.Header, want, got == req)
				}
				if got.Context() != ctx || got.Body != bodyBefore || got.Method != req.Method || got.URL.String() != req.URL.String() || got.ContentLength != req.ContentLength || got.GetBody == nil {
					t.Error("auth identity changed request context, body, replay, URL, or method")
				}
				body, err := io.ReadAll(got.Body)
				if err != nil || string(body) != "synthetic-auth-body" {
					t.Error("auth body changed")
				}
				replay, err := got.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				defer replay.Close()
				data, _ := io.ReadAll(replay)
				if !bytes.Equal(body, data) {
					t.Error("auth GetBody changed")
				}
				if explicit {
					got.Header["X-Unrelated"][0] = "transport-mutation"
				}
				got.Header.Set("X-Transport", "owned")
				return fakeJSONResponse(http.StatusOK, `{}`), nil
			})}}
			resp, err := a.doAuthRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if calls != 1 || !reflect.DeepEqual(req.Header, before) || req.Body != bodyBefore || req.Context() != ctx {
				t.Fatal("auth mutated caller's request or skipped transport")
			}
		})
	}
}

func TestDoAuthRequestIdentityPreservesRedirectProtection(t *testing.T) {
	for _, location := range []string{"https://other.invalid/leak", "https://issuer.invalid/next"} {
		t.Run(location, func(t *testing.T) {
			calls, checks := 0, 0
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { checks++; return http.ErrUseLastResponse },
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Header.Get("Cosy-Version") != qoderProtocolVersion {
						t.Error("missing common identity on redirected auth request")
					}
					resp := fakeJSONResponse(http.StatusTemporaryRedirect, `{}`)
					resp.Header.Set("Location", location)
					return resp, nil
				}),
			}
			req, _ := http.NewRequest(http.MethodPost, "https://issuer.invalid/start", strings.NewReader("synthetic-token"))
			resp, err := (&authManager{httpc: client}).doAuthRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			wantChecks := 0
			if strings.HasPrefix(location, "https://issuer.invalid/") {
				wantChecks = 1
			}
			if resp.StatusCode != http.StatusTemporaryRedirect || calls != 1 || checks != wantChecks {
				t.Fatal("auth redirect protection or original hook changed")
			}
			if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse || checks != wantChecks+1 {
				t.Fatal("auth modified shared client redirect hook")
			}
		})
	}
}

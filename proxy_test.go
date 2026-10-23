package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type sequenceProtocolContext struct {
	mu       sync.Mutex
	prepared []*preparedRequest
	calls    int
	closes   int
}

func (c *sequenceProtocolContext) PrepareInferRequest(_ context.Context, _ inferRequestInput) (*preparedRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.calls
	c.calls++
	if len(c.prepared) == 0 {
		return nil, nil
	}
	if index >= len(c.prepared) {
		index = len(c.prepared) - 1
	}
	prepared := c.prepared[index]
	return &preparedRequest{URL: prepared.URL, Header: prepared.Header.Clone(), Body: append([]byte(nil), prepared.Body...)}, nil
}

func (c *sequenceProtocolContext) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return nil
}

func (c *sequenceProtocolContext) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func testAuthManager(protoCtx protocolContext, inferBase string) *authManager {
	return &authManager{
		protoCtx:  protoCtx,
		inferBase: inferBase,
		ui: &userInfo{
			UID:                "synthetic-user",
			SecurityOAuthToken: "synthetic-token",
			ExpireTime:         time.Now().Add(2 * time.Hour).Unix(),
		},
		logf: func(string, ...any) {},
	}
}

func resolverTestCatalog() []*modelConfig {
	return []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180000},
		{Key: "ultimate", DisplayName: "Ultimate", MaxInputTokens: 1000000},
		{Key: "efficient", DisplayName: "Efficient", MaxInputTokens: 180000},
		{Key: "qmodel_38max", DisplayName: "Qwen3.8-Max", MaxInputTokens: 1000000},
	}
}

func TestServerHasNoWASMDependency(t *testing.T) {
	if _, ok := reflect.TypeOf(server{}).FieldByName("wasm"); ok {
		t.Fatal("server still has concrete wasm dependency")
	}
}

func TestServerLogUpstreamErrorUsesDiagnosticWithoutChangingReturnedError(t *testing.T) {
	cause := errors.New("synthetic operator diagnostic cause")
	classified := newProtocolError(protocolAuthUnavailable, "Authentication is unavailable", cause)
	returned := fmt.Errorf("prepareInferRequest: %w", classified)
	var logs strings.Builder
	s := &server{logf: func(format string, args ...any) {
		fmt.Fprintf(&logs, format+"\n", args...)
	}}

	s.logUpstreamError("synthetic", returned)
	if !strings.Contains(logs.String(), "prepareInferRequest: Authentication is unavailable") ||
		!strings.Contains(logs.String(), cause.Error()) {
		t.Fatalf("operator log lacks public/internal stages: %q", logs.String())
	}
	if strings.Contains(returned.Error(), cause.Error()) {
		t.Fatalf("returned error leaked internal cause: %q", returned)
	}
}

func TestCallUpstreamPreparesEveryRetryAttempt(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		attempt := len(bodies)
		mu.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"queue":{"isQueued":true,"waitTime":1}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	protoCtx := &sequenceProtocolContext{prepared: []*preparedRequest{
		{URL: upstream.URL, Header: http.Header{"X-Attempt": {"1"}}, Body: []byte("attempt-1")},
		{URL: upstream.URL, Header: http.Header{"X-Attempt": {"2"}}, Body: []byte("attempt-2")},
	}}
	s := &server{auth: testAuthManager(protoCtx, upstream.URL), httpc: upstream.Client(), logf: func(string, ...any) {}}

	resp, err := s.callUpstream(context.Background(), []byte("original"), &modelConfig{Key: "auto", Source: "system"}, "synthetic")
	if err != nil {
		t.Fatalf("callUpstream() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if protoCtx.callCount() != 2 {
		t.Fatalf("PrepareInferRequest() calls = %d, want 2", protoCtx.callCount())
	}
	mu.Lock()
	defer mu.Unlock()
	if want := [][]byte{[]byte("attempt-1"), []byte("attempt-2")}; !reflect.DeepEqual(bodies, want) {
		t.Fatalf("upstream body sequence mismatch: got count %d, want count %d", len(bodies), len(want))
	}
}

type retryRecordingProtocolContext struct {
	inner protocolContext
	mu    sync.Mutex
	calls int
	input []inferRequestInput
}

func (c *retryRecordingProtocolContext) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	c.mu.Lock()
	c.calls++
	c.input = append(c.input, cloneNativeInferRequestInput(input))
	c.mu.Unlock()
	return c.inner.PrepareInferRequest(ctx, input)
}

func (c *retryRecordingProtocolContext) Close() error {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.Close()
}

func (c *retryRecordingProtocolContext) snapshot() (int, []inferRequestInput) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inputs := make([]inferRequestInput, len(c.input))
	for i, input := range c.input {
		inputs[i] = cloneNativeInferRequestInput(input)
	}
	return c.calls, inputs
}

type retryObservedRequest struct {
	body          []byte
	authorization string
	date          string
	modelKey      string
	modelSource   string
}

type retryRequestCapture struct {
	mu             sync.Mutex
	requests       []retryObservedRequest
	successAttempt int
}

func (c *retryRequestCapture) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.requests = append(c.requests, retryObservedRequest{
		body:          append([]byte(nil), body...),
		authorization: r.Header.Get("Authorization"),
		date:          r.Header.Get("Cosy-Date"),
		modelKey:      r.Header.Get("X-Model-Key"),
		modelSource:   r.Header.Get("X-Model-Source"),
	})
	attempt := len(c.requests)
	successAttempt := c.successAttempt
	if successAttempt == 0 {
		successAttempt = 2
	}
	c.mu.Unlock()
	if attempt < successAttempt {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"queue":{"isQueued":true,"waitTime":1}}`))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (c *retryRequestCapture) snapshot() []retryObservedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	requests := make([]retryObservedRequest, len(c.requests))
	for i, request := range c.requests {
		requests[i] = request
		requests[i].body = append([]byte(nil), request.body...)
	}
	return requests
}

func retryNativeConfig() protocolContextConfig {
	return protocolContextConfig{
		MachineID: "00000000-1111-4222-8333-444444444444",
		Version:   qoderProtocolVersion,
		User: protocolUserInfo{
			UID:              "synthetic-retry-user",
			EncryptUserInfo:  "synthetic-retry-info",
			Key:              "synthetic-retry-key",
			OrganizationID:   "synthetic-retry-org",
			OrganizationTags: []string{"synthetic-retry-tag"},
			DataPolicyAgreed: true,
		},
		Scene: defaultProtocolScene(),
	}
}

func retryAttemptEntropy() [][]byte {
	return [][]byte{
		bytes.Repeat([]byte{0x31}, 16),
		bytes.Repeat([]byte{0x42}, 16),
	}
}

func retryAttemptTimes() []int64 {
	return []int64{1_781_000_123_000, 1_781_000_124_000}
}

func retryTranscriptForAttempts(entropy [][]byte, times []int64) protocolTranscript {
	transcript := protocolTranscript{
		UnixMilli:    append([]int64(nil), times...),
		EntropyReads: make([]entropyRead, len(entropy)),
	}
	for i, value := range entropy {
		transcript.EntropyReads[i] = entropyRead{Length: len(value), Bytes: append([]byte(nil), value...)}
	}
	return transcript
}

func retryPrepareOnlyTranscript() protocolTranscript {
	return retryTranscriptForAttempts(retryAttemptEntropy(), retryAttemptTimes())
}

func retryFourAttemptEntropy() [][]byte {
	return [][]byte{
		bytes.Repeat([]byte{0x31}, 16),
		bytes.Repeat([]byte{0x42}, 16),
		bytes.Repeat([]byte{0x53}, 16),
		bytes.Repeat([]byte{0x64}, 16),
	}
}

func retryFourAttemptTimes() []int64 {
	return []int64{1_781_000_123_000, 1_781_000_124_000, 1_781_000_125_000, 1_781_000_126_000}
}

func assertRetryRegeneratesNativePreparation(t *testing.T, requests []retryObservedRequest, rawBody []byte, model *modelConfig, entropy [][]byte, times []int64) {
	t.Helper()
	if len(entropy) != len(times) || len(requests) != len(entropy) {
		t.Fatalf("retry request/entropy/time counts = %d/%d/%d", len(requests), len(entropy), len(times))
	}
	var rawShape struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rawBody, &rawShape); err != nil || rawShape.RequestID == "" {
		t.Fatalf("retry raw body shape invalid: length=%d error type=%T", len(rawBody), err)
	}
	for i, request := range requests {
		decoded, err := (nativeBodyCodec{}).Decode(request.body)
		if err != nil {
			t.Fatalf("retry attempt %d body decode returned kind %q with length %d", i+1, protocolErrorKindOf(err), len(request.body))
		}
		if !bytes.Equal(decoded, rawBody) {
			t.Fatalf("retry attempt %d decoded body mismatch: got length %d want length %d", i+1, len(decoded), len(rawBody))
		}
		var gotShape struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(decoded, &gotShape); err != nil || gotShape.RequestID != rawShape.RequestID {
			t.Fatalf("retry attempt %d internal request ID mismatch: decoded length %d error type=%T", i+1, len(decoded), err)
		}
		payload, _ := nativeInferAuthorizationForTest(t, http.Header{"Authorization": {request.authorization}})
		wantRequestID, err := nativeInferRequestID(entropy[i])
		if err != nil {
			t.Fatalf("retry attempt %d entropy rejected: length=%d", i+1, len(entropy[i]))
		}
		if payload.RequestID != wantRequestID {
			t.Fatalf("retry attempt %d COSY request ID mismatch: got length %d want length %d", i+1, len(payload.RequestID), len(wantRequestID))
		}
		wantDate := strconv.FormatInt(time.UnixMilli(times[i]).Unix(), 10)
		if request.date != wantDate {
			t.Fatalf("retry attempt %d date mismatch: got length %d want length %d", i+1, len(request.date), len(wantDate))
		}
		if request.modelKey != model.Key || request.modelSource != model.Source {
			t.Fatalf("retry attempt %d model header shape mismatch: key/source lengths %d/%d", i+1, len(request.modelKey), len(request.modelSource))
		}
	}
	seenAuthorization := make(map[string]struct{}, len(requests))
	for i, request := range requests {
		if !bytes.Equal(requests[0].body, request.body) {
			t.Fatalf("retry encoded body changed at attempt %d: baseline/current lengths %d/%d", i+1, len(requests[0].body), len(request.body))
		}
		if _, exists := seenAuthorization[request.authorization]; exists {
			t.Fatalf("retry Authorization was reused at attempt %d: length %d", i+1, len(request.authorization))
		}
		seenAuthorization[request.authorization] = struct{}{}
	}
}

func assertRetryRawInputsStable(t *testing.T, recorder *retryRecordingProtocolContext, rawBody []byte, wantAttempts int) {
	t.Helper()
	calls, inputs := recorder.snapshot()
	if calls != wantAttempts || len(inputs) != wantAttempts {
		t.Fatalf("retry Prepare call/input count = %d/%d, want %d/%d", calls, len(inputs), wantAttempts, wantAttempts)
	}
	for i, input := range inputs {
		if !bytes.Equal(input.Body, rawBody) {
			t.Fatalf("retry Prepare input %d body changed: got length %d want length %d", i+1, len(input.Body), len(rawBody))
		}
	}
}

func TestCallUpstreamNativePreparesEveryRetryAndRegeneratesCOSY(t *testing.T) {
	capture := &retryRequestCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer upstream.Close()

	replay := newTranscriptReplay(retryPrepareOnlyTranscript())
	factory := &nativeContextFactory{
		host:          protocolHostDeps{Clock: replay, Entropy: replay},
		runtimeFields: &nativeContextRuntimeGeneratorFake{},
	}
	created, err := factory.New(context.Background(), retryNativeConfig())
	if err != nil {
		t.Fatalf("native retry context New returned kind %q", protocolErrorKindOf(err))
	}
	recorder := &retryRecordingProtocolContext{inner: created}
	model := &modelConfig{Key: "synthetic-model", Source: "system"}
	rawBody := []byte(deterministicFixtureRemoteChatAskBody(t))
	s := &server{auth: testAuthManager(recorder, upstream.URL), httpc: upstream.Client(), logf: func(string, ...any) {}}

	resp, err := s.callUpstream(context.Background(), rawBody, model, "synthetic")
	if err != nil {
		_ = recorder.Close()
		t.Fatalf("native retry callUpstream returned error type %T", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		_ = recorder.Close()
		t.Fatalf("native retry response shape = nil %t status %d", resp == nil, func() int {
			if resp == nil {
				return 0
			}
			return resp.StatusCode
		}())
	}
	_ = resp.Body.Close()
	assertReplayExhausted(t, replay)
	assertRetryRawInputsStable(t, recorder, rawBody, 2)
	assertRetryRegeneratesNativePreparation(t, capture.snapshot(), rawBody, model, retryAttemptEntropy(), retryAttemptTimes())
	if closeErr := recorder.Close(); closeErr != nil {
		t.Fatalf("native retry context Close returned kind %q", protocolErrorKindOf(closeErr))
	}
}

func TestCallUpstreamNativePreparesAllFourAttempts(t *testing.T) {
	capture := &retryRequestCapture{successAttempt: 4}
	upstream := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer upstream.Close()

	entropy := retryFourAttemptEntropy()
	times := retryFourAttemptTimes()
	replay := newTranscriptReplay(retryTranscriptForAttempts(entropy, times))
	factory := &nativeContextFactory{
		host:          protocolHostDeps{Clock: replay, Entropy: replay},
		runtimeFields: &nativeContextRuntimeGeneratorFake{},
	}
	created, err := factory.New(context.Background(), retryNativeConfig())
	if err != nil {
		t.Fatalf("four-attempt native context New returned kind %q", protocolErrorKindOf(err))
	}
	recorder := &retryRecordingProtocolContext{inner: created}
	model := &modelConfig{Key: "synthetic-model", Source: "system"}
	rawBody := []byte(deterministicFixtureRemoteChatAskBody(t))
	s := &server{auth: testAuthManager(recorder, upstream.URL), httpc: upstream.Client(), logf: func(string, ...any) {}}

	resp, err := s.callUpstream(context.Background(), rawBody, model, "synthetic")
	if err != nil {
		_ = recorder.Close()
		t.Fatalf("four-attempt native callUpstream returned error type %T", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		_ = recorder.Close()
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("four-attempt native response shape = nil %t status %d", resp == nil, status)
	}
	_ = resp.Body.Close()
	assertReplayExhausted(t, replay)
	assertRetryRawInputsStable(t, recorder, rawBody, 4)
	assertRetryRegeneratesNativePreparation(t, capture.snapshot(), rawBody, model, entropy, times)
	if closeErr := recorder.Close(); closeErr != nil {
		t.Fatalf("four-attempt native context Close returned kind %q", protocolErrorKindOf(closeErr))
	}
}

func TestDoUpstreamPreservesPreparedBodyAndHeaderValues(t *testing.T) {
	preparedBody := []byte{'a', 0, 0xff, 'z'}
	preparedHeaders := http.Header{"X-Multi": {"first", "second"}}
	var gotBody []byte
	var gotValues []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotValues = append([]string(nil), r.Header.Values("X-Multi")...)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	protoCtx := &sequenceProtocolContext{prepared: []*preparedRequest{{URL: upstream.URL, Header: preparedHeaders, Body: preparedBody}}}
	s := &server{auth: testAuthManager(protoCtx, upstream.URL), httpc: upstream.Client(), logf: func(string, ...any) {}}

	resp, err := s.doUpstream(context.Background(), []byte("original"), &modelConfig{Key: "auto", Source: "system"})
	if err != nil {
		t.Fatalf("doUpstream() error = %v", err)
	}
	resp.Body.Close()
	if !bytes.Equal(gotBody, preparedBody) {
		t.Fatalf("upstream body = %v, want %v", gotBody, preparedBody)
	}
	if !reflect.DeepEqual(gotValues, preparedHeaders.Values("X-Multi")) {
		t.Fatalf("upstream X-Multi values = %q, want %q", gotValues, preparedHeaders.Values("X-Multi"))
	}
}

func TestCallUpstreamPreparesAgainAfterRefresh(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	var bodies [][]byte
	var authValues []string
	mux := http.NewServeMux()
	serverHTTP := httptest.NewServer(mux)
	defer serverHTTP.Close()
	mux.HandleFunc("/api/v1/deviceToken/refresh", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		refreshes++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_token":"synthetic-new-token","refresh_token":"synthetic-new-refresh","expires_in":7200}`))
	})
	mux.HandleFunc("/infer", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		authValues = append(authValues, r.Header.Get("X-Prepared-By"))
		attempt := len(bodies)
		mu.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	oldCtx := &sequenceProtocolContext{prepared: []*preparedRequest{{
		URL: serverHTTP.URL + "/infer", Header: http.Header{"X-Prepared-By": {"old"}}, Body: []byte("old-body"),
	}}}
	newCtx := &sequenceProtocolContext{prepared: []*preparedRequest{{
		URL: serverHTTP.URL + "/infer", Header: http.Header{"X-Prepared-By": {"new"}}, Body: []byte("new-body"),
	}}}
	factory := &fakeProtocolContextFactory{contexts: []protocolContext{newCtx}}
	auth := syntheticAuthManager(t, &authManager{
		protocol: &protocolServices{
			credentials:    &fakeCredentialCodec{encrypted: "synthetic-saved"},
			runtimeFields:  &fakeRuntimeFieldGenerator{output: runtimeFieldOutput{EncryptUserInfo: "new-encrypted", Key: "new-key"}},
			contextFactory: factory,
		},
		protoCtx: oldCtx, authFile: filepath.Join(t.TempDir(), "auth", "user"), machineID: "synthetic-machine",
		openapiBase: serverHTTP.URL, inferBase: serverHTTP.URL + "/infer", httpc: serverHTTP.Client(), logf: func(string, ...any) {},
		ui: &userInfo{
			UID: "synthetic-user", SecurityOAuthToken: "synthetic-old-token", AccessToken: "synthetic-old-token",
			RefreshToken: "synthetic-old-refresh", ExpireTime: time.Now().Add(2 * time.Hour).Unix(),
			EncryptUserInfo: "old-encrypted", Key: "old-key",
		},
	})
	s := &server{auth: auth, httpc: serverHTTP.Client(), logf: func(string, ...any) {}}

	resp, err := s.callUpstream(context.Background(), []byte("original"), &modelConfig{Key: "auto", Source: "system"}, "synthetic")
	if err != nil {
		t.Fatalf("callUpstream() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if refreshes != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshes)
	}
	if oldCtx.callCount() != 1 || newCtx.callCount() != 1 {
		t.Fatalf("prepare calls old/new = %d/%d, want 1/1", oldCtx.callCount(), newCtx.callCount())
	}
	if want := [][]byte{[]byte("old-body"), []byte("new-body")}; !reflect.DeepEqual(bodies, want) {
		t.Fatalf("refreshed upstream body sequence mismatch: got count %d, want count %d", len(bodies), len(want))
	}
	if want := []string{"old", "new"}; !reflect.DeepEqual(authValues, want) {
		t.Fatalf("prepared headers = %q, want %q", authValues, want)
	}
}

func TestModelResolverAcceptsInternalKeysAndDisplayNames(t *testing.T) {
	r := newModelResolver(resolverTestCatalog(), nil, "", "")

	for _, identifier := range []string{"qmodel_38max", "Qwen3.8-Max"} {
		if got := r.resolve(identifier).Key; got != "qmodel_38max" {
			t.Errorf("resolve(%q).Key = %q, want qmodel_38max", identifier, got)
		}
	}
}

func TestModelResolverPreservesMappingPrecedenceAndAcceptsNameTargets(t *testing.T) {
	r := newModelResolver(resolverTestCatalog(), map[string]string{
		"Qwen3.8-Max": "efficient",
		"mapped":      "Qwen3.8-Max",
		"synthetic":   "unknown-target",
		"*":           "auto",
	}, "", "")

	if got := r.resolve("Qwen3.8-Max").Key; got != "efficient" {
		t.Fatalf("exact mapping over display name resolved to %q, want efficient", got)
	}
	if got := r.resolve("mapped").Key; got != "qmodel_38max" {
		t.Fatalf("display-name mapping target resolved to %q, want qmodel_38max", got)
	}
	if got := r.resolve("synthetic"); got.Key != "unknown-target" || got.Source != "system" {
		t.Fatalf("unknown mapping target resolved to %+v, want synthetic unknown-target", got)
	}

	wildcard := newModelResolver(resolverTestCatalog(), map[string]string{"*": "efficient"}, "", "")
	if got := wildcard.resolve("qmodel_38max").Key; got != "efficient" {
		t.Fatalf("wildcard mapping over internal key resolved to %q, want efficient", got)
	}
}

func TestModelResolverDisplayNameSupportsOneMSuffix(t *testing.T) {
	r := newModelResolver(resolverTestCatalog(), nil, "Auto", "Ultimate")

	if got := r.resolve("Efficient[1m]").Key; got != "ultimate" {
		t.Fatalf("Efficient[1m] resolved to %q, want ultimate", got)
	}
	if got := r.resolve("Qwen3.8-Max[1m]").Key; got != "qmodel_38max" {
		t.Fatalf("Qwen3.8-Max[1m] resolved to %q, want qmodel_38max", got)
	}
	if got := r.resolve("unknown").Key; got != "auto" {
		t.Fatalf("display-name default resolved to %q, want auto", got)
	}
}

func TestModelResolverPublicIDAvoidsReservedOneMSuffix(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000},
		{Key: "ultimate", DisplayName: "Ultimate", MaxInputTokens: 1_000_000},
		{Key: "special", DisplayName: "Special[1m]", MaxInputTokens: 180_000},
	}
	r := newModelResolver(catalog, nil, "auto", "ultimate")

	publicID := r.publicID(r.byKey["special"])
	if publicID != "special" {
		t.Fatalf("publicID(special) = %q, want special", publicID)
	}
	if got := r.resolve(publicID).Key; got != "special" {
		t.Errorf("resolve(publicID(special)).Key = %q, want special", got)
	}
}

func TestModelResolverUsesOnlyUnambiguousDisplayNames(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180000},
		{Key: "blank", DisplayName: "   ", MaxInputTokens: 180000},
		{Key: "shared_a", DisplayName: "Shared", MaxInputTokens: 180000},
		{Key: "shared_b", DisplayName: "Shared", MaxInputTokens: 180000},
		{Key: "Alias", DisplayName: "Internal Alias", MaxInputTokens: 180000},
		{Key: "conflict", DisplayName: "Alias", MaxInputTokens: 180000},
		{Key: "qmodel_38max", DisplayName: "Qwen3.8-Max", MaxInputTokens: 1000000},
	}
	r := newModelResolver(catalog, nil, "auto", "ultimate")

	if got := r.resolve("Shared").Key; got != "auto" {
		t.Errorf("ambiguous Shared resolved to %q, want default auto", got)
	}
	if got := r.resolve("Alias").Key; got != "Alias" {
		t.Errorf("internal key Alias resolved to %q, want Alias", got)
	}

	for _, key := range []string{"blank", "shared_a", "shared_b", "conflict"} {
		if got := r.publicID(r.byKey[key]); got != key {
			t.Errorf("publicID(%q) = %q, want key fallback", key, got)
		}
	}
	if got := r.publicID(r.byKey["qmodel_38max"]); got != "Qwen3.8-Max" {
		t.Errorf("publicID(qmodel_38max) = %q, want Qwen3.8-Max", got)
	}
	if got := r.publicID(nil); got != "" {
		t.Errorf("publicID(nil) = %q, want empty string", got)
	}
}

type modelListResponse struct {
	Object string `json:"object"`
	Data   []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		QoderKey    string `json:"qoder_key"`
		MaxTokens   int    `json:"max_tokens"`
	} `json:"data"`
}

func TestHandleModelsReturnsFriendlyStableIDs(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "qmodel_38max", DisplayName: "Qwen3.8-Max", MaxInputTokens: 1_000_000, Enable: true},
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000, Enable: true},
		{Key: "gmodel", DisplayName: "GLM-5.3", MaxInputTokens: 200_000, Enable: true},
	}
	s := &server{models: newModelResolver(catalog, nil, "", "")}
	recorder := httptest.NewRecorder()

	s.handleModels(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response modelListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Object != "list" {
		t.Errorf("object = %q, want list", response.Object)
	}
	var ids []string
	for _, item := range response.Data {
		ids = append(ids, item.ID)
		if item.QoderKey == "" {
			t.Errorf("model %q has empty qoder_key", item.ID)
		}
	}
	if want := []string{"Auto", "GLM-5.3", "Qwen3.8-Max"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	qwen := response.Data[2]
	if qwen.Name != "Qwen3.8-Max" || qwen.DisplayName != "Qwen3.8-Max" {
		t.Errorf("Qwen names = (%q, %q), want Qwen3.8-Max", qwen.Name, qwen.DisplayName)
	}
	if qwen.QoderKey != "qmodel_38max" {
		t.Errorf("Qwen qoder_key = %q, want qmodel_38max", qwen.QoderKey)
	}
	if qwen.MaxTokens != 1_000_000 {
		t.Errorf("Qwen max_tokens = %d, want 1000000", qwen.MaxTokens)
	}
}

func TestHandleModelsFallsBackToKeysForAmbiguousOrEmptyNames(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000, Enable: true},
		{Key: "alpha", DisplayName: "Shared", MaxInputTokens: 180_000, Enable: true},
		{Key: "beta", DisplayName: "Shared", MaxInputTokens: 180_000, Enable: true},
		{Key: "raw", DisplayName: "   ", MaxInputTokens: 180_000, Enable: true},
		{Key: "special", DisplayName: "Special[1m]", MaxInputTokens: 180_000, Enable: true},
	}
	s := &server{models: newModelResolver(catalog, nil, "", "")}
	recorder := httptest.NewRecorder()

	s.handleModels(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response modelListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var ids []string
	for _, item := range response.Data {
		ids = append(ids, item.ID)
		if item.QoderKey == "" {
			t.Errorf("model %q has empty qoder_key", item.ID)
		}
	}
	if want := []string{"Auto", "alpha", "beta", "raw", "special"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	if response.Data[1].ID != "alpha" || response.Data[2].ID != "beta" {
		t.Errorf("ambiguous IDs = (%q, %q), want (alpha, beta)", response.Data[1].ID, response.Data[2].ID)
	}
	raw := response.Data[3]
	if raw.Name != "raw" || raw.DisplayName != "raw" {
		t.Errorf("raw names = (%q, %q), want (raw, raw)", raw.Name, raw.DisplayName)
	}
	special := response.Data[4]
	if special.ID != "special" || special.QoderKey != "special" {
		t.Errorf("special identifiers = (%q, %q), want (special, special)", special.ID, special.QoderKey)
	}
	if special.Name != "Special[1m]" || special.DisplayName != "Special[1m]" {
		t.Errorf("special names = (%q, %q), want (Special[1m], Special[1m])", special.Name, special.DisplayName)
	}
}

func TestHandleModelsExcludesDisabledEntries(t *testing.T) {
	catalog := []*modelConfig{
		{Key: "auto", DisplayName: "Auto", MaxInputTokens: 180_000, Enable: true},
		{Key: "disabled", DisplayName: "Disabled", MaxInputTokens: 180_000},
		{Key: "gmodel", DisplayName: "GLM-5.3", MaxInputTokens: 200_000, Enable: true},
	}
	s := &server{models: newModelResolver(catalog, nil, "", "")}
	recorder := httptest.NewRecorder()

	s.handleModels(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response modelListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var ids []string
	for _, item := range response.Data {
		ids = append(ids, item.ID)
	}
	if want := []string{"Auto", "GLM-5.3"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v (disabled entries must not be advertised)", ids, want)
	}
}

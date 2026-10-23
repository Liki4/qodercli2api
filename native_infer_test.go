package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type nativeInferOrderedHost struct {
	mu          sync.Mutex
	now         time.Time
	entropy     []byte
	entropyErr  error
	clockErr    error
	afterRead   func()
	afterNow    func()
	events      []string
	readLengths []int
}

func (h *nativeInferOrderedHost) Read(dst []byte) error {
	h.mu.Lock()
	h.events = append(h.events, "entropy")
	h.readLengths = append(h.readLengths, len(dst))
	if h.entropyErr != nil {
		err := h.entropyErr
		h.mu.Unlock()
		return err
	}
	if len(h.entropy) != len(dst) {
		h.mu.Unlock()
		return errors.New("synthetic entropy length mismatch")
	}
	copy(dst, h.entropy)
	afterRead := h.afterRead
	h.mu.Unlock()
	if afterRead != nil {
		afterRead()
	}
	return nil
}

func (h *nativeInferOrderedHost) Now() (time.Time, error) {
	h.mu.Lock()
	h.events = append(h.events, "clock")
	if h.clockErr != nil {
		err := h.clockErr
		h.mu.Unlock()
		return time.Time{}, err
	}
	now := h.now
	afterNow := h.afterNow
	h.mu.Unlock()
	if afterNow != nil {
		afterNow()
	}
	return now, nil
}

func (h *nativeInferOrderedHost) transcriptShape() ([]string, []int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...), append([]int(nil), h.readLengths...)
}

func syntheticNativeInferSnapshot(host protocolHostDeps) nativeContextSnapshot {
	return nativeContextSnapshot{
		host:      host,
		bodyCodec: nativeBodyCodec{},
		machineID: "00000000-1111-4222-8333-444444444444",
		version:   qoderProtocolVersion,
		user: protocolUserInfo{
			UID:              "synthetic-user",
			EncryptUserInfo:  "synthetic-info",
			Key:              "synthetic-key",
			OrganizationID:   "",
			OrganizationTags: []string{},
			DataPolicyAgreed: false,
		},
		scene: defaultProtocolScene(),
	}
}

func syntheticNativeInferInput() inferRequestInput {
	return inferRequestInput{
		Endpoint:    "https://example.invalid/base?existing=1",
		Body:        []byte(`{"synthetic":true}`),
		ModelKey:    "synthetic-model",
		ModelSource: "custom",
	}
}

type nativeInferPerturbationVector struct {
	name              string
	field             string
	unixMilli         int64
	entropy           []byte
	mutateConfig      func(*protocolContextConfig)
	mutateInput       func(*inferRequestInput)
	wantSignature     string
	wantURLChanged    bool
	wantBodyChanged   bool
	wantHeaderChanges []string
}

func nativeInferPerturbationVectors() []nativeInferPerturbationVector {
	return []nativeInferPerturbationVector{
		{
			name:  "endpoint",
			field: "endpoint",
			mutateInput: func(input *inferRequestInput) {
				input.Endpoint = "https://example.invalid/base?existing=1#fragment"
			},
			wantSignature:  "3fed36d7af23e12c33c2a81e93c553ad",
			wantURLChanged: true,
		},
		{
			name:  "model key",
			field: "model-key",
			mutateInput: func(input *inferRequestInput) {
				input.ModelKey = "synthetic-model-alt"
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"X-Model-Key"},
		},
		{
			name:  "model source",
			field: "model-source",
			mutateInput: func(input *inferRequestInput) {
				input.ModelSource = "custom"
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"X-Model-Source"},
		},
		{
			name:  "policy",
			field: "data-policy",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.DataPolicyAgreed = false
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"Cosy-Data-Policy"},
		},
		{
			name:  "organization ID",
			field: "organization-id",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.OrganizationID = "synthetic-org-alt"
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"Cosy-Organization-Id"},
		},
		{
			name:  "tag order",
			field: "organization-tags",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.OrganizationTags = []string{"synthetic-b", "synthetic-a"}
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"Cosy-Organization-Tags"},
		},
		{
			name:  "scene",
			field: "scene",
			mutateConfig: func(config *protocolContextConfig) {
				config.Scene.Scene = "synthetic-scene-alt"
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"Cosy-Scene"},
		},
		{
			name:  "machine ID",
			field: "machine-id",
			mutateConfig: func(config *protocolContextConfig) {
				config.MachineID = "11111111-2222-4333-8444-555555555555"
			},
			wantSignature:     "3fed36d7af23e12c33c2a81e93c553ad",
			wantHeaderChanges: []string{"Cosy-MachineId", "Cosy-MachineToken"},
		},
		{
			name:  "context version",
			field: "context-version",
			mutateConfig: func(config *protocolContextConfig) {
				config.Version = "9.8.7-synthetic"
			},
			wantSignature:     "9649e4cd8cd4cd978dc642f4a9202ffe",
			wantHeaderChanges: []string{"Authorization", "Cosy-Version"},
		},
		{
			name:  "encrypted user info",
			field: "encrypted-user-info",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.EncryptUserInfo = "synthetic-info-alt"
			},
			wantSignature:     "baf3c1f6a5eb5c435349879c3659207c",
			wantHeaderChanges: []string{"Authorization"},
		},
		{
			name:  "RSA key",
			field: "runtime-key",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.Key = "synthetic-key-alt"
			},
			wantSignature:     "f68f5f4b6e57ba2624e77c158e15d453",
			wantHeaderChanges: []string{"Authorization", "Cosy-Key"},
		},
		{
			name:  "one body byte",
			field: "body-byte",
			mutateInput: func(input *inferRequestInput) {
				input.Body[len(input.Body)/2] ^= 0x01
			},
			wantSignature:     "e41fd73c7ed8eebdf4f27ee3fe172c26",
			wantBodyChanged:   true,
			wantHeaderChanges: []string{"Authorization"},
		},
		{
			name:          "clock 1781000123000",
			field:         "clock",
			unixMilli:     1_781_000_123_000,
			wantSignature: "3fed36d7af23e12c33c2a81e93c553ad",
		},
		{
			name:          "clock 1781000123999",
			field:         "clock",
			unixMilli:     1_781_000_123_999,
			wantSignature: "3fed36d7af23e12c33c2a81e93c553ad",
		},
		{
			name:              "request entropy",
			field:             "request-entropy",
			entropy:           []byte{0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
			wantSignature:     "15620fc0a3f66522049b4c805f527e5d",
			wantHeaderChanges: []string{"Authorization"},
		},
	}
}

func nativeInferVectorConfig() protocolContextConfig {
	// These signature vectors were captured from the historical oracle.
	return protocolContextConfig{
		MachineID: "00000000-1111-4222-8333-444444444444",
		Version:   protocolFixtureIdentity.Version,
		User: protocolUserInfo{
			UID:              "synthetic-vector-user",
			EncryptUserInfo:  "synthetic-vector-info",
			Key:              "synthetic-vector-key",
			OrganizationID:   "synthetic-vector-org",
			OrganizationTags: []string{"synthetic-a", "synthetic-b"},
			DataPolicyAgreed: true,
		},
		Scene: defaultProtocolScene(),
	}
}

func nativeInferVectorInput() inferRequestInput {
	return inferRequestInput{
		Endpoint:    "https://example.invalid/vector",
		Body:        []byte(`{"vector":"baseline","unicode":"雪"}`),
		ModelKey:    "synthetic-model",
		ModelSource: "system",
	}
}

func nativeInferVectorEntropy() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
}

func nativeInferVectorNewTranscript() protocolTranscript {
	return protocolTranscript{EntropyReads: []entropyRead{
		{Length: 16, Bytes: bytes.Repeat([]byte{0x11}, 16)},
		{Length: 109, Bytes: bytes.Repeat([]byte{0x22}, 109)},
	}}
}

func nativeInferVectorPrepareTranscript(unixMilli int64, entropy []byte) protocolTranscript {
	return protocolTranscript{
		UnixMilli: []int64{unixMilli},
		EntropyReads: []entropyRead{{
			Length: 16,
			Bytes:  append([]byte(nil), entropy...),
		}},
	}
}

func prepareNativeInferVectorWithFactory(t *testing.T, factory protocolContextFactory, config protocolContextConfig, input inferRequestInput, unixMilli int64, entropy []byte) *preparedRequest {
	t.Helper()
	newReplay := newTranscriptReplay(nativeInferVectorNewTranscript())
	newCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: newReplay, Entropy: newReplay})
	protocolCtx, err := factory.New(newCtx, cloneNativeContextConfig(config))
	if err != nil {
		t.Fatalf("vector context New returned kind %q", protocolErrorKindOf(err))
	}
	assertReplayExhausted(t, newReplay)

	prepareReplay := newTranscriptReplay(nativeInferVectorPrepareTranscript(unixMilli, entropy))
	prepareCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: prepareReplay, Entropy: prepareReplay})
	prepared, err := protocolCtx.PrepareInferRequest(prepareCtx, cloneNativeInferRequestInput(input))
	if err != nil {
		_ = protocolCtx.Close()
		t.Fatalf("vector PrepareInferRequest returned kind %q", protocolErrorKindOf(err))
	}
	assertReplayExhausted(t, prepareReplay)
	if closeErr := protocolCtx.Close(); closeErr != nil {
		t.Fatalf("vector context close returned kind %q", protocolErrorKindOf(closeErr))
	}
	if prepared == nil {
		t.Fatal("vector PrepareInferRequest returned nil")
	}
	return prepared
}

func assertNativeInferPreparedExact(t *testing.T, got, want *preparedRequest) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("prepared request nil mismatch: got nil=%t want nil=%t", got == nil, want == nil)
	}
	if got.URL != want.URL {
		t.Fatalf("prepared URL mismatch: got length %d, want length %d", len(got.URL), len(want.URL))
	}
	if !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("prepared body mismatch: got length %d, want length %d", len(got.Body), len(want.Body))
	}
	assertNativeInferHeaderSet(t, got.Header, want.Header)
}

func nativeInferHeaderDifferenceNames(left, right http.Header) []string {
	canonicalize := func(header http.Header) map[string][]string {
		result := make(map[string][]string, len(header))
		for name, values := range header {
			canonical := http.CanonicalHeaderKey(name)
			result[canonical] = append(result[canonical], values...)
		}
		return result
	}
	leftValues := canonicalize(left)
	rightValues := canonicalize(right)
	names := make(map[string]struct{}, len(leftValues)+len(rightValues))
	for name := range leftValues {
		names[name] = struct{}{}
	}
	for name := range rightValues {
		names[name] = struct{}{}
	}
	var different []string
	for name := range names {
		if !reflect.DeepEqual(leftValues[name], rightValues[name]) {
			different = append(different, name)
		}
	}
	sort.Strings(different)
	return different
}

func assertNativeInferDocumentedChanges(t *testing.T, baseline, got *preparedRequest, vector nativeInferPerturbationVector) {
	t.Helper()
	if (baseline.URL != got.URL) != vector.wantURLChanged {
		t.Fatalf("vector %q field %q URL change mismatch: baseline length %d got length %d", vector.name, vector.field, len(baseline.URL), len(got.URL))
	}
	if (!bytes.Equal(baseline.Body, got.Body)) != vector.wantBodyChanged {
		t.Fatalf("vector %q field %q body change mismatch: baseline length %d got length %d", vector.name, vector.field, len(baseline.Body), len(got.Body))
	}
	wantHeaders := make([]string, len(vector.wantHeaderChanges))
	for i, name := range vector.wantHeaderChanges {
		wantHeaders[i] = http.CanonicalHeaderKey(name)
	}
	sort.Strings(wantHeaders)
	gotHeaders := nativeInferHeaderDifferenceNames(baseline.Header, got.Header)
	if !slices.Equal(gotHeaders, wantHeaders) {
		t.Fatalf("vector %q field %q header changes mismatch: got names %v want names %v", vector.name, vector.field, gotHeaders, wantHeaders)
	}
}

func nativeInferAuthorizationForTest(t *testing.T, header http.Header) (cosyAuthorizationPayloadForTest, string) {
	t.Helper()
	authorization := header.Get("Authorization")
	const prefix = "Bearer COSY."
	if !strings.HasPrefix(authorization, prefix) {
		t.Fatalf("Authorization prefix mismatch: length=%d", len(authorization))
	}
	parts := strings.Split(strings.TrimPrefix(authorization, prefix), ".")
	if len(parts) != 2 {
		t.Fatalf("Authorization shape mismatch: parts=%d length=%d", len(parts), len(authorization))
	}
	payloadRaw, err := decodeStrictStdBase64(parts[0])
	if err != nil {
		t.Fatalf("Authorization payload encoding mismatch: encoded length=%d", len(parts[0]))
	}
	var payload cosyAuthorizationPayloadForTest
	decodeExactJSON(t, payloadRaw, &payload)
	if len(parts[1]) != 32 {
		t.Fatalf("Authorization signature length=%d, want 32", len(parts[1]))
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		t.Fatalf("Authorization signature encoding mismatch: length=%d", len(parts[1]))
	}
	return payload, parts[1]
}

func TestNativeInferPerturbationSignatureVectors(t *testing.T) {
	vectors := nativeInferPerturbationVectors()
	if len(vectors) != 15 {
		t.Fatalf("perturbation vector count = %d, want 15", len(vectors))
	}
	seenNames := make(map[string]struct{}, len(vectors))
	for _, vector := range vectors {
		if vector.name == "" || vector.field == "" || vector.wantSignature == "" {
			t.Fatalf("perturbation vector metadata is incomplete: name/field/signature lengths %d/%d/%d", len(vector.name), len(vector.field), len(vector.wantSignature))
		}
		if _, exists := seenNames[vector.name]; exists {
			t.Fatalf("perturbation vector name is duplicated: length=%d", len(vector.name))
		}
		seenNames[vector.name] = struct{}{}
	}

	nativeFactory := &nativeContextFactory{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: &fixtureEntropy{}}}

	const baselineUnixMilli = int64(1_781_000_123_456)
	baselineEntropy := nativeInferVectorEntropy()
	baselineConfig := nativeInferVectorConfig()
	baselineInput := nativeInferVectorInput()
	baselineNative := prepareNativeInferVectorWithFactory(t, nativeFactory, baselineConfig, baselineInput, baselineUnixMilli, baselineEntropy)

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			if vector.wantSignature == "" {
				t.Fatalf("vector %q field %q lacks pinned signature", vector.name, vector.field)
			}
			config := cloneNativeContextConfig(baselineConfig)
			input := cloneNativeInferRequestInput(baselineInput)
			if vector.mutateConfig != nil {
				vector.mutateConfig(&config)
			}
			if vector.mutateInput != nil {
				vector.mutateInput(&input)
			}
			unixMilli := baselineUnixMilli
			if vector.unixMilli != 0 {
				unixMilli = vector.unixMilli
			}
			entropy := baselineEntropy
			if vector.entropy != nil {
				entropy = vector.entropy
			}

			nativePrepared := prepareNativeInferVectorWithFactory(t, nativeFactory, config, input, unixMilli, entropy)

			payload, signature := nativeInferAuthorizationForTest(t, nativePrepared.Header)
			if signature != vector.wantSignature {
				t.Fatalf("vector %q field %q signature mismatch: got length %d want length %d", vector.name, vector.field, len(signature), len(vector.wantSignature))
			}
			wantRequestID, err := nativeInferRequestID(entropy)
			if err != nil {
				t.Fatalf("vector %q field %q request ID input rejected: entropy length=%d", vector.name, vector.field, len(entropy))
			}
			if payload.Version != "v1" || payload.IDEVersion != "" || payload.RequestID != wantRequestID || payload.Info != config.User.EncryptUserInfo || payload.CosyVersion != config.Version {
				t.Fatalf("vector %q field %q payload component mismatch: payload length=%d", vector.name, vector.field, len(nativePrepared.Header.Get("Authorization")))
			}
			assertNativeInferDocumentedChanges(t, baselineNative, nativePrepared, vector)
		})
	}
}

func TestNativeInferPrepareHostCallOrder(t *testing.T) {
	factory := &nativeContextFactory{host: validNativeContextHost()}
	newReplay := newTranscriptReplay(nativeInferVectorNewTranscript())
	newCtx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: newReplay, Entropy: newReplay})
	created, err := factory.New(newCtx, nativeInferVectorConfig())
	if err != nil {
		t.Fatalf("WASM order characterization New returned kind %q", protocolErrorKindOf(err))
	}
	defer func() { _ = created.Close() }()
	assertReplayExhausted(t, newReplay)

	host := &nativeInferOrderedHost{
		now:     time.UnixMilli(1_781_000_123_456),
		entropy: nativeInferVectorEntropy(),
	}
	ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: host, Entropy: host})
	prepared, err := created.PrepareInferRequest(ctx, nativeInferVectorInput())
	if err != nil || prepared == nil {
		t.Fatalf("WASM order characterization Prepare returned result=%t kind=%q", prepared != nil, protocolErrorKindOf(err))
	}
	events, readLengths := host.transcriptShape()
	if !reflect.DeepEqual(events, []string{"clock", "entropy"}) || !reflect.DeepEqual(readLengths, []int{16}) {
		t.Fatalf("WASM Prepare host order = events %v read lengths %v, want clock then entropy", events, readLengths)
	}
}

func TestNativeInferRejectsNilOrganizationTags(t *testing.T) {
	factory := &nativeContextFactory{host: validNativeContextHost()}
	config := nativeInferVectorConfig()
	config.User.OrganizationTags = nil
	recorder := newTranscriptRecorder(protocolHostDeps{Clock: fixtureClock{}, Entropy: &fixtureEntropy{}})
	ctx := withProtocolHostDeps(context.Background(), protocolHostDeps{Clock: recorder, Entropy: recorder})

	created, err := factory.New(ctx, config)
	if created != nil {
		_ = created.Close()
		t.Fatal("WASM accepted nil organization tags")
	}
	if err == nil || protocolErrorKindOf(err) != protocolBackendFailure {
		t.Fatalf("WASM nil-tag error kind = %q, want %q", protocolErrorKindOf(err), protocolBackendFailure)
	}
	transcript := recorder.Transcript()
	if len(transcript.UnixMilli) != 0 || len(transcript.EntropyReads) != 0 {
		t.Fatalf("WASM nil-tag rejection transcript shape = clock %d entropy %d", len(transcript.UnixMilli), len(transcript.EntropyReads))
	}
}

func TestNativeInferConditionalHeaderMatrix(t *testing.T) {
	nativeFactory := &nativeContextFactory{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: &fixtureEntropy{}}}
	baseConfig := nativeInferVectorConfig()
	baseInput := nativeInferVectorInput()
	entropy := nativeInferVectorEntropy()
	const unixMilli = int64(1_781_000_123_456)
	baseline := prepareNativeInferVectorWithFactory(t, nativeFactory, baseConfig, baseInput, unixMilli, entropy)
	if len(baseline.Header) != 22 {
		t.Fatalf("complete native header cardinality = %d, want 22", len(baseline.Header))
	}

	tests := []struct {
		name          string
		mutateConfig  func(*protocolContextConfig)
		mutateInput   func(*inferRequestInput)
		missingHeader []string
		setHeader     map[string]string
	}{
		{
			name: "organization empty tags empty",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.OrganizationID = ""
				config.User.OrganizationTags = []string{}
			},
			missingHeader: []string{"Cosy-Organization-Id", "Cosy-Organization-Tags"},
		},
		{
			name: "organization nonempty tags empty",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.OrganizationTags = []string{}
			},
			missingHeader: []string{"Cosy-Organization-Tags"},
		},
		{
			name: "organization empty tags nonempty",
			mutateConfig: func(config *protocolContextConfig) {
				config.User.OrganizationID = ""
			},
			missingHeader: []string{"Cosy-Organization-Id"},
		},
		{
			name: "organization nonempty tags nonempty",
		},
		{
			name: "model key empty source nonempty",
			mutateInput: func(input *inferRequestInput) {
				input.ModelKey = ""
			},
			missingHeader: []string{"X-Model-Key", "X-Model-Source"},
		},
		{
			name: "model key nonempty source empty",
			mutateInput: func(input *inferRequestInput) {
				input.ModelSource = ""
			},
			setHeader: map[string]string{"X-Model-Source": ""},
		},
		{
			name: "model key empty source empty",
			mutateInput: func(input *inferRequestInput) {
				input.ModelKey = ""
				input.ModelSource = ""
			},
			missingHeader: []string{"X-Model-Key", "X-Model-Source"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := cloneNativeContextConfig(baseConfig)
			input := cloneNativeInferRequestInput(baseInput)
			if tt.mutateConfig != nil {
				tt.mutateConfig(&config)
			}
			if tt.mutateInput != nil {
				tt.mutateInput(&input)
			}
			got := prepareNativeInferVectorWithFactory(t, nativeFactory, config, input, unixMilli, entropy)
			want := &preparedRequest{URL: baseline.URL, Header: baseline.Header.Clone(), Body: append([]byte(nil), baseline.Body...)}
			for name, value := range tt.setHeader {
				want.Header.Set(name, value)
			}
			for _, name := range tt.missingHeader {
				want.Header.Del(name)
			}
			if len(got.Header) != 22-len(tt.missingHeader) {
				t.Fatalf("conditional WASM header cardinality = %d, want %d, differing names %v", len(got.Header), 22-len(tt.missingHeader), nativeInferHeaderDifferenceNames(got.Header, baseline.Header))
			}
			assertNativeInferPreparedExact(t, got, want)
		})
	}
}

func TestNativeInferDeterministicCorpus(t *testing.T) {
	_, fixture := loadProtocolFixture(t, "infer-user.json")
	var fixtureInput inferFixtureInput
	decodeExactJSON(t, fixture.Input, &fixtureInput)

	baseConfig := nativeInferVectorConfig()
	baseInput := nativeInferVectorInput()
	longBody := []byte(`{"system":"` + strings.Repeat("long-system-", 512) + `","tools":[{"type":"function","function":{"name":"synthetic_long_tool","description":"` + strings.Repeat("tool-description-", 256) + `"}}]}`)
	tests := []struct {
		name      string
		config    protocolContextConfig
		input     inferRequestInput
		unixMilli int64
		entropy   []byte
	}{
		{
			name: "official fixture input",
			config: protocolContextConfig{
				MachineID: fixtureInput.MachineID,
				Version:   fixtureInput.Version,
				User:      cloneNativeProtocolUserInfo(fixtureInput.User),
				Scene:     cloneNativeProtocolScene(fixtureInput.Scene),
			},
			input: inferRequestInput{
				Endpoint:    fixtureInput.Endpoint,
				Body:        []byte(fixtureInput.BodyRaw),
				ModelKey:    fixtureInput.ModelKey,
				ModelSource: fixtureInput.ModelSource,
			},
			unixMilli: protocolFixtureUnixMilli,
			entropy:   nativeInferVectorEntropy(),
		},
		{name: "empty body", config: cloneNativeContextConfig(baseConfig), input: inferRequestInput{Endpoint: baseInput.Endpoint, Body: []byte{}, ModelKey: baseInput.ModelKey, ModelSource: baseInput.ModelSource}, unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "real RemoteChatAsk", config: cloneNativeContextConfig(baseConfig), input: inferRequestInput{Endpoint: baseInput.Endpoint, Body: []byte(deterministicFixtureRemoteChatAskBody(t)), ModelKey: baseInput.ModelKey, ModelSource: baseInput.ModelSource}, unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "Unicode body", config: cloneNativeContextConfig(baseConfig), input: inferRequestInput{Endpoint: baseInput.Endpoint, Body: []byte(`{"message":"雪と星","emoji":"☃"}`), ModelKey: baseInput.ModelKey, ModelSource: baseInput.ModelSource}, unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "long system tool JSON", config: cloneNativeContextConfig(baseConfig), input: inferRequestInput{Endpoint: baseInput.Endpoint, Body: longBody, ModelKey: baseInput.ModelKey, ModelSource: baseInput.ModelSource}, unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "model source custom", config: cloneNativeContextConfig(baseConfig), input: inferRequestInput{Endpoint: baseInput.Endpoint, Body: cloneNativeInferRequestInput(baseInput).Body, ModelKey: baseInput.ModelKey, ModelSource: "custom"}, unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "model source system", config: cloneNativeContextConfig(baseConfig), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "empty organization and empty tags", config: func() protocolContextConfig {
			config := cloneNativeContextConfig(baseConfig)
			config.User.OrganizationID = ""
			config.User.OrganizationTags = []string{}
			return config
		}(), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "policy false", config: func() protocolContextConfig {
			config := cloneNativeContextConfig(baseConfig)
			config.User.DataPolicyAgreed = false
			return config
		}(), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "UID perturbation", config: func() protocolContextConfig {
			config := cloneNativeContextConfig(baseConfig)
			config.User.UID = "synthetic-vector-user-alt"
			return config
		}(), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "client type perturbation", config: func() protocolContextConfig {
			config := cloneNativeContextConfig(baseConfig)
			config.Scene.ClientType = "synthetic-client-alt"
			return config
		}(), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "business product perturbation", config: func() protocolContextConfig {
			config := cloneNativeContextConfig(baseConfig)
			config.Scene.BusinessProduct = "synthetic-product-alt"
			return config
		}(), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "business type perturbation", config: func() protocolContextConfig {
			config := cloneNativeContextConfig(baseConfig)
			config.Scene.BusinessType = "synthetic-business-alt"
			return config
		}(), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "millisecond end", config: cloneNativeContextConfig(baseConfig), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_123_999, entropy: nativeInferVectorEntropy()},
		{name: "next second", config: cloneNativeContextConfig(baseConfig), input: cloneNativeInferRequestInput(baseInput), unixMilli: 1_781_000_124_000, entropy: nativeInferVectorEntropy()},
		{name: "empty endpoint", config: cloneNativeContextConfig(baseConfig), input: func() inferRequestInput {
			input := cloneNativeInferRequestInput(baseInput)
			input.Endpoint = ""
			return input
		}(), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "trailing slash endpoint", config: cloneNativeContextConfig(baseConfig), input: func() inferRequestInput {
			input := cloneNativeInferRequestInput(baseInput)
			input.Endpoint += "/"
			return input
		}(), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "existing query endpoint", config: cloneNativeContextConfig(baseConfig), input: func() inferRequestInput {
			input := cloneNativeInferRequestInput(baseInput)
			input.Endpoint += "?old=1"
			return input
		}(), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
		{name: "fragment endpoint", config: cloneNativeContextConfig(baseConfig), input: func() inferRequestInput {
			input := cloneNativeInferRequestInput(baseInput)
			input.Endpoint += "#fragment"
			return input
		}(), unixMilli: 1_781_000_123_456, entropy: nativeInferVectorEntropy()},
	}

	nativeFactory := &nativeContextFactory{host: protocolHostDeps{Clock: fixtureClock{}, Entropy: &fixtureEntropy{}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := prepareNativeInferVectorWithFactory(t, nativeFactory, tt.config, tt.input, tt.unixMilli, tt.entropy)
			second := prepareNativeInferVectorWithFactory(t, nativeFactory, tt.config, tt.input, tt.unixMilli, tt.entropy)
			assertNativeInferPreparedExact(t, first, second)
		})
	}
}

func TestNativeInferPrepareValidatesDependenciesAuthAndInput(t *testing.T) {
	entropy, err := base64.StdEncoding.DecodeString("fn+AgYKDhIWGh4iJiouMjQ==")
	if err != nil {
		t.Fatalf("decode synthetic validation entropy: length=%d", len(entropy))
	}

	tests := []struct {
		name       string
		kind       protocolErrorKind
		mutateHost func(*protocolHostDeps)
		mutateSnap func(*nativeContextSnapshot)
		mutateIn   func(*inferRequestInput)
	}{
		{
			name: "missing clock",
			kind: protocolBackendFailure,
			mutateHost: func(host *protocolHostDeps) {
				host.Clock = nil
			},
		},
		{
			name: "missing entropy",
			kind: protocolBackendFailure,
			mutateHost: func(host *protocolHostDeps) {
				host.Entropy = nil
			},
		},
		{
			name: "missing encrypted user info",
			kind: protocolAuthUnavailable,
			mutateSnap: func(snapshot *nativeContextSnapshot) {
				snapshot.user.EncryptUserInfo = ""
			},
		},
		{
			name: "missing runtime key",
			kind: protocolAuthUnavailable,
			mutateSnap: func(snapshot *nativeContextSnapshot) {
				snapshot.user.Key = ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostProbe := &nativeInferOrderedHost{now: time.UnixMilli(1781000123999), entropy: entropy}
			host := protocolHostDeps{Clock: hostProbe, Entropy: hostProbe}
			if tt.mutateHost != nil {
				tt.mutateHost(&host)
			}
			snapshot := syntheticNativeInferSnapshot(host)
			if tt.mutateSnap != nil {
				tt.mutateSnap(&snapshot)
			}
			input := syntheticNativeInferInput()
			if tt.mutateIn != nil {
				tt.mutateIn(&input)
			}

			got, err := prepareNativeInferRequest(context.Background(), snapshot, input)
			if got != nil {
				t.Fatal("invalid native prepare input returned a request")
			}
			if err == nil || protocolErrorKindOf(err) != tt.kind {
				t.Fatalf("validation error kind = %q, want %q", protocolErrorKindOf(err), tt.kind)
			}
			events, readLengths := hostProbe.transcriptShape()
			if len(events) != 0 || len(readLengths) != 0 {
				t.Fatalf("validation failure consumed host transcript: events=%v read lengths=%v", events, readLengths)
			}
		})
	}
}

func TestNativeInferPrepareCancellationAndHostFailuresAreSafe(t *testing.T) {
	entropy, err := base64.StdEncoding.DecodeString("fn+AgYKDhIWGh4iJiouMjQ==")
	if err != nil {
		t.Fatalf("decode synthetic failure entropy: length=%d", len(entropy))
	}

	t.Run("canceled before body or host work", func(t *testing.T) {
		host := &nativeInferOrderedHost{now: time.UnixMilli(1781000123999), entropy: entropy}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := prepareNativeInferRequest(ctx, syntheticNativeInferSnapshot(protocolHostDeps{Clock: host, Entropy: host}), syntheticNativeInferInput())
		if got != nil {
			t.Fatal("canceled native prepare returned a request")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled native prepare error type = %T", err)
		}
		events, readLengths := host.transcriptShape()
		if len(events) != 0 || len(readLengths) != 0 {
			t.Fatalf("canceled native prepare consumed host transcript: events=%v read lengths=%v", events, readLengths)
		}
	})

	t.Run("canceled after entropy consumes no later work", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		host := &nativeInferOrderedHost{
			now:       time.UnixMilli(1781000123999),
			entropy:   entropy,
			afterRead: cancel,
		}
		got, err := prepareNativeInferRequest(ctx, syntheticNativeInferSnapshot(protocolHostDeps{Clock: host, Entropy: host}), syntheticNativeInferInput())
		if got != nil {
			t.Fatal("post-entropy cancellation returned a request")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("post-entropy cancellation error type = %T", err)
		}
		events, readLengths := host.transcriptShape()
		if !reflect.DeepEqual(events, []string{"clock", "entropy"}) || !reflect.DeepEqual(readLengths, []int{16}) {
			t.Fatalf("post-entropy cancellation transcript shape mismatch: events=%v read lengths=%v", events, readLengths)
		}
	})

	t.Run("canceled after clock returns no request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		host := &nativeInferOrderedHost{
			now:      time.UnixMilli(1781000123999),
			entropy:  entropy,
			afterNow: cancel,
		}
		got, err := prepareNativeInferRequest(ctx, syntheticNativeInferSnapshot(protocolHostDeps{Clock: host, Entropy: host}), syntheticNativeInferInput())
		if got != nil {
			t.Fatal("post-clock cancellation returned a request")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("post-clock cancellation error type = %T", err)
		}
		events, readLengths := host.transcriptShape()
		if !reflect.DeepEqual(events, []string{"clock"}) || len(readLengths) != 0 {
			t.Fatalf("post-clock cancellation transcript shape mismatch: events=%v read lengths=%v", events, readLengths)
		}
	})

	t.Run("entropy failure follows clock and is safe", func(t *testing.T) {
		const sentinel = "SENTINEL-NATIVE-INFER-ENTROPY"
		host := &nativeInferOrderedHost{
			now:        time.UnixMilli(1781000123999),
			entropy:    entropy,
			entropyErr: errors.New("synthetic entropy failure containing " + sentinel),
		}
		got, err := prepareNativeInferRequest(context.Background(), syntheticNativeInferSnapshot(protocolHostDeps{Clock: host, Entropy: host}), syntheticNativeInferInput())
		if got != nil {
			t.Fatal("entropy failure returned a request")
		}
		if err == nil || protocolErrorKindOf(err) != protocolEntropyFailure {
			t.Fatalf("entropy failure kind = %q, want %q", protocolErrorKindOf(err), protocolEntropyFailure)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("entropy failure public error exposed internal content")
		}
		events, readLengths := host.transcriptShape()
		if !reflect.DeepEqual(events, []string{"clock", "entropy"}) || !reflect.DeepEqual(readLengths, []int{16}) {
			t.Fatalf("entropy failure transcript shape mismatch: events=%v read lengths=%v", events, readLengths)
		}
	})

	t.Run("clock failure consumes no entropy and is safe", func(t *testing.T) {
		const sentinel = "SENTINEL-NATIVE-INFER-CLOCK"
		host := &nativeInferOrderedHost{
			now:      time.UnixMilli(1781000123999),
			entropy:  entropy,
			clockErr: errors.New("synthetic clock failure containing " + sentinel),
		}
		got, err := prepareNativeInferRequest(context.Background(), syntheticNativeInferSnapshot(protocolHostDeps{Clock: host, Entropy: host}), syntheticNativeInferInput())
		if got != nil {
			t.Fatal("clock failure returned a request")
		}
		if err == nil || protocolErrorKindOf(err) != protocolBackendFailure {
			t.Fatalf("clock failure kind = %q, want %q", protocolErrorKindOf(err), protocolBackendFailure)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("clock failure public error exposed internal content")
		}
		events, readLengths := host.transcriptShape()
		if !reflect.DeepEqual(events, []string{"clock"}) || len(readLengths) != 0 {
			t.Fatalf("clock failure transcript shape mismatch: events=%v read lengths=%v", events, readLengths)
		}
	})
}

func TestNativeInferPrepareBuildsExactRequest(t *testing.T) {
	t.Parallel()

	entropy, err := base64.StdEncoding.DecodeString("fn+AgYKDhIWGh4iJiouMjQ==")
	if err != nil {
		t.Fatalf("decode synthetic prepare entropy: length=%d", len(entropy))
	}
	host := &nativeInferOrderedHost{
		now:     time.UnixMilli(1781000123999),
		entropy: entropy,
	}
	snapshot := syntheticNativeInferSnapshot(protocolHostDeps{Clock: host, Entropy: host})
	snapshot.version = protocolFixtureIdentity.Version // Historical payload/signature below.
	input := syntheticNativeInferInput()

	got, err := prepareNativeInferRequest(context.Background(), snapshot, input)
	if err != nil {
		t.Fatalf("native prepare returned kind %q", protocolErrorKindOf(err))
	}
	if got == nil {
		t.Fatal("native prepare returned nil request")
	}

	wantURL := input.Endpoint + nativeInferPath + nativeInferQuery
	if got.URL != wantURL {
		t.Fatalf("prepared URL mismatch: got length %d, want length %d", len(got.URL), len(wantURL))
	}
	wantBody, err := (nativeBodyCodec{}).Encode(input.Body)
	if err != nil {
		t.Fatalf("encode expected body: kind=%q", protocolErrorKindOf(err))
	}
	if !bytes.Equal(got.Body, wantBody) {
		t.Fatalf("prepared body mismatch: got length %d, want length %d", len(got.Body), len(wantBody))
	}

	authorization := got.Header.Get("Authorization")
	const prefix = "Bearer COSY."
	if !strings.HasPrefix(authorization, prefix) {
		t.Fatalf("Authorization prefix mismatch: length=%d", len(authorization))
	}
	parts := strings.Split(strings.TrimPrefix(authorization, prefix), ".")
	if len(parts) != 2 {
		t.Fatalf("Authorization envelope shape mismatch: parts=%d length=%d", len(parts), len(authorization))
	}
	wantPayloadRaw := []byte(`{"version":"v1","requestId":"8d8c8b8a-8988-4786-8584-838281807f7e","info":"synthetic-info","cosyVersion":"1.1.34","ideVersion":""}`)
	wantPayloadB64 := base64.StdEncoding.EncodeToString(wantPayloadRaw)
	if parts[0] != wantPayloadB64 {
		t.Fatalf("Authorization payload mismatch: got length %d, want length %d", len(parts[0]), len(wantPayloadB64))
	}
	const wantSignature = "42d10ec20f81911638ffd2f2e5949e74"
	if parts[1] != wantSignature {
		t.Fatalf("Authorization signature mismatch: got length %d, want length %d", len(parts[1]), len(wantSignature))
	}

	wantHeader := http.Header{
		"Accept":                {"text/event-stream"},
		"Authorization":         {authorization},
		"Cache-Control":         {"no-cache"},
		"Connection":            {"keep-alive"},
		"Content-Type":          {"application/json"},
		"Cosy-Business-Product": {"cli"},
		"Cosy-Business-Type":    {"agent"},
		"Cosy-ClientType":       {"5"},
		"Cosy-Data-Policy":      {"disagree"},
		"Cosy-Date":             {"1781000123"},
		"Cosy-Key":              {"synthetic-key"},
		"Cosy-MachineId":        {"00000000-1111-4222-8333-444444444444"},
		"Cosy-MachineToken":     {"00000000-1111-4222-8333-444444444444"},
		"Cosy-MachineType":      {"5"},
		"Cosy-Scene":            {"assistant"},
		"Cosy-User":             {"synthetic-user"},
		"Cosy-Version":          {snapshot.version},
		"Login-Version":         {"v2"},
		"X-Model-Key":           {"synthetic-model"},
		"X-Model-Source":        {"custom"},
	}
	assertNativeInferHeaderSet(t, got.Header, wantHeader)

	events, readLengths := host.transcriptShape()
	if !reflect.DeepEqual(events, []string{"clock", "entropy"}) || !reflect.DeepEqual(readLengths, []int{16}) {
		t.Fatalf("host transcript shape mismatch: events=%v read lengths=%v", events, readLengths)
	}
}

func TestNativeInferRequestIDRejectsWrongLengthAsInvalidInput(t *testing.T) {
	t.Parallel()

	for _, length := range []int{0, 15, 17} {
		got, err := nativeInferRequestID(make([]byte, length))
		if got != "" {
			t.Fatalf("wrong-length request ID returned output: input length=%d output length=%d", length, len(got))
		}
		if err == nil || protocolErrorKindOf(err) != protocolInvalidInput {
			t.Fatalf("wrong-length request ID error kind mismatch: input length=%d kind=%q", length, protocolErrorKindOf(err))
		}
	}
}

func TestNativeInferRequestIDMatchesFixtureEntropy(t *testing.T) {
	t.Parallel()

	entropy, err := base64.StdEncoding.DecodeString("fn+AgYKDhIWGh4iJiouMjQ==")
	if err != nil {
		t.Fatalf("decode synthetic entropy fixture: length=%d", len(entropy))
	}
	const want = "8d8c8b8a-8988-4786-8584-838281807f7e"
	got, err := nativeInferRequestID(entropy)
	if err != nil {
		t.Fatalf("request ID construction failed: category=%T", err)
	}
	if got != want {
		t.Fatalf("request ID mismatch: got length %d, want length %d", len(got), len(want))
	}
}

func TestNativeInferHeadersAreExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		policyAgreed   bool
		organizationID string
		tags           []string
		modelKey       string
		modelSource    string
		missing        []string
	}{
		{name: "complete 22 headers", policyAgreed: true, organizationID: "synthetic-organization", tags: []string{"second", "first"}, modelKey: "synthetic-model", modelSource: "system"},
		{name: "empty organization and tags", organizationID: "", tags: []string{}, modelKey: "synthetic-model", modelSource: "system", missing: []string{"Cosy-Organization-Id", "Cosy-Organization-Tags"}},
		{name: "organization only", organizationID: "synthetic-organization", tags: []string{}, modelKey: "synthetic-model", modelSource: "system", missing: []string{"Cosy-Organization-Tags"}},
		{name: "tags only", organizationID: "", tags: []string{"second", "first"}, modelKey: "synthetic-model", modelSource: "system", missing: []string{"Cosy-Organization-Id"}},
		{name: "empty model key omits model pair", policyAgreed: true, organizationID: "synthetic-organization", tags: []string{"second", "first"}, modelKey: "", modelSource: "custom", missing: []string{"X-Model-Key", "X-Model-Source"}},
		{name: "empty model source remains present", policyAgreed: true, organizationID: "synthetic-organization", tags: []string{"second", "first"}, modelKey: "synthetic-model", modelSource: ""},
		{name: "empty model pair", policyAgreed: true, organizationID: "synthetic-organization", tags: []string{"second", "first"}, modelKey: "", modelSource: "", missing: []string{"X-Model-Key", "X-Model-Source"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := nativeInferHeaders(nativeInferHeaderValues{
				Authorization:   "synthetic-authorization",
				BusinessProduct: "synthetic-product",
				BusinessType:    "synthetic-business-type",
				ClientType:      "synthetic-client-type",
				DataPolicy:      tt.policyAgreed,
				UnixSeconds:     "1781000123",
				Key:             "synthetic-key",
				MachineID:       "00112233-4455-4677-8899-aabbccddeeff",
				OrganizationID:  tt.organizationID,
				Tags:            tt.tags,
				Scene:           "synthetic-scene",
				UID:             "synthetic-user",
				Version:         qoderProtocolVersion,
				ModelKey:        tt.modelKey,
				ModelSource:     tt.modelSource,
			})

			policy := "disagree"
			if tt.policyAgreed {
				policy = "agree"
			}
			want := http.Header{
				"Accept":                 {"text/event-stream"},
				"Authorization":          {"synthetic-authorization"},
				"Cache-Control":          {"no-cache"},
				"Connection":             {"keep-alive"},
				"Content-Type":           {"application/json"},
				"Cosy-Business-Product":  {"synthetic-product"},
				"Cosy-Business-Type":     {"synthetic-business-type"},
				"Cosy-ClientType":        {"synthetic-client-type"},
				"Cosy-Data-Policy":       {policy},
				"Cosy-Date":              {"1781000123"},
				"Cosy-Key":               {"synthetic-key"},
				"Cosy-MachineId":         {"00112233-4455-4677-8899-aabbccddeeff"},
				"Cosy-MachineToken":      {"00112233-4455-4677-8899-aabbccddeeff"},
				"Cosy-MachineType":       {"5"},
				"Cosy-Organization-Id":   {tt.organizationID},
				"Cosy-Organization-Tags": {strings.Join(tt.tags, ",")},
				"Cosy-Scene":             {"synthetic-scene"},
				"Cosy-User":              {"synthetic-user"},
				"Cosy-Version":           {qoderProtocolVersion},
				"Login-Version":          {"v2"},
				"X-Model-Key":            {tt.modelKey},
				"X-Model-Source":         {tt.modelSource},
			}
			for _, name := range tt.missing {
				want.Del(name)
			}
			assertNativeInferHeaderSet(t, got, want)
		})
	}
}

func assertNativeInferHeaderSet(t *testing.T, got, want http.Header) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("header cardinality mismatch: got %d, want %d, differing names %v", len(got), len(want), nativeInferHeaderDifferenceNames(got, want))
	}
	for name, wantValues := range want {
		gotValues := got.Values(name)
		if len(gotValues) != len(wantValues) {
			t.Fatalf("header %q value count mismatch: got %d, want %d", http.CanonicalHeaderKey(name), len(gotValues), len(wantValues))
		}
		for i := range wantValues {
			if gotValues[i] != wantValues[i] {
				t.Fatalf("header %q value mismatch at index %d: got length %d, want length %d", http.CanonicalHeaderKey(name), i, len(gotValues[i]), len(wantValues[i]))
			}
		}
	}
}

func TestNativeInferCanonicalMD5UsesExactShape(t *testing.T) {
	t.Parallel()

	const want = "d0a4ebfcda1ca89e1b9f87f3c31e077a"
	got := nativeInferSignature("cGF5bG9hZA==", "synthetic-key", "1781000123", "encoded-synthetic-body")
	if got != want {
		t.Fatalf("signature mismatch: got length %d, want length %d", len(got), len(want))
	}
	if len(got) != 32 {
		t.Fatalf("signature length mismatch: got %d, want 32", len(got))
	}
	decoded, err := hex.DecodeString(got)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("signature is not lowercase hexadecimal: length=%d", len(got))
	}
	for _, ch := range got {
		if ch >= 'A' && ch <= 'F' {
			t.Fatalf("signature contains uppercase hexadecimal: length=%d", len(got))
		}
	}
}

func TestNativeInferPayloadUsesFixedOrderAndContextVersion(t *testing.T) {
	t.Parallel()

	const (
		requestID = "00112233-4455-4677-8899-aabbccddeeff"
		info      = "synthetic-info+/="
	)
	tests := []struct {
		name    string
		version string
		wantRaw []byte
	}{
		{
			name:    "historical protocol version",
			version: protocolFixtureIdentity.Version,
			wantRaw: []byte(`{"version":"v1","requestId":"00112233-4455-4677-8899-aabbccddeeff","info":"synthetic-info+/=","cosyVersion":"1.1.34","ideVersion":""}`),
		},
		{
			name:    "production protocol version",
			version: qoderProtocolVersion,
			wantRaw: []byte(`{"version":"v1","requestId":"00112233-4455-4677-8899-aabbccddeeff","info":"synthetic-info+/=","cosyVersion":"1.1.74","ideVersion":""}`),
		},
		{
			name:    "context version perturbation",
			version: "9.8.7-synthetic",
			wantRaw: []byte(`{"version":"v1","requestId":"00112233-4455-4677-8899-aabbccddeeff","info":"synthetic-info+/=","cosyVersion":"9.8.7-synthetic","ideVersion":""}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotRaw, gotEncoded, err := nativeInferPayload(requestID, info, tt.version)
			if err != nil {
				t.Fatalf("payload construction failed: category=%T", err)
			}
			if string(gotRaw) != string(tt.wantRaw) {
				t.Fatalf("payload bytes mismatch: got length %d, want length %d", len(gotRaw), len(tt.wantRaw))
			}
			wantEncoded := base64.StdEncoding.EncodeToString(tt.wantRaw)
			if gotEncoded != wantEncoded {
				t.Fatalf("payload base64 mismatch: got length %d, want length %d", len(gotEncoded), len(wantEncoded))
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(gotEncoded)
			if err != nil {
				t.Fatalf("payload is not strict standard padded base64: length=%d", len(gotEncoded))
			}
			if string(decoded) != string(tt.wantRaw) {
				t.Fatalf("decoded payload mismatch: got length %d, want length %d", len(decoded), len(tt.wantRaw))
			}
		})
	}
}

func TestNativeInferURLUsesLiteralConcatenation(t *testing.T) {
	t.Parallel()

	const suffix = "/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "empty", endpoint: "", want: suffix},
		{name: "normal", endpoint: "https://example.invalid", want: "https://example.invalid" + suffix},
		{name: "trailing slash", endpoint: "https://example.invalid/", want: "https://example.invalid/" + suffix},
		{name: "existing path", endpoint: "https://example.invalid/base", want: "https://example.invalid/base" + suffix},
		{name: "existing query", endpoint: "https://example.invalid?old=1", want: "https://example.invalid?old=1" + suffix},
		{name: "fragment", endpoint: "https://example.invalid/#fragment", want: "https://example.invalid/#fragment" + suffix},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := nativeInferURL(tt.endpoint); got != tt.want {
				t.Fatalf("literal URL mismatch for %s: got length %d, want length %d", tt.name, len(got), len(tt.want))
			}
		})
	}
}

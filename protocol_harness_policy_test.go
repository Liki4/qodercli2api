package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

type protocolHarnessDenyTransport struct {
	calls atomic.Int64
}

func (t *protocolHarnessDenyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("authorized harness refresh is disabled")
}

func protocolHarnessRejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

type protocolHarnessRefreshCounts struct {
	HTTP    int64
	Encrypt int64
	Runtime int64
	Context int64
}

func clearAuthManagerDirtyForHarness(manager *authManager) {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	manager.credentialDirty = false
	manager.mu.Unlock()
}

func protocolHarnessRefreshAccountingValid(before, after protocolHarnessRefreshCounts) bool {
	return after.HTTP-before.HTTP == 1 &&
		after.Encrypt-before.Encrypt == 1 &&
		after.Runtime-before.Runtime == 1 &&
		after.Context-before.Context == 1
}

type protocolHarnessCapabilitySnapshot struct {
	CredentialEncrypt int64
	CredentialDecrypt int64
	RuntimeGenerate   int64
	ModelCacheDecrypt int64
	ContextNew        int64
	ContextPrepare    int64
}

func (s protocolHarnessCapabilitySnapshot) complete(includeEncrypt bool) bool {
	return (!includeEncrypt || s.CredentialEncrypt > 0) &&
		s.CredentialDecrypt > 0 &&
		s.RuntimeGenerate > 0 &&
		s.ModelCacheDecrypt > 0 &&
		s.ContextNew > 0 &&
		s.ContextPrepare > 0
}

func protocolHarnessCapabilityCallAdvanced(before, after int64) bool {
	return after > before
}

func protocolHarnessPrimaryAttemptsValid(prepareCalls, transportCalls int64) bool {
	return transportCalls >= 1 && transportCalls <= 4 && prepareCalls == transportCalls
}

type protocolHarnessUpstreamReason string

type protocolHarnessUpstreamShape string

const (
	protocolHarnessUpstreamNoEventStream           protocolHarnessUpstreamReason = "no-event-stream"
	protocolHarnessUpstreamMissingFinish           protocolHarnessUpstreamReason = "missing-finish"
	protocolHarnessUpstreamFinishWithoutData       protocolHarnessUpstreamReason = "finish-without-data"
	protocolHarnessUpstreamUnknownField            protocolHarnessUpstreamShape  = "unknown-sse-field"
	protocolHarnessUpstreamMultilineEvent          protocolHarnessUpstreamShape  = "multiline-event"
	protocolHarnessUpstreamMultilineData           protocolHarnessUpstreamShape  = "multiline-data"
	protocolHarnessUpstreamDataBeforeTerminalEvent protocolHarnessUpstreamShape  = "data-before-event-terminal"
	protocolHarnessUpstreamInnerDoneMarkerShape    protocolHarnessUpstreamShape  = "inner-done-marker"
	protocolHarnessUpstreamFinishInvalidJSON       protocolHarnessUpstreamReason = "finish-data-invalid-json"
	protocolHarnessUpstreamNamedEventInvalidJSON   protocolHarnessUpstreamReason = "named-event-data-invalid-json"
	protocolHarnessUpstreamEnvelopeDoneMarker      protocolHarnessUpstreamReason = "envelope-done-marker"
	protocolHarnessUpstreamEnvelopeNonJSONObj      protocolHarnessUpstreamReason = "envelope-nonjson-object-like"
	protocolHarnessUpstreamEnvelopeNonJSONArr      protocolHarnessUpstreamReason = "envelope-nonjson-array-like"
	protocolHarnessUpstreamEnvelopeNonJSONQuoted   protocolHarnessUpstreamReason = "envelope-nonjson-quoted-like"
	protocolHarnessUpstreamEnvelopeNonJSONNumber   protocolHarnessUpstreamReason = "envelope-nonjson-number-like"
	protocolHarnessUpstreamEnvelopeNonJSONLiteral  protocolHarnessUpstreamReason = "envelope-nonjson-literal-like"
	protocolHarnessUpstreamEnvelopeNonJSONOther    protocolHarnessUpstreamReason = "envelope-nonjson-text-token-other"
	protocolHarnessUpstreamEnvelopeInvalidJSON     protocolHarnessUpstreamReason = "envelope-invalid-json"
	protocolHarnessUpstreamEnvelopeMissingStatus   protocolHarnessUpstreamReason = "envelope-missing-status"
	protocolHarnessUpstreamNonOKStatus             protocolHarnessUpstreamReason = "non-200-status"
	protocolHarnessUpstreamOuterError              protocolHarnessUpstreamReason = "outer-error"
	protocolHarnessUpstreamInnerError              protocolHarnessUpstreamReason = "inner-error"
	protocolHarnessUpstreamInnerJSONNonObject      protocolHarnessUpstreamReason = "inner-json-non-object"
	protocolHarnessUpstreamInnerNonJSONObj         protocolHarnessUpstreamReason = "inner-nonjson-object-like"
	protocolHarnessUpstreamIncompleteFrame         protocolHarnessUpstreamReason = "incomplete-frame"
	protocolHarnessUpstreamMalformed               protocolHarnessUpstreamReason = "malformed-framing-envelope"
	protocolHarnessUpstreamReadFailure             protocolHarnessUpstreamReason = "non-eof-read-failure"
	protocolHarnessUpstreamPostFinish              protocolHarnessUpstreamReason = "post-finish-data-frame"
)

type protocolHarnessUpstreamSnapshot struct {
	Observed                int64
	Success                 int64
	MissingFinish           int64
	FinishWithoutData       int64
	FinishInvalidJSON       int64
	NamedEventInvalidJSON   int64
	EnvelopeDoneMarker      int64
	EnvelopeNonJSONObj      int64
	EnvelopeNonJSONArr      int64
	EnvelopeNonJSONQuoted   int64
	EnvelopeNonJSONNumber   int64
	EnvelopeNonJSONLiteral  int64
	EnvelopeNonJSONOther    int64
	EnvelopeInvalidJSON     int64
	EnvelopeMissingStatus   int64
	NonOKStatus             int64
	OuterError              int64
	InnerError              int64
	InnerJSONNonObject      int64
	InnerNonJSONObj         int64
	IncompleteFrame         int64
	Malformed               int64
	ReadFailure             int64
	PostFinish              int64
	UnknownField            int64
	MultilineEvent          int64
	MultilineData           int64
	DataBeforeTerminalEvent int64
	InnerDoneMarkerShape    int64
}

func protocolHarnessUpstreamShapeDelta(before, after protocolHarnessUpstreamSnapshot) []string {
	candidates := []struct {
		shape protocolHarnessUpstreamShape
		delta int64
	}{
		{shape: protocolHarnessUpstreamUnknownField, delta: after.UnknownField - before.UnknownField},
		{shape: protocolHarnessUpstreamMultilineEvent, delta: after.MultilineEvent - before.MultilineEvent},
		{shape: protocolHarnessUpstreamMultilineData, delta: after.MultilineData - before.MultilineData},
		{shape: protocolHarnessUpstreamDataBeforeTerminalEvent, delta: after.DataBeforeTerminalEvent - before.DataBeforeTerminalEvent},
		{shape: protocolHarnessUpstreamInnerDoneMarkerShape, delta: after.InnerDoneMarkerShape - before.InnerDoneMarkerShape},
	}
	shapes := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.delta > 0 {
			shapes = append(shapes, string(candidate.shape))
		}
	}
	return shapes
}

type protocolHarnessNonJSONKind uint8

const (
	protocolHarnessNonJSONDone protocolHarnessNonJSONKind = iota
	protocolHarnessNonJSONObject
	protocolHarnessNonJSONArray
	protocolHarnessNonJSONQuoted
	protocolHarnessNonJSONNumber
	protocolHarnessNonJSONLiteral
	protocolHarnessNonJSONOther
)

func protocolHarnessClassifyNonJSON(data []byte) protocolHarnessNonJSONKind {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("[DONE]")) {
		return protocolHarnessNonJSONDone
	}
	if len(trimmed) == 0 {
		return protocolHarnessNonJSONOther
	}
	switch trimmed[0] {
	case '{':
		return protocolHarnessNonJSONObject
	case '[':
		return protocolHarnessNonJSONArray
	case '"':
		return protocolHarnessNonJSONQuoted
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return protocolHarnessNonJSONNumber
	case 't', 'f', 'n':
		return protocolHarnessNonJSONLiteral
	default:
		return protocolHarnessNonJSONOther
	}
}

func protocolHarnessClassifyUnnamedNonJSON(data []byte) protocolHarnessUpstreamReason {
	return []protocolHarnessUpstreamReason{
		protocolHarnessUpstreamEnvelopeDoneMarker,
		protocolHarnessUpstreamEnvelopeNonJSONObj,
		protocolHarnessUpstreamEnvelopeNonJSONArr,
		protocolHarnessUpstreamEnvelopeNonJSONQuoted,
		protocolHarnessUpstreamEnvelopeNonJSONNumber,
		protocolHarnessUpstreamEnvelopeNonJSONLiteral,
		protocolHarnessUpstreamEnvelopeNonJSONOther,
	}[protocolHarnessClassifyNonJSON(data)]
}

func protocolHarnessUpstreamReasonDelta(before, after protocolHarnessUpstreamSnapshot) protocolHarnessUpstreamReason {
	observedCount := after.Observed - before.Observed
	if observedCount == 0 {
		return protocolHarnessUpstreamNoEventStream
	}
	if observedCount != 1 {
		return protocolHarnessUpstreamMalformed
	}
	reasons := []struct {
		reason protocolHarnessUpstreamReason
		delta  int64
	}{
		{reason: protocolHarnessUpstreamMissingFinish, delta: after.MissingFinish - before.MissingFinish},
		{reason: protocolHarnessUpstreamFinishWithoutData, delta: after.FinishWithoutData - before.FinishWithoutData},
		{reason: protocolHarnessUpstreamFinishInvalidJSON, delta: after.FinishInvalidJSON - before.FinishInvalidJSON},
		{reason: protocolHarnessUpstreamNamedEventInvalidJSON, delta: after.NamedEventInvalidJSON - before.NamedEventInvalidJSON},
		{reason: protocolHarnessUpstreamEnvelopeDoneMarker, delta: after.EnvelopeDoneMarker - before.EnvelopeDoneMarker},
		{reason: protocolHarnessUpstreamEnvelopeNonJSONObj, delta: after.EnvelopeNonJSONObj - before.EnvelopeNonJSONObj},
		{reason: protocolHarnessUpstreamEnvelopeNonJSONArr, delta: after.EnvelopeNonJSONArr - before.EnvelopeNonJSONArr},
		{reason: protocolHarnessUpstreamEnvelopeNonJSONQuoted, delta: after.EnvelopeNonJSONQuoted - before.EnvelopeNonJSONQuoted},
		{reason: protocolHarnessUpstreamEnvelopeNonJSONNumber, delta: after.EnvelopeNonJSONNumber - before.EnvelopeNonJSONNumber},
		{reason: protocolHarnessUpstreamEnvelopeNonJSONLiteral, delta: after.EnvelopeNonJSONLiteral - before.EnvelopeNonJSONLiteral},
		{reason: protocolHarnessUpstreamEnvelopeNonJSONOther, delta: after.EnvelopeNonJSONOther - before.EnvelopeNonJSONOther},
		{reason: protocolHarnessUpstreamEnvelopeInvalidJSON, delta: after.EnvelopeInvalidJSON - before.EnvelopeInvalidJSON},
		{reason: protocolHarnessUpstreamEnvelopeMissingStatus, delta: after.EnvelopeMissingStatus - before.EnvelopeMissingStatus},
		{reason: protocolHarnessUpstreamNonOKStatus, delta: after.NonOKStatus - before.NonOKStatus},
		{reason: protocolHarnessUpstreamOuterError, delta: after.OuterError - before.OuterError},
		{reason: protocolHarnessUpstreamInnerError, delta: after.InnerError - before.InnerError},
		{reason: protocolHarnessUpstreamInnerJSONNonObject, delta: after.InnerJSONNonObject - before.InnerJSONNonObject},
		{reason: protocolHarnessUpstreamInnerNonJSONObj, delta: after.InnerNonJSONObj - before.InnerNonJSONObj},
		{reason: protocolHarnessUpstreamIncompleteFrame, delta: after.IncompleteFrame - before.IncompleteFrame},
		{reason: protocolHarnessUpstreamMalformed, delta: after.Malformed - before.Malformed},
		{reason: protocolHarnessUpstreamReadFailure, delta: after.ReadFailure - before.ReadFailure},
		{reason: protocolHarnessUpstreamPostFinish, delta: after.PostFinish - before.PostFinish},
	}
	failureCount := int64(0)
	failureReason := protocolHarnessUpstreamReason("")
	for _, candidate := range reasons {
		if candidate.delta < 0 {
			return protocolHarnessUpstreamMalformed
		}
		failureCount += candidate.delta
		if candidate.delta != 0 {
			failureReason = candidate.reason
		}
	}
	successCount := after.Success - before.Success
	if successCount == 1 && failureCount == 0 {
		return ""
	}
	if successCount == 0 && failureCount == 1 {
		return failureReason
	}
	return protocolHarnessUpstreamMalformed
}

func protocolHarnessChatStreamFrameValid(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	sawObject := false
	sawChoices := false
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return false
		}
		switch key {
		case "object":
			value, err := decoder.Token()
			object, ok := value.(string)
			if err != nil || !ok || object != "chat.completion.chunk" {
				return false
			}
			sawObject = true
		case "choices":
			value, err := decoder.Token()
			opening, ok := value.(json.Delim)
			if err != nil || !ok || opening != json.Delim('[') {
				return false
			}
			if err := protocolHarnessDiscardJSONContainer(decoder, opening); err != nil {
				return false
			}
			sawChoices = true
		case "error":
			return false
		default:
			if err := protocolHarnessDiscardJSONValue(decoder); err != nil {
				return false
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false
	}
	return sawObject && sawChoices
}

func protocolHarnessDiscardJSONValue(decoder *json.Decoder) error {
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	opening, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	return protocolHarnessDiscardJSONContainer(decoder, opening)
}

func protocolHarnessDiscardJSONContainer(decoder *json.Decoder, opening json.Delim) error {
	switch opening {
	case json.Delim('{'):
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := protocolHarnessDiscardJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid synthetic JSON object")
		}
		return nil
	case json.Delim('['):
		for decoder.More() {
			if err := protocolHarnessDiscardJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid synthetic JSON array")
		}
		return nil
	default:
		return errors.New("invalid synthetic JSON container")
	}
}

func closeAuthManagerReadOnlyForTest(manager *authManager) error {
	if manager == nil {
		return nil
	}
	clearAuthManagerDirtyForHarness(manager)
	return manager.Close()
}

type protocolHarnessPersistenceProbe struct {
	encryptCalls atomic.Int32
}

func (p *protocolHarnessPersistenceProbe) Encrypt(context.Context, string, string) (string, error) {
	p.encryptCalls.Add(1)
	return "synthetic-encrypted-credential", nil
}

func (*protocolHarnessPersistenceProbe) Decrypt(context.Context, string, string) (string, error) {
	return "", nil
}

type protocolHarnessCloseProbe struct {
	closeCalls atomic.Int32
}

func (*protocolHarnessCloseProbe) PrepareInferRequest(context.Context, inferRequestInput) (*preparedRequest, error) {
	return &preparedRequest{}, nil
}

func (p *protocolHarnessCloseProbe) Close() error {
	p.closeCalls.Add(1)
	return nil
}

func TestAuthorizedHarnessReadOnlyCleanupDoesNotPersist(t *testing.T) {
	codec := &protocolHarnessPersistenceProbe{}
	contextProbe := &protocolHarnessCloseProbe{}
	manager := &authManager{
		protocol:        &protocolServices{credentials: codec},
		protoCtx:        contextProbe,
		ui:              &userInfo{UID: "synthetic-policy-user"},
		credentialDirty: true,
		logf:            func(string, ...any) {},
	}
	if err := closeAuthManagerReadOnlyForTest(manager); err != nil {
		t.Fatal("read-only harness cleanup failed")
	}
	if codec.encryptCalls.Load() != 0 {
		t.Fatal("read-only harness cleanup attempted credential persistence")
	}
	if contextProbe.closeCalls.Load() != 1 {
		t.Fatal("read-only harness cleanup did not close the protocol context exactly once")
	}
}

func TestAuthorizedHarnessRefreshBaselineExcludesPreRefreshPersistence(t *testing.T) {
	manager := &authManager{credentialDirty: true}
	clearAuthManagerDirtyForHarness(manager)
	manager.mu.Lock()
	dirty := manager.credentialDirty
	manager.mu.Unlock()
	if dirty {
		t.Fatal("refresh harness baseline retained load-induced dirty state")
	}

	baseline := protocolHarnessRefreshCounts{HTTP: 0, Encrypt: 1, Runtime: 2, Context: 3}
	withoutRefreshPersistence := protocolHarnessRefreshCounts{HTTP: 1, Encrypt: 1, Runtime: 3, Context: 4}
	if protocolHarnessRefreshAccountingValid(baseline, withoutRefreshPersistence) {
		t.Fatal("pre-refresh persistence satisfied refreshed-token accounting")
	}
	withRefreshPersistence := protocolHarnessRefreshCounts{HTTP: 1, Encrypt: 2, Runtime: 3, Context: 4}
	if !protocolHarnessRefreshAccountingValid(baseline, withRefreshPersistence) {
		t.Fatal("exact synthetic refresh transaction failed accounting")
	}
}

func TestAuthorizedHarnessRefreshAccountingRejectsInvalidDeltas(t *testing.T) {
	baseline := protocolHarnessRefreshCounts{HTTP: 4, Encrypt: 5, Runtime: 6, Context: 7}
	for _, test := range []struct {
		name  string
		after protocolHarnessRefreshCounts
	}{
		{name: "zero HTTP", after: protocolHarnessRefreshCounts{HTTP: 4, Encrypt: 6, Runtime: 7, Context: 8}},
		{name: "two HTTP", after: protocolHarnessRefreshCounts{HTTP: 6, Encrypt: 6, Runtime: 7, Context: 8}},
		{name: "zero Encrypt", after: protocolHarnessRefreshCounts{HTTP: 5, Encrypt: 5, Runtime: 7, Context: 8}},
		{name: "two Encrypt", after: protocolHarnessRefreshCounts{HTTP: 5, Encrypt: 7, Runtime: 7, Context: 8}},
		{name: "zero runtime", after: protocolHarnessRefreshCounts{HTTP: 5, Encrypt: 6, Runtime: 6, Context: 8}},
		{name: "two runtime", after: protocolHarnessRefreshCounts{HTTP: 5, Encrypt: 6, Runtime: 8, Context: 8}},
		{name: "zero context", after: protocolHarnessRefreshCounts{HTTP: 5, Encrypt: 6, Runtime: 7, Context: 7}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if protocolHarnessRefreshAccountingValid(baseline, test.after) {
				t.Fatal("invalid refresh deltas were accepted")
			}
		})
	}
}

func TestAuthorizedHarnessNativeCapabilityCompleteness(t *testing.T) {
	complete := protocolHarnessCapabilitySnapshot{
		CredentialDecrypt: 1,
		RuntimeGenerate:   1,
		ModelCacheDecrypt: 1,
		ContextNew:        1,
		ContextPrepare:    1,
	}
	if !complete.complete(false) {
		t.Fatal("complete native capability accounting was rejected")
	}
	complete.ContextPrepare = 0
	if complete.complete(false) {
		t.Fatal("native capability accounting accepted a missing prepare call")
	}
}

func TestAuthorizedHarnessCapabilityCallAccounting(t *testing.T) {
	for _, test := range []struct {
		name   string
		before int64
		after  int64
		want   bool
	}{
		{name: "one call", before: 0, after: 1, want: true},
		{name: "additional call", before: 3, after: 4, want: true},
		{name: "no call", before: 2, after: 2, want: false},
		{name: "invalid regression", before: 2, after: 1, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHarnessCapabilityCallAdvanced(test.before, test.after); got != test.want {
				t.Fatalf("capability accounting result = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAuthorizedHarnessPrimaryAttemptPolicy(t *testing.T) {
	for _, test := range []struct {
		name           string
		prepareCalls   int64
		transportCalls int64
		want           bool
	}{
		{name: "one primary attempt", prepareCalls: 1, transportCalls: 1, want: true},
		{name: "four primary attempts", prepareCalls: 4, transportCalls: 4, want: true},
		{name: "zero attempts", prepareCalls: 0, transportCalls: 0, want: false},
		{name: "too many attempts", prepareCalls: 5, transportCalls: 5, want: false},
		{name: "prepare and transport differ", prepareCalls: 2, transportCalls: 1, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHarnessPrimaryAttemptsValid(test.prepareCalls, test.transportCalls); got != test.want {
				t.Fatalf("primary-attempt policy result = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAuthorizedHarnessRefreshDenyTransportNeverDelegates(t *testing.T) {
	transport := &protocolHarnessDenyTransport{}
	request, err := http.NewRequest(http.MethodPost, "https://example.invalid/synthetic-refresh", nil)
	if err != nil {
		t.Fatal("construct synthetic refresh request")
	}
	response, err := transport.RoundTrip(request)
	if response != nil || err == nil {
		t.Fatal("refresh deny transport did not fail closed")
	}
	if transport.calls.Load() != 1 {
		t.Fatal("refresh deny transport call count mismatch")
	}
}

func TestAuthorizedHarnessChatStreamFramePolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		want    bool
	}{
		{name: "completion chunk", payload: []byte(`{"object":"chat.completion.chunk","choices":[]}`), want: true},
		{name: "error object", payload: []byte(`{"error":{"type":"synthetic"}}`), want: false},
		{name: "wrong object", payload: []byte(`{"object":"response","choices":[]}`), want: false},
		{name: "malformed", payload: []byte(`{`), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHarnessChatStreamFrameValid(test.payload); got != test.want {
				t.Fatalf("chat frame policy result = %t, want %t", got, test.want)
			}
		})
	}
}

func protocolHarnessTypedStreamFrameValid(event string, payload []byte, allowed map[string]struct{}) bool {
	if _, ok := allowed[event]; !ok {
		return false
	}
	var frame struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(payload, &frame) == nil && frame.Type == event
}

func protocolHarnessAnthropicStreamFrameValid(event string, payload []byte) bool {
	return protocolHarnessTypedStreamFrameValid(event, payload, map[string]struct{}{
		"message_start":       {},
		"content_block_start": {},
		"content_block_delta": {},
		"content_block_stop":  {},
		"message_delta":       {},
		"message_stop":        {},
		"ping":                {},
	})
}

func protocolHarnessResponsesStreamFrameValid(event string, payload []byte) bool {
	return protocolHarnessTypedStreamFrameValid(event, payload, map[string]struct{}{
		"response.created":                       {},
		"response.in_progress":                   {},
		"response.output_item.added":             {},
		"response.output_item.done":              {},
		"response.content_part.added":            {},
		"response.content_part.done":             {},
		"response.output_text.delta":             {},
		"response.output_text.done":              {},
		"response.reasoning_summary_part.added":  {},
		"response.reasoning_summary_part.done":   {},
		"response.reasoning_summary_text.delta":  {},
		"response.reasoning_summary_text.done":   {},
		"response.function_call_arguments.delta": {},
		"response.function_call_arguments.done":  {},
		"response.custom_tool_call_input.delta":  {},
		"response.custom_tool_call_input.done":   {},
		"response.completed":                     {},
	})
}

func TestAuthorizedHarnessAnthropicStreamFramePolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		event   string
		payload []byte
		want    bool
	}{
		{name: "message start", event: "message_start", payload: []byte(`{"type":"message_start","message":{"type":"message"}}`), want: true},
		{name: "content delta", event: "content_block_delta", payload: []byte(`{"type":"content_block_delta","delta":{"type":"text_delta"}}`), want: true},
		{name: "message stop", event: "message_stop", payload: []byte(`{"type":"message_stop"}`), want: true},
		{name: "event mismatch", event: "message_stop", payload: []byte(`{"type":"message_start"}`), want: false},
		{name: "error object", event: "error", payload: []byte(`{"type":"error"}`), want: false},
		{name: "missing type", event: "message_start", payload: []byte(`{"message":{}}`), want: false},
		{name: "malformed", event: "message_start", payload: []byte(`{`), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHarnessAnthropicStreamFrameValid(test.event, test.payload); got != test.want {
				t.Fatalf("Anthropic frame policy result = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAuthorizedHarnessResponsesStreamFramePolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		event   string
		payload []byte
		want    bool
	}{
		{name: "created", event: "response.created", payload: []byte(`{"type":"response.created","response":{"object":"response"}}`), want: true},
		{name: "output delta", event: "response.output_text.delta", payload: []byte(`{"type":"response.output_text.delta","delta":"synthetic"}`), want: true},
		{name: "custom input delta", event: "response.custom_tool_call_input.delta", payload: []byte(`{"type":"response.custom_tool_call_input.delta","delta":"synthetic"}`), want: true},
		{name: "custom input done", event: "response.custom_tool_call_input.done", payload: []byte(`{"type":"response.custom_tool_call_input.done","input":"synthetic"}`), want: true},
		{name: "custom event mismatch", event: "response.custom_tool_call_input.done", payload: []byte(`{"type":"response.custom_tool_call_input.delta","delta":"synthetic"}`), want: false},
		{name: "malformed custom input", event: "response.custom_tool_call_input.delta", payload: []byte(`{`), want: false},
		{name: "completed", event: "response.completed", payload: []byte(`{"type":"response.completed","response":{"object":"response"}}`), want: true},
		{name: "event mismatch", event: "response.completed", payload: []byte(`{"type":"response.created"}`), want: false},
		{name: "failed response", event: "response.failed", payload: []byte(`{"type":"response.failed"}`), want: false},
		{name: "unknown response event", event: "response.synthetic", payload: []byte(`{"type":"response.synthetic"}`), want: false},
		{name: "malformed", event: "response.created", payload: []byte(`{`), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHarnessResponsesStreamFrameValid(test.event, test.payload); got != test.want {
				t.Fatalf("Responses frame policy result = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAuthorizedHarnessUpstreamReasonDelta(t *testing.T) {
	baseline := protocolHarnessUpstreamSnapshot{Observed: 4, Success: 3, MissingFinish: 1}
	for _, test := range []struct {
		name  string
		after protocolHarnessUpstreamSnapshot
		want  protocolHarnessUpstreamReason
	}{
		{name: "success", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 4, MissingFinish: 1}},
		{name: "no event stream", after: baseline, want: protocolHarnessUpstreamNoEventStream},
		{name: "multiple event streams", after: protocolHarnessUpstreamSnapshot{Observed: 6, Success: 5, MissingFinish: 1}, want: protocolHarnessUpstreamMalformed},
		{name: "missing finish", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 2}, want: protocolHarnessUpstreamMissingFinish},
		{name: "finish without data", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, FinishWithoutData: 1}, want: protocolHarnessUpstreamFinishWithoutData},
		{name: "finish invalid JSON", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, FinishInvalidJSON: 1}, want: protocolHarnessUpstreamFinishInvalidJSON},
		{name: "named event invalid JSON", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, NamedEventInvalidJSON: 1}, want: protocolHarnessUpstreamNamedEventInvalidJSON},
		{name: "envelope done marker", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeDoneMarker: 1}, want: protocolHarnessUpstreamEnvelopeDoneMarker},
		{name: "envelope nonjson object-like", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeNonJSONObj: 1}, want: protocolHarnessUpstreamEnvelopeNonJSONObj},
		{name: "envelope nonjson array-like", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeNonJSONArr: 1}, want: protocolHarnessUpstreamEnvelopeNonJSONArr},
		{name: "envelope nonjson quoted-like", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeNonJSONQuoted: 1}, want: protocolHarnessUpstreamEnvelopeNonJSONQuoted},
		{name: "envelope nonjson number-like", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeNonJSONNumber: 1}, want: protocolHarnessUpstreamEnvelopeNonJSONNumber},
		{name: "envelope nonjson literal-like", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeNonJSONLiteral: 1}, want: protocolHarnessUpstreamEnvelopeNonJSONLiteral},
		{name: "envelope nonjson other", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeNonJSONOther: 1}, want: protocolHarnessUpstreamEnvelopeNonJSONOther},
		{name: "envelope invalid inner JSON", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeInvalidJSON: 1}, want: protocolHarnessUpstreamEnvelopeInvalidJSON},
		{name: "envelope missing status", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, EnvelopeMissingStatus: 1}, want: protocolHarnessUpstreamEnvelopeMissingStatus},
		{name: "non-200 status", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, NonOKStatus: 1}, want: protocolHarnessUpstreamNonOKStatus},
		{name: "outer error", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, OuterError: 1}, want: protocolHarnessUpstreamOuterError},
		{name: "inner error", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, InnerError: 1}, want: protocolHarnessUpstreamInnerError},
		{name: "inner JSON non-object", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, InnerJSONNonObject: 1}, want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson object-like", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, InnerNonJSONObj: 1}, want: protocolHarnessUpstreamInnerNonJSONObj},
		{name: "incomplete frame", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, IncompleteFrame: 1}, want: protocolHarnessUpstreamIncompleteFrame},
		{name: "malformed", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, Malformed: 1}, want: protocolHarnessUpstreamMalformed},
		{name: "read failure", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, ReadFailure: 1}, want: protocolHarnessUpstreamReadFailure},
		{name: "post finish", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 3, MissingFinish: 1, PostFinish: 1}, want: protocolHarnessUpstreamPostFinish},
		{name: "ambiguous accounting", after: protocolHarnessUpstreamSnapshot{Observed: 5, Success: 4, MissingFinish: 2}, want: protocolHarnessUpstreamMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHarnessUpstreamReasonDelta(baseline, test.after); got != test.want {
				t.Fatalf("upstream reason delta = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAuthorizedHarnessUpstreamShapeDelta(t *testing.T) {
	before := protocolHarnessUpstreamSnapshot{UnknownField: 1, MultilineEvent: 2, MultilineData: 3, DataBeforeTerminalEvent: 4, InnerDoneMarkerShape: 5}
	after := protocolHarnessUpstreamSnapshot{UnknownField: 2, MultilineEvent: 3, MultilineData: 4, DataBeforeTerminalEvent: 5, InnerDoneMarkerShape: 6}
	got := protocolHarnessUpstreamShapeDelta(before, after)
	want := []string{"unknown-sse-field", "multiline-event", "multiline-data", "data-before-event-terminal", "inner-done-marker"}
	if len(got) != len(want) {
		t.Fatalf("upstream shape delta count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("upstream shape delta %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestAuthorizedHarnessRejectsRedirects(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/redirect", nil)
	if err != nil {
		t.Fatal("construct synthetic redirect request")
	}
	if err := protocolHarnessRejectRedirect(request, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("redirect policy did not fail closed")
	}
}

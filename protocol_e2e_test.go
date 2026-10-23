//go:build e2e

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Controller commands (all output is content-free):
//
//	QODER2API_E2E=1 go test -tags=e2e . -run '^TestProtocolE2E(Native|DefaultNative)$' -count=1 -v
//	QODER2API_E2E=1 QODER2API_E2E_REFRESH=1 go test -tags=e2e . -run '^TestProtocolE2ERefresh$' -count=1 -v
//
// QODER2API_E2E_REGION selects global (default) or cn and its config root/endpoints.
// Without the separate refresh opt-in, auth runs only against a private byte copy;
// catalog reads still use the original source root. Content-silent overrides are
// QODER2API_E2E_AUTH_DIR, QODER2API_E2E_INFER_ENDPOINT,
// QODER2API_E2E_OPENAPI_ENDPOINT, and QODER2API_E2E_WEB_ENDPOINT.
// QODER2API_DUMP_DIR and environment PAT discovery are deliberately ignored.

const (
	protocolE2ESetupTimeout   = 90 * time.Second
	protocolE2ERouteTimeout   = 2 * time.Minute
	protocolE2ERefreshTimeout = 90 * time.Second
	protocolE2EPrompt         = "Synthetic protocol validation. Reply only OK."
)

type protocolE2EResult struct {
	Route          string
	Stream         bool
	HTTPStatus     int
	HTTPSuccess    bool
	SchemaSuccess  bool
	Duration       time.Duration
	UpstreamShapes []string
}

type protocolE2EConfig struct {
	region          string
	authDir         string
	inferEndpoint   string
	openapiEndpoint string
	webEndpoint     string
}

type protocolE2ECapabilityCounts struct {
	credentialEncrypt atomic.Int64
	credentialDecrypt atomic.Int64
	runtimeGenerate   atomic.Int64
	modelCacheDecrypt atomic.Int64
	contextNew        atomic.Int64
	contextPrepare    atomic.Int64
}

type protocolE2ECountingCredentialCodec struct {
	inner  credentialCodec
	counts *protocolE2ECapabilityCounts
}

func (c *protocolE2ECountingCredentialCodec) Encrypt(ctx context.Context, plain, machineKey string) (string, error) {
	c.counts.credentialEncrypt.Add(1)
	return c.inner.Encrypt(ctx, plain, machineKey)
}

func (c *protocolE2ECountingCredentialCodec) Decrypt(ctx context.Context, blob, machineKey string) (string, error) {
	c.counts.credentialDecrypt.Add(1)
	return c.inner.Decrypt(ctx, blob, machineKey)
}

type protocolE2ECountingRuntimeFieldGenerator struct {
	inner  runtimeFieldGenerator
	counts *protocolE2ECapabilityCounts
}

func (g *protocolE2ECountingRuntimeFieldGenerator) Generate(ctx context.Context, input runtimeFieldInput) (runtimeFieldOutput, error) {
	g.counts.runtimeGenerate.Add(1)
	return g.inner.Generate(ctx, input)
}

type protocolE2ECountingModelCacheDecryptor struct {
	inner  modelCacheDecryptor
	counts *protocolE2ECapabilityCounts
}

func (d *protocolE2ECountingModelCacheDecryptor) Decrypt(ctx context.Context, blob, uid string) ([]byte, error) {
	d.counts.modelCacheDecrypt.Add(1)
	return d.inner.Decrypt(ctx, blob, uid)
}

type protocolE2ECountingContextFactory struct {
	inner  protocolContextFactory
	counts *protocolE2ECapabilityCounts
}

func (f *protocolE2ECountingContextFactory) New(ctx context.Context, config protocolContextConfig) (protocolContext, error) {
	f.counts.contextNew.Add(1)
	created, err := f.inner.New(ctx, config)
	if created == nil {
		return nil, err
	}
	return &protocolE2ECountingContext{inner: created, counts: f.counts}, err
}

type protocolE2ECountingContext struct {
	inner  protocolContext
	counts *protocolE2ECapabilityCounts
}

func (c *protocolE2ECountingContext) PrepareInferRequest(ctx context.Context, input inferRequestInput) (*preparedRequest, error) {
	c.counts.contextPrepare.Add(1)
	return c.inner.PrepareInferRequest(ctx, input)
}

func (c *protocolE2ECountingContext) Close() error {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.Close()
}

const (
	protocolE2EUpstreamLineLimit  = 64 << 10
	protocolE2EUpstreamFrameLimit = 512 << 10
)

type protocolE2EUpstreamObserver struct {
	fragment             []byte
	discardLine          bool
	frameEvent           []byte
	frameData            []byte
	frameHasEvent        bool
	frameHasData         bool
	frameDataBeforeEvent bool
	shapes               map[protocolHarnessUpstreamShape]struct{}
	sawFinish            bool
	finishWithoutData    bool
	postFinish           bool
	incompleteFrame      bool
	frameFailure         protocolHarnessUpstreamReason
	finalized            bool
	success              bool
	reason               protocolHarnessUpstreamReason
	onShape              func(protocolHarnessUpstreamShape)
	onFinalize           func(protocolHarnessUpstreamReason)
}

func newProtocolE2EUpstreamObserver() *protocolE2EUpstreamObserver {
	return &protocolE2EUpstreamObserver{}
}

func (o *protocolE2EUpstreamObserver) Write(payload []byte) (int, error) {
	written := len(payload)
	for len(payload) > 0 {
		newline := bytes.IndexByte(payload, '\n')
		if newline < 0 {
			o.appendFragment(payload)
			break
		}
		o.appendFragment(payload[:newline])
		o.processFragment()
		payload = payload[newline+1:]
	}
	return written, nil
}

func (o *protocolE2EUpstreamObserver) appendFragment(fragment []byte) {
	if o.discardLine {
		return
	}
	if len(o.fragment)+len(fragment) > protocolE2EUpstreamLineLimit {
		o.zeroBytes(&o.fragment)
		o.discardLine = true
		o.incompleteFrame = true
		return
	}
	o.fragment = append(o.fragment, fragment...)
}

func (o *protocolE2EUpstreamObserver) processFragment() {
	if o.discardLine {
		o.discardLine = false
		o.zeroBytes(&o.fragment)
		return
	}
	line := bytes.TrimSuffix(o.fragment, []byte{'\r'})
	if len(line) == 0 {
		o.zeroBytes(&o.fragment)
		o.finishFrame()
		return
	}
	if line[0] == ':' {
		o.zeroBytes(&o.fragment)
		return
	}
	field, value, found := bytes.Cut(line, []byte{':'})
	if !found {
		o.addShape(protocolHarnessUpstreamUnknownField)
		o.zeroBytes(&o.fragment)
		return
	}
	switch string(field) {
	case "event":
		if o.sawFinish {
			o.postFinish = true
			o.zeroBytes(&o.fragment)
			return
		}
		if o.frameHasEvent {
			o.addShape(protocolHarnessUpstreamMultilineEvent)
		}
		value = bytes.TrimSpace(value)
		o.appendFrameValue(&o.frameEvent, value, ' ')
		o.frameHasEvent = true
	case "data":
		if o.sawFinish {
			o.postFinish = true
			o.zeroBytes(&o.fragment)
			return
		}
		if o.frameHasData {
			o.addShape(protocolHarnessUpstreamMultilineData)
		}
		if !o.frameHasEvent {
			o.frameDataBeforeEvent = true
		}
		value = bytes.TrimPrefix(value, []byte{' '})
		o.appendFrameValue(&o.frameData, value, '\n')
		o.frameHasData = true
	default:
		o.addShape(protocolHarnessUpstreamUnknownField)
	}
	o.zeroBytes(&o.fragment)
}

func (o *protocolE2EUpstreamObserver) appendFrameValue(target *[]byte, value []byte, separator byte) {
	extra := len(value)
	if len(*target) > 0 {
		extra++
	}
	if len(o.frameEvent)+len(o.frameData)+extra > protocolE2EUpstreamFrameLimit {
		o.incompleteFrame = true
		return
	}
	if len(*target) > 0 {
		*target = append(*target, separator)
	}
	*target = append(*target, value...)
}

func (o *protocolE2EUpstreamObserver) finishFrame() {
	if !o.frameHasEvent && !o.frameHasData {
		o.resetFrame()
		return
	}
	if o.sawFinish {
		o.postFinish = true
		o.resetFrame()
		return
	}
	event := string(o.frameEvent)
	if event == "finish" {
		if o.frameDataBeforeEvent {
			o.addShape(protocolHarnessUpstreamDataBeforeTerminalEvent)
		}
		if !o.frameHasData || len(o.frameData) == 0 {
			o.finishWithoutData = true
			o.resetFrame()
			return
		}
		var terminal map[string]json.RawMessage
		if json.Unmarshal(o.frameData, &terminal) != nil {
			o.markFrameFailure(protocolHarnessUpstreamFinishInvalidJSON)
		} else if terminal == nil {
			o.markFrameFailure(protocolHarnessUpstreamMalformed)
		} else {
			o.sawFinish = true
		}
		o.resetFrame()
		return
	}
	if o.frameHasData {
		o.validateEnvelope(o.frameData, event != "")
	}
	o.resetFrame()
}

func (o *protocolE2EUpstreamObserver) validateEnvelope(data []byte, namedEvent bool) {
	var envelope struct {
		StatusCodeValue *int            `json:"statusCodeValue"`
		Body            string          `json:"body"`
		Error           json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		if namedEvent {
			o.markFrameFailure(protocolHarnessUpstreamNamedEventInvalidJSON)
		} else {
			o.markFrameFailure(protocolHarnessClassifyUnnamedNonJSON(data))
		}
		return
	}
	if envelope.StatusCodeValue == nil {
		o.markFrameFailure(protocolHarnessUpstreamEnvelopeMissingStatus)
		return
	}
	if *envelope.StatusCodeValue != http.StatusOK {
		o.markFrameFailure(protocolHarnessUpstreamNonOKStatus)
		return
	}
	if len(envelope.Error) != 0 && string(bytes.TrimSpace(envelope.Error)) != "null" {
		o.markFrameFailure(protocolHarnessUpstreamOuterError)
		return
	}
	if envelope.Body == "" {
		return
	}
	var inner struct {
		Error json.RawMessage `json:"error"`
	}
	innerData := bytes.TrimSpace([]byte(envelope.Body))
	if bytes.Equal(innerData, []byte("[DONE]")) {
		o.addShape(protocolHarnessUpstreamInnerDoneMarkerShape)
		return
	}
	if len(innerData) == 0 || innerData[0] != '{' {
		o.markFrameFailure(protocolHarnessUpstreamInnerJSONNonObject)
		return
	}
	if json.Unmarshal(innerData, &inner) != nil {
		o.markFrameFailure(protocolHarnessUpstreamInnerNonJSONObj)
		return
	}
	if len(inner.Error) != 0 && string(bytes.TrimSpace(inner.Error)) != "null" {
		o.markFrameFailure(protocolHarnessUpstreamInnerError)
	}
}

func (o *protocolE2EUpstreamObserver) markFrameFailure(reason protocolHarnessUpstreamReason) {
	if o.frameFailure == "" {
		o.frameFailure = reason
	}
}

func (o *protocolE2EUpstreamObserver) addShape(shape protocolHarnessUpstreamShape) {
	if o.shapes == nil {
		o.shapes = make(map[protocolHarnessUpstreamShape]struct{})
	}
	if _, exists := o.shapes[shape]; exists {
		return
	}
	o.shapes[shape] = struct{}{}
	if o.onShape != nil {
		o.onShape(shape)
	}
}

func (o *protocolE2EUpstreamObserver) resetFrame() {
	o.zeroBytes(&o.frameEvent)
	o.zeroBytes(&o.frameData)
	o.frameHasEvent = false
	o.frameHasData = false
	o.frameDataBeforeEvent = false
}

func (*protocolE2EUpstreamObserver) zeroBytes(value *[]byte) {
	for index := range *value {
		(*value)[index] = 0
	}
	*value = nil
}

func (o *protocolE2EUpstreamObserver) Finalize(err error) {
	if o == nil || o.finalized {
		return
	}
	o.finalized = true
	if len(o.fragment) != 0 || o.discardLine || o.frameHasEvent || o.frameHasData {
		o.processFragment()
		o.finishFrame()
	}
	o.reason = o.failureReason(err)
	o.success = o.reason == ""
	if o.onFinalize != nil {
		o.onFinalize(o.reason)
	}
}

func (o *protocolE2EUpstreamObserver) failureReason(err error) protocolHarnessUpstreamReason {
	switch {
	case err != nil && !errors.Is(err, io.EOF):
		return protocolHarnessUpstreamReadFailure
	case o.postFinish:
		return protocolHarnessUpstreamPostFinish
	case o.incompleteFrame:
		return protocolHarnessUpstreamIncompleteFrame
	case o.frameFailure != "":
		return o.frameFailure
	case o.finishWithoutData:
		return protocolHarnessUpstreamFinishWithoutData
	case !o.sawFinish:
		return protocolHarnessUpstreamMissingFinish
	default:
		return ""
	}
}

func (o *protocolE2EUpstreamObserver) Success() bool {
	return o != nil && o.finalized && o.success
}

func (o *protocolE2EUpstreamObserver) Reason() protocolHarnessUpstreamReason {
	if o == nil || !o.finalized {
		return ""
	}
	return o.reason
}

func (o *protocolE2EUpstreamObserver) HasShape(shape protocolHarnessUpstreamShape) bool {
	if o == nil {
		return false
	}
	_, ok := o.shapes[shape]
	return ok
}

type protocolE2ECountingTransport struct {
	base                            http.RoundTripper
	calls                           atomic.Int64
	readFailures                    atomic.Int64
	upstreamObserved                atomic.Int64
	upstreamSuccess                 atomic.Int64
	upstreamMissingFinish           atomic.Int64
	upstreamFinishWithoutData       atomic.Int64
	upstreamFinishInvalidJSON       atomic.Int64
	upstreamNamedEventInvalidJSON   atomic.Int64
	upstreamEnvelopeDoneMarker      atomic.Int64
	upstreamEnvelopeNonJSONObj      atomic.Int64
	upstreamEnvelopeNonJSONArr      atomic.Int64
	upstreamEnvelopeNonJSONQuoted   atomic.Int64
	upstreamEnvelopeNonJSONNumber   atomic.Int64
	upstreamEnvelopeNonJSONLiteral  atomic.Int64
	upstreamEnvelopeNonJSONOther    atomic.Int64
	upstreamEnvelopeInvalidJSON     atomic.Int64
	upstreamEnvelopeMissingStatus   atomic.Int64
	upstreamNonOKStatus             atomic.Int64
	upstreamOuterError              atomic.Int64
	upstreamInnerError              atomic.Int64
	upstreamInnerJSONNonObject      atomic.Int64
	upstreamInnerNonJSONObj         atomic.Int64
	upstreamIncompleteFrame         atomic.Int64
	upstreamMalformed               atomic.Int64
	upstreamReadFailure             atomic.Int64
	upstreamPostFinish              atomic.Int64
	upstreamUnknownField            atomic.Int64
	upstreamMultilineEvent          atomic.Int64
	upstreamMultilineData           atomic.Int64
	upstreamDataBeforeTerminalEvent atomic.Int64
	upstreamInnerDoneMarkerShape    atomic.Int64
}

func (t *protocolE2ECountingTransport) upstreamSnapshot() protocolHarnessUpstreamSnapshot {
	if t == nil {
		return protocolHarnessUpstreamSnapshot{}
	}
	return protocolHarnessUpstreamSnapshot{
		Observed:                t.upstreamObserved.Load(),
		Success:                 t.upstreamSuccess.Load(),
		MissingFinish:           t.upstreamMissingFinish.Load(),
		FinishWithoutData:       t.upstreamFinishWithoutData.Load(),
		FinishInvalidJSON:       t.upstreamFinishInvalidJSON.Load(),
		NamedEventInvalidJSON:   t.upstreamNamedEventInvalidJSON.Load(),
		EnvelopeDoneMarker:      t.upstreamEnvelopeDoneMarker.Load(),
		EnvelopeNonJSONObj:      t.upstreamEnvelopeNonJSONObj.Load(),
		EnvelopeNonJSONArr:      t.upstreamEnvelopeNonJSONArr.Load(),
		EnvelopeNonJSONQuoted:   t.upstreamEnvelopeNonJSONQuoted.Load(),
		EnvelopeNonJSONNumber:   t.upstreamEnvelopeNonJSONNumber.Load(),
		EnvelopeNonJSONLiteral:  t.upstreamEnvelopeNonJSONLiteral.Load(),
		EnvelopeNonJSONOther:    t.upstreamEnvelopeNonJSONOther.Load(),
		EnvelopeInvalidJSON:     t.upstreamEnvelopeInvalidJSON.Load(),
		EnvelopeMissingStatus:   t.upstreamEnvelopeMissingStatus.Load(),
		NonOKStatus:             t.upstreamNonOKStatus.Load(),
		OuterError:              t.upstreamOuterError.Load(),
		InnerError:              t.upstreamInnerError.Load(),
		InnerJSONNonObject:      t.upstreamInnerJSONNonObject.Load(),
		InnerNonJSONObj:         t.upstreamInnerNonJSONObj.Load(),
		IncompleteFrame:         t.upstreamIncompleteFrame.Load(),
		Malformed:               t.upstreamMalformed.Load(),
		ReadFailure:             t.upstreamReadFailure.Load(),
		PostFinish:              t.upstreamPostFinish.Load(),
		UnknownField:            t.upstreamUnknownField.Load(),
		MultilineEvent:          t.upstreamMultilineEvent.Load(),
		MultilineData:           t.upstreamMultilineData.Load(),
		DataBeforeTerminalEvent: t.upstreamDataBeforeTerminalEvent.Load(),
		InnerDoneMarkerShape:    t.upstreamInnerDoneMarkerShape.Load(),
	}
}

func (t *protocolE2ECountingTransport) recordUpstreamShape(shape protocolHarnessUpstreamShape) {
	switch shape {
	case protocolHarnessUpstreamUnknownField:
		t.upstreamUnknownField.Add(1)
	case protocolHarnessUpstreamMultilineEvent:
		t.upstreamMultilineEvent.Add(1)
	case protocolHarnessUpstreamMultilineData:
		t.upstreamMultilineData.Add(1)
	case protocolHarnessUpstreamDataBeforeTerminalEvent:
		t.upstreamDataBeforeTerminalEvent.Add(1)
	case protocolHarnessUpstreamInnerDoneMarkerShape:
		t.upstreamInnerDoneMarkerShape.Add(1)
	}
}

func (t *protocolE2ECountingTransport) recordUpstreamResult(reason protocolHarnessUpstreamReason) {
	switch reason {
	case "":
		t.upstreamSuccess.Add(1)
	case protocolHarnessUpstreamMissingFinish:
		t.upstreamMissingFinish.Add(1)
	case protocolHarnessUpstreamFinishWithoutData:
		t.upstreamFinishWithoutData.Add(1)
	case protocolHarnessUpstreamFinishInvalidJSON:
		t.upstreamFinishInvalidJSON.Add(1)
	case protocolHarnessUpstreamNamedEventInvalidJSON:
		t.upstreamNamedEventInvalidJSON.Add(1)
	case protocolHarnessUpstreamEnvelopeDoneMarker:
		t.upstreamEnvelopeDoneMarker.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONObj:
		t.upstreamEnvelopeNonJSONObj.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONArr:
		t.upstreamEnvelopeNonJSONArr.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONQuoted:
		t.upstreamEnvelopeNonJSONQuoted.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONNumber:
		t.upstreamEnvelopeNonJSONNumber.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONLiteral:
		t.upstreamEnvelopeNonJSONLiteral.Add(1)
	case protocolHarnessUpstreamEnvelopeNonJSONOther:
		t.upstreamEnvelopeNonJSONOther.Add(1)
	case protocolHarnessUpstreamEnvelopeInvalidJSON:
		t.upstreamEnvelopeInvalidJSON.Add(1)
	case protocolHarnessUpstreamEnvelopeMissingStatus:
		t.upstreamEnvelopeMissingStatus.Add(1)
	case protocolHarnessUpstreamNonOKStatus:
		t.upstreamNonOKStatus.Add(1)
	case protocolHarnessUpstreamOuterError:
		t.upstreamOuterError.Add(1)
	case protocolHarnessUpstreamInnerError:
		t.upstreamInnerError.Add(1)
	case protocolHarnessUpstreamInnerJSONNonObject:
		t.upstreamInnerJSONNonObject.Add(1)
	case protocolHarnessUpstreamInnerNonJSONObj:
		t.upstreamInnerNonJSONObj.Add(1)
	case protocolHarnessUpstreamIncompleteFrame:
		t.upstreamIncompleteFrame.Add(1)
	case protocolHarnessUpstreamMalformed:
		t.upstreamMalformed.Add(1)
	case protocolHarnessUpstreamReadFailure:
		t.upstreamReadFailure.Add(1)
	case protocolHarnessUpstreamPostFinish:
		t.upstreamPostFinish.Add(1)
	default:
		t.upstreamMalformed.Add(1)
	}
}

type protocolE2EObservedBody struct {
	inner    io.ReadCloser
	counter  *atomic.Int64
	failed   atomic.Bool
	observer *protocolE2EUpstreamObserver
}

func (b *protocolE2EObservedBody) Read(payload []byte) (int, error) {
	count, err := b.inner.Read(payload)
	if b.observer != nil && count > 0 {
		_, _ = b.observer.Write(payload[:count])
	}
	if err != nil {
		if b.observer != nil {
			b.observer.Finalize(err)
		}
		if !errors.Is(err, io.EOF) && b.failed.CompareAndSwap(false, true) {
			b.counter.Add(1)
		}
	}
	return count, err
}

func (b *protocolE2EObservedBody) Close() error {
	if b.observer != nil {
		b.observer.Finalize(nil)
	}
	return b.inner.Close()
}

func protocolE2EIsEventStream(response *http.Response) bool {
	if response == nil || response.StatusCode != http.StatusOK {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	return mediaType == "text/event-stream"
}

func (t *protocolE2ECountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	response, err := t.base.RoundTrip(request)
	if response != nil && response.Body != nil {
		observed := &protocolE2EObservedBody{inner: response.Body, counter: &t.readFailures}
		if protocolE2EIsEventStream(response) {
			t.upstreamObserved.Add(1)
			observer := newProtocolE2EUpstreamObserver()
			observer.onShape = t.recordUpstreamShape
			observer.onFinalize = t.recordUpstreamResult
			observed.observer = observer
		}
		response.Body = observed
	}
	return response, err
}

type protocolE2EHarness struct {
	services         *protocolServices
	auth             *authManager
	handler          http.Handler
	capabilities     *protocolE2ECapabilityCounts
	transport        *protocolE2ECountingTransport
	refreshTransport *protocolE2ECountingTransport
	denyRefresh      *protocolHarnessDenyTransport
	readOnlyAuth     bool
	sourceAuthFile   string
	closeIdle        []func()
	closeOnce        sync.Once
	closeFailed      bool
}

type protocolE2EJSONField struct {
	key     string
	allowed []string
}

type protocolE2EJSONExpectation struct {
	strings []protocolE2EJSONField
	arrays  []string
}

type protocolE2ESSEExpectation struct {
	events            []string
	requireDone       bool
	validateData      func([]byte) bool
	validateEventData func(string, []byte) bool
}

type protocolE2ERouteSpec struct {
	name string
	path string
	json protocolE2EJSONExpectation
	sse  protocolE2ESSEExpectation
}

type protocolE2EValidation struct {
	ok       bool
	category string
}

type protocolE2EResponseProbe struct {
	header     http.Header
	status     int
	length     int64
	pipe       *io.PipeWriter
	validation <-chan protocolE2EValidation
}

func TestProtocolE2ENative(t *testing.T) {
	runProtocolE2ENative(t)
}

func TestProtocolE2ERefresh(t *testing.T) {
	runProtocolE2ERefresh(t)
}

func TestProtocolE2EDefaultNative(t *testing.T) {
	requireProtocolE2E(t)
	if _, err := parseAppConfig(nil, envLookup(nil), io.Discard); err != nil {
		protocolE2EFatal(t, "default-config")
	}
	harness := newProtocolE2EHarness(t, false)
	harness.runRoute(t, protocolE2ERouteSpecs()[0], false)
	if harness.Close() {
		t.Errorf("protocol E2E cleanup failed: status=0 category=cleanup length=0")
	}
}

type protocolE2ERoundTripperFunc func(*http.Request) (*http.Response, error)

func (f protocolE2ERoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type protocolE2ESingleReadBody struct {
	payload []byte
	read    bool
}

func (b *protocolE2ESingleReadBody) Read(payload []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(payload, b.payload), nil
}

func (*protocolE2ESingleReadBody) Close() error { return nil }

type protocolE2ESyntheticReadFailureBody struct{}

func (*protocolE2ESyntheticReadFailureBody) Read(payload []byte) (int, error) {
	return copy(payload, "synthetic"), errors.New("synthetic body read failure")
}

func (*protocolE2ESyntheticReadFailureBody) Close() error { return nil }

func TestProtocolE2EUpstreamObserverAcceptsSplitAuthoritativeFinish(t *testing.T) {
	payload := []byte("data:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\nevent:finish\ndata:{\"totalDuration\":1}\n\n")
	for split := 0; split <= len(payload); split++ {
		observer := newProtocolE2EUpstreamObserver()
		_, _ = observer.Write(payload[:split])
		_, _ = observer.Write(payload[split:])
		observer.Finalize(io.EOF)
		if !observer.Success() {
			t.Fatalf("authoritative finish rejected at synthetic split %d", split)
		}
	}
}

func TestProtocolE2EUpstreamObserverAcceptsProductionCompatibleFramesAcrossSplits(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		shapes  []protocolHarnessUpstreamShape
	}{
		{
			name:    "data before terminal event",
			payload: "data:{\"totalDuration\":1}\nevent:finish\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamDataBeforeTerminalEvent},
		},
		{
			name:    "multiline data",
			payload: "event:finish\ndata:{\"totalDuration\":\ndata:1}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamMultilineData},
		},
		{
			name:    "repeated event lines",
			payload: "event:synthetic\nevent:frame\ndata:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\nevent:finish\ndata:{}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamMultilineEvent},
		},
		{
			name:    "ignored standard and unknown fields",
			payload: "id:synthetic\nretry:1\nsynthetic:ignored\ndata:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\nevent:finish\ndata:{}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamUnknownField},
		},
		{
			name:    "inner done marker before authoritative finish",
			payload: "data:{\"statusCodeValue\":200,\"body\":\"  [DONE]  \"}\n\nevent:finish\ndata:{}\n\n",
			shapes:  []protocolHarnessUpstreamShape{protocolHarnessUpstreamInnerDoneMarkerShape},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(test.payload)
			for split := 0; split <= len(payload); split++ {
				observer := newProtocolE2EUpstreamObserver()
				_, _ = observer.Write(payload[:split])
				_, _ = observer.Write(payload[split:])
				observer.Finalize(io.EOF)
				if !observer.Success() {
					t.Fatalf("production-compatible upstream shape rejected as %q at synthetic split %d", observer.Reason(), split)
				}
				for _, shape := range test.shapes {
					if !observer.HasShape(shape) {
						t.Fatalf("safe upstream shape %q absent at synthetic split %d", shape, split)
					}
				}
			}
		})
	}
}

func TestProtocolE2EUpstreamObserverClassifiesUnsafeTerminalShapesAcrossSplits(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		endErr  error
		want    protocolHarnessUpstreamReason
	}{
		{name: "empty", want: protocolHarnessUpstreamMissingFinish},
		{name: "partial frame", payload: "data:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\n", want: protocolHarnessUpstreamMissingFinish},
		{name: "finish without data", payload: "event:finish\n\n", want: protocolHarnessUpstreamFinishWithoutData},
		{name: "finish data invalid JSON", payload: "event:finish\ndata:{\n\n", want: protocolHarnessUpstreamFinishInvalidJSON},
		{name: "named non-finish event data invalid JSON", payload: "event:heartbeat\ndata:{\n\n", want: protocolHarnessUpstreamNamedEventInvalidJSON},
		{name: "unnamed exact done marker", payload: "data:   [DONE]  \n\n", want: protocolHarnessUpstreamEnvelopeDoneMarker},
		{name: "unnamed nonjson object-like", payload: "data: {\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONObj},
		{name: "unnamed nonjson array-like", payload: "data: [synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONArr},
		{name: "unnamed nonjson quoted-like", payload: "data: \"synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONQuoted},
		{name: "unnamed nonjson number-like", payload: "data: -synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONNumber},
		{name: "unnamed nonjson literal-like", payload: "data: true-synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONLiteral},
		{name: "unnamed nonjson text token", payload: "data: synthetic\n\n", want: protocolHarnessUpstreamEnvelopeNonJSONOther},
		{name: "normal envelope missing status", payload: "data:{\"body\":\"{}\"}\n\n", want: protocolHarnessUpstreamEnvelopeMissingStatus},
		{name: "non-200 status", payload: "data:{\"statusCodeValue\":503,\"body\":\"synthetic\"}\n\n", want: protocolHarnessUpstreamNonOKStatus},
		{name: "outer error", payload: "data:{\"statusCodeValue\":200,\"error\":{}}\n\n", want: protocolHarnessUpstreamOuterError},
		{name: "inner error", payload: "data:{\"statusCodeValue\":200,\"body\":\"{\\\"error\\\":{}}\"}\n\n", want: protocolHarnessUpstreamInnerError},
		{name: "inner JSON null", payload: "data:{\"statusCodeValue\":200,\"body\":\"null\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON array", payload: "data:{\"statusCodeValue\":200,\"body\":\"[]\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON string", payload: "data:{\"statusCodeValue\":200,\"body\":\"\\\"synthetic\\\"\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON number", payload: "data:{\"statusCodeValue\":200,\"body\":\"1\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner JSON literal", payload: "data:{\"statusCodeValue\":200,\"body\":\"true\"}\n\nevent:finish\ndata:{}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner done marker without finish", payload: "data:{\"statusCodeValue\":200,\"body\":\"  [DONE]  \"}\n\n", want: protocolHarnessUpstreamMissingFinish},
		{name: "inner nonjson object-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"{\"}\n\n", want: protocolHarnessUpstreamInnerNonJSONObj},
		{name: "inner nonjson array-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"[synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson quoted-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"\\\"synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson number-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"-synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson literal-like", payload: "data:{\"statusCodeValue\":200,\"body\":\"true-synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "inner nonjson text token", payload: "data:{\"statusCodeValue\":200,\"body\":\"synthetic\"}\n\n", want: protocolHarnessUpstreamInnerJSONNonObject},
		{name: "read failure after finish", payload: "event:finish\ndata:{}\n\n", endErr: errors.New("synthetic read failure"), want: protocolHarnessUpstreamReadFailure},
		{name: "data after finish", payload: "event:finish\ndata:{}\n\ndata:{\"statusCodeValue\":200,\"body\":\"{}\"}\n\n", want: protocolHarnessUpstreamPostFinish},
		{name: "frame after finish", payload: "event:finish\ndata:{}\n\nevent:synthetic\n\n", want: protocolHarnessUpstreamPostFinish},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(test.payload)
			for split := 0; split <= len(payload); split++ {
				observer := newProtocolE2EUpstreamObserver()
				_, _ = observer.Write(payload[:split])
				_, _ = observer.Write(payload[split:])
				observer.Finalize(test.endErr)
				if observer.Success() {
					t.Fatalf("unsafe upstream terminal shape was accepted at synthetic split %d", split)
				}
				if got := observer.Reason(); got != test.want {
					t.Fatalf("upstream reason = %q, want %q at synthetic split %d", got, test.want, split)
				}
			}
		})
	}
}

func TestProtocolE2EUpstreamObserverClassifiesBoundedIncompleteFrame(t *testing.T) {
	observer := newProtocolE2EUpstreamObserver()
	_, _ = observer.Write(append([]byte("data:"), bytes.Repeat([]byte{'x'}, protocolE2EUpstreamLineLimit+1)...))
	observer.Finalize(io.EOF)
	if got := observer.Reason(); got != protocolHarnessUpstreamIncompleteFrame {
		t.Fatalf("bounded incomplete frame reason = %q, want %q", got, protocolHarnessUpstreamIncompleteFrame)
	}
}

func TestProtocolE2EUpstreamObservedBodyCloseFinalizesCompleteFinish(t *testing.T) {
	observer := newProtocolE2EUpstreamObserver()
	body := &protocolE2EObservedBody{
		inner:    &protocolE2ESingleReadBody{payload: []byte("event:finish\ndata:{}\n\n")},
		counter:  &atomic.Int64{},
		observer: observer,
	}
	buffer := make([]byte, 128)
	if count, err := body.Read(buffer); count == 0 || err != nil {
		t.Fatal("synthetic finish body read failed")
	}
	if err := body.Close(); err != nil {
		t.Fatal("synthetic finish body close failed")
	}
	if !observer.Success() {
		t.Fatal("complete authoritative finish did not finalize on close")
	}
}

func TestProtocolE2ETransportIgnoresNonEventStreamSuccess(t *testing.T) {
	transport := &protocolE2ECountingTransport{base: protocolE2ERoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"queue":{"isQueued":true}}`)),
		}, nil
	})}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://example.invalid/synthetic-queue", nil))
	if err != nil || response == nil {
		t.Fatal("synthetic non-event-stream response setup failed")
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if transport.upstreamSnapshot() != (protocolHarnessUpstreamSnapshot{}) {
		t.Fatal("non-event-stream response was classified as authoritative upstream SSE")
	}
}

func TestProtocolE2ETransportReadFailureAccounting(t *testing.T) {
	transport := &protocolE2ECountingTransport{base: protocolE2ERoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &protocolE2ESyntheticReadFailureBody{},
		}, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "https://example.invalid/synthetic-read-failure", nil)
	response, err := transport.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		t.Fatal("synthetic transport response setup failed")
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if transport.calls.Load() != 1 || transport.readFailures.Load() != 1 {
		t.Fatalf("transport calls/read failures = %d/%d, want 1/1", transport.calls.Load(), transport.readFailures.Load())
	}
}

func requireProtocolE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("QODER2API_E2E") != "1" {
		t.Skip("authorized protocol E2E disabled; set QODER2API_E2E=1")
	}
}

func TestProtocolE2EEnvironmentConfig(t *testing.T) {
	globalRoot, cnRoot, override := t.TempDir(), t.TempDir(), t.TempDir()
	for _, test := range []struct {
		name string
		env  map[string]string
		want protocolE2EConfig
	}{
		{"global-default", nil, protocolE2EConfig{region: "global", authDir: filepath.Join(homeDir(), ".qoder", ".auth"), inferEndpoint: defaultInfer, openapiEndpoint: defaultOpenapi, webEndpoint: defaultBase}},
		{"cn-default", map[string]string{"QODER2API_E2E_REGION": "cn"}, protocolE2EConfig{region: "cn", authDir: filepath.Join(homeDir(), ".qoder-cn", ".auth"), inferEndpoint: "https://gateway.qoder.com.cn", openapiEndpoint: "https://openapi.qoder.com.cn", webEndpoint: "https://qoder.cn"}},
		{"global-root", map[string]string{"QODER_CONFIG_DIR": globalRoot, "QODERCN_CONFIG_DIR": cnRoot}, protocolE2EConfig{region: "global", authDir: filepath.Join(globalRoot, ".auth"), inferEndpoint: defaultInfer, openapiEndpoint: defaultOpenapi, webEndpoint: defaultBase}},
		{"cn-root", map[string]string{"QODER2API_E2E_REGION": "cn", "QODER_CONFIG_DIR": globalRoot, "QODERCN_CONFIG_DIR": cnRoot}, protocolE2EConfig{region: "cn", authDir: filepath.Join(cnRoot, ".auth"), inferEndpoint: "https://gateway.qoder.com.cn", openapiEndpoint: "https://openapi.qoder.com.cn", webEndpoint: "https://qoder.cn"}},
		{"explicit-overrides", map[string]string{"QODER2API_E2E_REGION": "cn", "QODERCN_CONFIG_DIR": cnRoot, "QODER2API_E2E_AUTH_DIR": override, "QODER2API_E2E_INFER_ENDPOINT": "https://INFER.invalid/path///", "QODER2API_E2E_OPENAPI_ENDPOINT": "http://OPENAPI.invalid/base/", "QODER2API_E2E_WEB_ENDPOINT": "https://WEB.invalid/"}, protocolE2EConfig{region: "cn", authDir: override, inferEndpoint: "https://infer.invalid/path", openapiEndpoint: "http://openapi.invalid/base", webEndpoint: "https://web.invalid"}},
		{"unrelated-region-pat-ignored", map[string]string{"QODER_REGION": "cn", "QODER2API_REGION": "cn", "QODER_PERSONAL_ACCESS_TOKEN": "synthetic-pat", "QODERCN_PERSONAL_ACCESS_TOKEN": "synthetic-cn-pat", "QODER2API_AUTH_DIR": override, "QODER2API_INFER_ENDPOINT": "https://unrelated.invalid"}, protocolE2EConfig{region: "global", authDir: filepath.Join(homeDir(), ".qoder", ".auth"), inferEndpoint: defaultInfer, openapiEndpoint: defaultOpenapi, webEndpoint: defaultBase}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				if !strings.HasPrefix(key, "QODER2API_E2E_") && key != "QODER_CONFIG_DIR" && key != "QODERCN_CONFIG_DIR" {
					t.Errorf("E2E configuration read unrelated environment key %s", key)
				}
				return envLookup(test.env)(key)
			}
			got, err := protocolE2EEnvironmentConfig(lookup)
			if err != nil || got != test.want {
				t.Fatalf("synthetic config = %#v, error=%v, want %#v", got, err, test.want)
			}
		})
	}
	for _, key := range []string{"QODER2API_E2E_REGION", "QODER2API_E2E_INFER_ENDPOINT", "QODER2API_E2E_OPENAPI_ENDPOINT", "QODER2API_E2E_WEB_ENDPOINT"} {
		values := []string{"ftp://invalid.invalid", "https://user:secret@invalid.invalid", "https://invalid.invalid/?secret=value", "https://invalid.invalid/#secret", "https://invalid.invalid:0", " https://invalid.invalid", "https://invalid.invalid\n"}
		if key == "QODER2API_E2E_REGION" {
			values = []string{"other", "CN", " cn "}
		}
		for _, value := range values {
			if _, err := protocolE2EEnvironmentConfig(envLookup(map[string]string{key: value})); err == nil || strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid configuration key %s was accepted or exposed its value", key)
			}
		}
	}
}

func protocolE2ESyntheticAuthStore(t *testing.T, region string, binding bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".auth")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	machineID := "01234567-89ab-4cde-8fab-0123456789ab"
	plain, err := json.Marshal(&userInfo{UID: "synthetic-e2e-user", SecurityOAuthToken: "synthetic-e2e-token", RefreshToken: "synthetic-e2e-refresh", ExpireTime: time.Now().Add(2 * time.Hour).Unix(), LoginMethod: "oauth"})
	if err != nil {
		t.Fatal("synthetic credential serialization failed")
	}
	cipher, err := (nativeCredentialCodec{}).Encrypt(context.Background(), string(plain), machineCredentialKey(machineID))
	if err != nil {
		t.Fatal("synthetic credential encryption failed")
	}
	files := map[string][]byte{"machine_id": []byte(machineID + "\n"), "user": []byte(cipher + "\n"), "unrelated": []byte("do-not-copy")}
	if binding {
		profile, err := resolveRegion(region)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(authBinding{Version: 1, Region: region, Issuer: profile.openapi, ClientID: prodClientID}, "", "  ")
		if err != nil {
			t.Fatal("synthetic binding serialization failed")
		}
		files[authBindingName] = append(raw, '\n')
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0640); err != nil {
			t.Fatal("synthetic auth file creation failed")
		}
	}
	return dir
}

type protocolE2EFileSnapshot struct {
	mode     os.FileMode
	modified time.Time
	data     string
}

func protocolE2ESnapshotTree(t *testing.T, root string) map[string]protocolE2EFileSnapshot {
	t.Helper()
	result := map[string]protocolE2EFileSnapshot{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		item := protocolE2EFileSnapshot{mode: info.Mode(), modified: info.ModTime()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.data = string(data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			item.data, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		result[name] = item
		return nil
	})
	if err != nil {
		t.Fatal("synthetic tree snapshot failed")
	}
	return result
}

func TestProtocolE2EAuthSetupReadOnlySource(t *testing.T) {
	for _, region := range []string{"global", "cn"} {
		for _, binding := range []bool{false, true} {
			name := region + "/legacy"
			if binding {
				name = region + "/bound"
			}
			t.Run(name, func(t *testing.T) {
				source := protocolE2ESyntheticAuthStore(t, region, binding)
				before := protocolE2ESnapshotTree(t, source)
				h, err := newProtocolE2EAuthHarness(t, context.Background(), false, envLookup(map[string]string{"QODER2API_E2E": "1", "QODER2API_E2E_AUTH_DIR": source, "QODER2API_E2E_REGION": region}))
				if err != nil {
					t.Fatal("synthetic auth setup failed", err)
				}
				if h.auth.authFile == filepath.Join(source, "user") || h.sourceAuthFile != filepath.Join(source, "user") || h.auth.store.ephemeral {
					t.Error("read-only harness must use a persistent private copy and retain separate source path")
				}
				if h.auth.machineID != "01234567-89ab-4cde-8fab-0123456789ab" || h.auth.store.expected.Region != region || h.capabilities.credentialDecrypt.Load() != 1 || h.capabilities.contextNew.Load() != 1 || !protocolE2EHasUsableToken(h.auth) {
					t.Error("copy did not decrypt/load with the selected region and original machine ID")
				}
				if h.denyRefresh == nil || h.auth.httpc.Transport != h.denyRefresh || h.denyRefresh.calls.Load() != 0 {
					t.Error("read-only auth HTTP was not disabled")
				}
				copyDir := filepath.Dir(h.auth.authFile)
				if info, err := os.Stat(copyDir); err != nil || info.Mode().Perm() != 0700 {
					t.Error("private auth directory is not 0700")
				}
				for _, file := range []string{"user", "machine_id", authBindingName} {
					data, err := os.ReadFile(filepath.Join(copyDir, file))
					original, exists := before[file]
					if !exists {
						if !errors.Is(err, os.ErrNotExist) {
							t.Error("optional absent binding was created")
						}
						continue
					}
					if err != nil || string(data) != original.data {
						t.Error("allowlisted auth bytes changed")
					}
					info, err := os.Stat(filepath.Join(copyDir, file))
					sourceInfo, sourceErr := os.Stat(filepath.Join(source, file))
					if err != nil || sourceErr != nil || info.Mode().Perm() != 0600 || os.SameFile(info, sourceInfo) {
						t.Error("auth copy must be a separate 0600 regular file")
					}
				}
				if _, err := os.Lstat(filepath.Join(copyDir, "unrelated")); !errors.Is(err, os.ErrNotExist) {
					t.Error("unrelated auth file was copied")
				}
				if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
					t.Error("source tree changed during construction/load")
				}
				h.auth.credentialDirty = true
				if h.Close() {
					t.Error("read-only close failed")
				}
				if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
					t.Error("source tree changed during close")
				}
				if h.capabilities.credentialEncrypt.Load() != 0 {
					t.Error("read-only close persisted credentials")
				}
			})
		}
	}
}

func TestProtocolE2EAuthSetupGatesBeforeSourceAccess(t *testing.T) {
	for _, test := range []struct {
		name, gate, refresh string
		allow               bool
		want                error
	}{
		{"disabled", "0", "1", false, errProtocolE2EDisabled},
		{"disabled-refresh", "0", "1", true, errProtocolE2EDisabled},
		{"refresh-not-authorized", "1", "0", true, errProtocolE2ERefreshDisabled},
		{"refresh-not-exact", "1", "true", true, errProtocolE2ERefreshDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := protocolE2ESyntheticAuthStore(t, "global", false)
			before := protocolE2ESnapshotTree(t, source)
			nonGateLookups := 0
			lookup := func(key string) (string, bool) {
				switch key {
				case "QODER2API_E2E":
					return test.gate, true
				case "QODER2API_E2E_REFRESH":
					return test.refresh, true
				default:
					nonGateLookups++
					if key == "QODER2API_E2E_AUTH_DIR" {
						return source, true
					}
					return "", false
				}
			}
			h, err := newProtocolE2EAuthHarness(t, context.Background(), test.allow, lookup)
			if h != nil {
				h.Close()
			}
			if !errors.Is(err, test.want) || h != nil || nonGateLookups != 0 {
				t.Error("constructor did not enforce both opt-ins before configuration/source access")
			}
			if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
				t.Error("disabled constructor changed synthetic source")
			}
		})
	}
}

func TestProtocolE2EAuthSetupRefreshUsesExplicitSyntheticSource(t *testing.T) {
	source := protocolE2ESyntheticAuthStore(t, "cn", true)
	h, err := newProtocolE2EAuthHarness(t, context.Background(), true, envLookup(map[string]string{"QODER2API_E2E": "1", "QODER2API_E2E_REFRESH": "1", "QODER2API_E2E_REGION": "cn", "QODER2API_E2E_AUTH_DIR": source}))
	if err != nil {
		t.Fatal("synthetic refresh-enabled setup failed", err)
	}
	if h.auth.authFile != filepath.Join(source, "user") || h.readOnlyAuth || h.refreshTransport == nil || h.refreshTransport.calls.Load() != 0 {
		t.Error("refresh-enabled constructor did not use explicitly authorized synthetic source without requests")
	}
	if h.Close() {
		t.Error("synthetic refresh-enabled close failed")
	}
}

func TestProtocolE2ECatalogUsesSourceAndVersionPolicy(t *testing.T) {
	for _, names := range [][]string{{"catalog-v7"}, {"catalog-v7", "catalog-v6"}, {"catalog-v6"}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			sourceAuth := filepath.Join(t.TempDir(), ".auth", "user")
			copyAuth := filepath.Join(t.TempDir(), ".auth", "user")
			uid := "synthetic-catalog-user"
			for _, authFile := range []string{sourceAuth, copyAuth} {
				if err := os.MkdirAll(filepath.Join(modelsCacheRoot(authFile), uid), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range names {
				if err := os.WriteFile(filepath.Join(modelsCacheRoot(sourceAuth), uid, name), []byte("source-"+name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(modelsCacheRoot(copyAuth), uid, "catalog-v6"), []byte("wrong-copy-cache"), 0600); err != nil {
				t.Fatal(err)
			}
			before := protocolE2ESnapshotTree(t, filepath.Dir(filepath.Dir(sourceAuth)))
			decryptor := &fakeModelCacheDecryptor{data: []byte(`{"chat":[{"key":"synthetic-source-model","display_name":"Synthetic"}]}`)}
			counts := &protocolE2ECapabilityCounts{}
			h := &protocolE2EHarness{sourceAuthFile: sourceAuth, auth: &authManager{authFile: copyAuth, ui: &userInfo{UID: uid}}, services: &protocolServices{modelCache: &protocolE2ECountingModelCacheDecryptor{inner: decryptor, counts: counts}}, capabilities: counts}
			resolver := protocolE2ELoadCatalog(t, context.Background(), h)
			if resolver.byKey["synthetic-source-model"] == nil || decryptor.calls != 1 || decryptor.input != "source-"+names[0] || decryptor.uid != uid || counts.modelCacheDecrypt.Load() != 1 {
				t.Error("catalog did not use original source path and shared v7/v6 policy exactly once")
			}
			if !reflect.DeepEqual(protocolE2ESnapshotTree(t, filepath.Dir(filepath.Dir(sourceAuth))), before) {
				t.Error("source catalog changed")
			}
		})
	}
}

func TestProtocolE2EAuthCopyAllowlistAndPermissions(t *testing.T) {
	source := protocolE2ESyntheticAuthStore(t, "global", true)
	for _, name := range []string{".credential-transaction", ".credential-transaction.lock", "arbitrary-cache"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte("excluded-synthetic-data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(source, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nonexistent", filepath.Join(source, "ignored-link")); err != nil {
		t.Fatal(err)
	}
	before := protocolE2ESnapshotTree(t, source)
	destination := t.TempDir()
	if err := os.Chmod(destination, 0755); err != nil {
		t.Fatal(err)
	}
	if err := protocolE2ECopyAuthStore(source, destination); err != nil {
		t.Fatal("synthetic copy failed", err)
	}
	copied := protocolE2ESnapshotTree(t, destination)
	if len(copied) != 4 || copied["."].mode.Perm() != 0700 {
		t.Fatal("copy contains non-allowlisted files or unsafe directory permissions")
	}
	for _, name := range []string{"user", "machine_id", authBindingName} {
		info, ok := copied[name]
		if !ok || !info.mode.IsRegular() || info.mode.Perm() != 0600 || info.data != before[name].data {
			t.Error("copy did not preserve allowlisted bytes as 0600 regular files")
		}
		original, _ := os.Lstat(filepath.Join(source, name))
		copyInfo, _ := os.Lstat(filepath.Join(destination, name))
		if os.SameFile(original, copyInfo) {
			t.Error("copy used a link instead of independent bytes")
		}
	}
	if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
		t.Error("copy mutated source tree")
	}
	// A source transaction lock must not be acquired, copied, or waited on.
	h, err := newProtocolE2EAuthHarness(t, context.Background(), false, envLookup(map[string]string{"QODER2API_E2E": "1", "QODER2API_E2E_AUTH_DIR": source}))
	if err != nil {
		t.Fatal("read-only setup inspected excluded transaction state", err)
	}
	if h.Close() {
		t.Error("read-only close failed")
	}
	if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
		t.Error("setup changed source transaction state")
	}
}

func TestProtocolE2EAuthCopyRejectsUnsafeAllowlistedFiles(t *testing.T) {
	for _, name := range []string{"user", "machine_id", authBindingName} {
		for _, kind := range []string{"missing", "directory", "symlink", "dangling-symlink", "unreadable"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				source := protocolE2ESyntheticAuthStore(t, "global", true)
				path := filepath.Join(source, name)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "directory":
					err = os.Mkdir(path, 0700)
				case "symlink", "dangling-symlink":
					target := filepath.Join(t.TempDir(), "synthetic-link-target")
					if kind == "symlink" {
						if err := os.WriteFile(target, data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					err = os.Symlink(target, path)
				case "unreadable":
					err = os.WriteFile(path, data, 0000)
				}
				if err != nil {
					t.Fatal(err)
				}
				// Snapshot cannot read an intentionally unreadable file as an unprivileged user.
				err = protocolE2ECopyAuthStore(source, t.TempDir())
				if name == authBindingName && kind == "missing" {
					if err != nil {
						t.Error("optional missing binding was not allowed")
					}
				} else if err == nil {
					t.Error("unsafe or missing required allowlisted file was accepted")
				} else if strings.Contains(err.Error(), source) || strings.Contains(err.Error(), string(data)) {
					t.Error("copy error disclosed source path or contents")
				}
			})
		}
	}
}

func TestProtocolE2EAuthSetupValidatesCopiedBinding(t *testing.T) {
	for _, kind := range []string{"region-mismatch", "issuer-mismatch", "malformed", "empty"} {
		t.Run(kind, func(t *testing.T) {
			source := protocolE2ESyntheticAuthStore(t, "cn", true)
			env := map[string]string{"QODER2API_E2E": "1", "QODER2API_E2E_AUTH_DIR": source, "QODER2API_E2E_REGION": "cn"}
			switch kind {
			case "region-mismatch":
				env["QODER2API_E2E_REGION"] = "global"
			case "issuer-mismatch":
				env["QODER2API_E2E_OPENAPI_ENDPOINT"] = "https://issuer-override.invalid"
			case "malformed", "empty":
				var data []byte
				if kind == "malformed" {
					data = []byte("synthetic-invalid-binding-secret")
				}
				if err := os.WriteFile(filepath.Join(source, authBindingName), data, 0640); err != nil {
					t.Fatal(err)
				}
			}
			before := protocolE2ESnapshotTree(t, source)
			h, err := newProtocolE2EAuthHarness(t, context.Background(), false, envLookup(env))
			if h != nil {
				h.Close()
			}
			if err == nil || h != nil {
				t.Error("invalid copied binding bypassed persistent-manager validation")
			} else if strings.Contains(err.Error(), source) || strings.Contains(err.Error(), "secret") {
				t.Error("binding failure exposed source path or contents")
			}
			if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
				t.Error("failed setup mutated source binding/store")
			}
		})
	}
}

type protocolE2ECleanupContext struct {
	protocolContext
	onClose func()
}

func (c *protocolE2ECleanupContext) Close() error {
	c.onClose()
	return c.protocolContext.Close()
}

func TestProtocolE2EAuthSetupClosesBeforeCopyCleanup(t *testing.T) {
	source := protocolE2ESyntheticAuthStore(t, "global", true)
	before := protocolE2ESnapshotTree(t, source)
	var copyDir string
	closed := 0
	var h *protocolE2EHarness
	t.Run("synthetic-cleanup", func(t *testing.T) {
		var err error
		h, err = newProtocolE2EAuthHarness(t, context.Background(), false, envLookup(map[string]string{"QODER2API_E2E": "1", "QODER2API_E2E_AUTH_DIR": source}))
		if err != nil {
			t.Fatal("synthetic setup failed", err)
		}
		copyDir = filepath.Dir(h.auth.authFile)
		h.auth.protoCtx = &protocolE2ECleanupContext{protocolContext: h.auth.protoCtx, onClose: func() {
			closed++
			if _, err := os.Stat(copyDir); err != nil {
				t.Error("temporary auth copy was removed before auth context close")
			}
		}}
		h.auth.credentialDirty = true
	})
	if closed != 1 || h == nil || !h.auth.closed || h.capabilities.credentialEncrypt.Load() != 0 {
		t.Fatal("harness cleanup did not close read-only auth exactly once")
	}
	if _, err := os.Stat(copyDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("private auth copy was not removed after close")
	}
	if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
		t.Error("cleanup changed source store")
	}
}

func TestProtocolE2EAuthSetupHonorsSetupContext(t *testing.T) {
	source := protocolE2ESyntheticAuthStore(t, "global", true)
	before := protocolE2ESnapshotTree(t, source)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h, err := newProtocolE2EAuthHarness(t, ctx, false, envLookup(map[string]string{"QODER2API_E2E": "1", "QODER2API_E2E_AUTH_DIR": source}))
	if h != nil {
		h.Close()
	}
	if h != nil || err == nil {
		t.Error("setup ignored canceled constructor context")
	}
	if !reflect.DeepEqual(protocolE2ESnapshotTree(t, source), before) {
		t.Error("canceled setup changed source store")
	}
}

func protocolE2EEnvironmentConfig(lookupEnv func(string) (string, bool)) (protocolE2EConfig, error) {
	cfg := appConfig{
		region:          lookupEnvOr(lookupEnv, "QODER2API_E2E_REGION", "global"),
		authDir:         strings.TrimSpace(lookupEnvOr(lookupEnv, "QODER2API_E2E_AUTH_DIR", "")),
		inferEndpoint:   lookupEnvOr(lookupEnv, "QODER2API_E2E_INFER_ENDPOINT", ""),
		openapiEndpoint: lookupEnvOr(lookupEnv, "QODER2API_E2E_OPENAPI_ENDPOINT", ""),
		webEndpoint:     lookupEnvOr(lookupEnv, "QODER2API_E2E_WEB_ENDPOINT", ""),
	}
	// Resolve only the explicitly selected E2E profile, never general app/PAT
	// discovery or an unrelated region selector.
	if err := cfg.resolveProfile(lookupEnv); err != nil {
		return protocolE2EConfig{}, err
	}
	return protocolE2EConfig{region: cfg.region, authDir: cfg.authDir, inferEndpoint: cfg.inferEndpoint, openapiEndpoint: cfg.openapiEndpoint, webEndpoint: cfg.webEndpoint}, nil
}

func protocolE2ECloneDefaultTransport() (http.RoundTripper, func()) {
	if standard, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := standard.Clone()
		return cloned, cloned.CloseIdleConnections
	}
	return http.DefaultTransport, func() {}
}

// Copy bytes, never links, and never transaction markers, locks, or unrelated
// files. readAuthFile rejects symlinks/nonregular files and checks read identity.
// Errors deliberately omit source paths and credential/binding contents.
func protocolE2ECopyAuthStore(source, destination string) error {
	if _, err := checkedDirectory(source); err != nil {
		return errProtocolE2EAuthPrerequisite
	}
	if _, err := checkedDirectory(destination); err != nil {
		return errors.New("auth-copy-directory")
	}
	if err := os.Chmod(destination, 0700); err != nil {
		return errors.New("auth-copy-directory")
	}
	for _, name := range []string{"user", "machine_id", authBindingName} {
		data, revision, err := readAuthFile(filepath.Join(source, name))
		if err != nil {
			return errProtocolE2EAuthPrerequisite
		}
		if name == authBindingName && !revision.exists {
			continue
		}
		if !revision.exists || (name != authBindingName && len(data) == 0) {
			return errProtocolE2EAuthPrerequisite
		}
		file, err := os.OpenFile(filepath.Join(destination, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("auth-copy-file")
		}
		_, writeErr := file.Write(data)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return errors.New("auth-copy-file")
		}
	}
	return nil
}

func protocolE2EFatal(t *testing.T, category string) {
	t.Helper()
	t.Fatalf("protocol E2E setup failed: status=0 category=%s length=0", category)
}

var (
	errProtocolE2EDisabled         = errors.New("authorized protocol E2E disabled; set QODER2API_E2E=1")
	errProtocolE2ERefreshDisabled  = errors.New("authorized refresh E2E disabled; set QODER2API_E2E_REFRESH=1")
	errProtocolE2EAuthPrerequisite = errors.New("authorized encrypted local credential prerequisite unavailable")
)

// The setup seam accepts an isolated environment so synthetic tests never enable
// the process-wide live E2E gate. It performs no inference or refresh requests.
func newProtocolE2EAuthHarness(t *testing.T, setupCtx context.Context, allowRefresh bool, lookupEnv func(string) (string, bool)) (*protocolE2EHarness, error) {
	t.Helper()
	if lookupEnvOr(lookupEnv, "QODER2API_E2E", "") != "1" {
		return nil, errProtocolE2EDisabled
	}
	if allowRefresh && lookupEnvOr(lookupEnv, "QODER2API_E2E_REFRESH", "") != "1" {
		return nil, errProtocolE2ERefreshDisabled
	}
	config, err := protocolE2EEnvironmentConfig(lookupEnv)
	if err != nil {
		return nil, err
	}
	authDir := config.authDir
	if allowRefresh {
		for _, name := range []string{"machine_id", "user"} {
			data, revision, err := readAuthFile(filepath.Join(authDir, name))
			if err != nil || !revision.exists || len(data) == 0 {
				return nil, errProtocolE2EAuthPrerequisite
			}
		}
	} else {
		// Register TempDir cleanup first: the later harness Close callback must
		// run before its persistent copy disappears (testing cleanup is LIFO).
		authDir = t.TempDir()
		if err := protocolE2ECopyAuthStore(config.authDir, authDir); err != nil {
			return nil, err
		}
	}
	services, err := newProtocolServices(productionProtocolHostDeps())
	if err != nil || services == nil {
		return nil, errors.New("protocol-services")
	}
	harness := &protocolE2EHarness{
		services:       services,
		capabilities:   &protocolE2ECapabilityCounts{},
		readOnlyAuth:   !allowRefresh,
		sourceAuthFile: filepath.Join(config.authDir, "user"),
	}
	t.Cleanup(func() { harness.Close() })
	harness.installCapabilityCounters()
	auth, err := newAuthManagerWithOptions(services, authDir, config.openapiEndpoint, config.inferEndpoint, config.webEndpoint, func(string, ...any) {}, authManagerOptions{ctx: setupCtx, region: config.region})
	if err != nil || auth == nil {
		return nil, errors.New("auth-construction")
	}
	harness.auth = auth
	// Install the transport immediately after construction, before load can
	// invoke any auth capability. Read-only mode must never reach auth HTTP.
	if allowRefresh {
		baseTransport, closeIdle := protocolE2ECloneDefaultTransport()
		harness.refreshTransport = &protocolE2ECountingTransport{base: baseTransport}
		harness.closeIdle = append(harness.closeIdle, closeIdle)
		auth.httpc = &http.Client{Transport: harness.refreshTransport, Timeout: protocolE2ERefreshTimeout, CheckRedirect: protocolHarnessRejectRedirect}
	} else {
		harness.denyRefresh = &protocolHarnessDenyTransport{}
		auth.httpc = &http.Client{Transport: harness.denyRefresh, Timeout: protocolE2ERefreshTimeout, CheckRedirect: protocolHarnessRejectRedirect}
	}
	if err := auth.load(setupCtx); err != nil {
		return nil, errors.New("credential-load")
	}
	clearAuthManagerDirtyForHarness(auth)
	return harness, nil
}

func newProtocolE2EHarness(t *testing.T, allowRefresh bool) *protocolE2EHarness {
	t.Helper()
	setupCtx, cancel := context.WithTimeout(context.Background(), protocolE2ESetupTimeout)
	defer cancel()
	harness, err := newProtocolE2EAuthHarness(t, setupCtx, allowRefresh, os.LookupEnv)
	if errors.Is(err, errProtocolE2EDisabled) || errors.Is(err, errProtocolE2ERefreshDisabled) || errors.Is(err, errProtocolE2EAuthPrerequisite) {
		t.Skip(err.Error())
	}
	if err != nil {
		protocolE2EFatal(t, "auth-setup")
	}
	auth, services := harness.auth, harness.services
	if harness.capabilities.credentialDecrypt.Load() == 0 {
		t.Skip("authorized encrypted local credential prerequisite unavailable")
	}
	if !protocolE2EHasUsableToken(auth) {
		t.Skip("authorized local token prerequisite unavailable")
	}
	if !allowRefresh {
		protocolE2ERequireFreshCredential(t, auth)
	}

	input := protocolE2ERuntimeInput(auth)
	if _, err := services.runtimeFields.Generate(setupCtx, input); err != nil {
		protocolE2EFatal(t, "runtime-fields")
	}
	resolver := protocolE2ELoadCatalog(t, setupCtx, harness)

	baseTransport, closeIdle := protocolE2ECloneDefaultTransport()
	harness.closeIdle = append(harness.closeIdle, closeIdle)
	harness.transport = &protocolE2ECountingTransport{base: baseTransport}
	server := &server{
		auth:   auth,
		models: resolver,
		httpc: &http.Client{
			Transport:     harness.transport,
			Timeout:       protocolE2ERouteTimeout,
			CheckRedirect: protocolHarnessRejectRedirect,
		},
		logf:    func(string, ...any) {},
		dumpDir: "",
	}
	harness.handler = server.handler()
	return harness
}

func (h *protocolE2EHarness) installCapabilityCounters() {
	installProtocolE2ECapabilityCounters(h.services, h.capabilities)
}

func installProtocolE2ECapabilityCounters(services *protocolServices, counts *protocolE2ECapabilityCounts) {
	if services == nil || counts == nil {
		return
	}
	services.credentials = &protocolE2ECountingCredentialCodec{inner: services.credentials, counts: counts}
	services.runtimeFields = &protocolE2ECountingRuntimeFieldGenerator{inner: services.runtimeFields, counts: counts}
	services.modelCache = &protocolE2ECountingModelCacheDecryptor{inner: services.modelCache, counts: counts}
	services.contextFactory = &protocolE2ECountingContextFactory{inner: services.contextFactory, counts: counts}
}

func (c *protocolE2ECapabilityCounts) snapshot() protocolHarnessCapabilitySnapshot {
	if c == nil {
		return protocolHarnessCapabilitySnapshot{}
	}
	return protocolHarnessCapabilitySnapshot{
		CredentialEncrypt: c.credentialEncrypt.Load(),
		CredentialDecrypt: c.credentialDecrypt.Load(),
		RuntimeGenerate:   c.runtimeGenerate.Load(),
		ModelCacheDecrypt: c.modelCacheDecrypt.Load(),
		ContextNew:        c.contextNew.Load(),
		ContextPrepare:    c.contextPrepare.Load(),
	}
}

func protocolE2EHasUsableToken(auth *authManager) bool {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.ui != nil && auth.ui.SecurityOAuthToken != ""
}

func protocolE2EHasRefreshToken(auth *authManager) bool {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.ui != nil && auth.ui.RefreshToken != ""
}

func protocolE2ERequireFreshCredential(t *testing.T, auth *authManager) {
	t.Helper()
	auth.mu.Lock()
	expiry := int64(0)
	if auth.ui != nil {
		expiry = auth.ui.ExpireTime
	}
	auth.mu.Unlock()
	if expiry != 0 && expiry-refreshSkewSec < time.Now().Unix() {
		t.Skip("authorized local credential requires refresh; run the refresh E2E gate")
	}
}

func protocolE2ERuntimeInput(auth *authManager) runtimeFieldInput {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.runtimeFieldInputLocked()
}

func protocolE2ELoadCatalog(t *testing.T, ctx context.Context, harness *protocolE2EHarness) *modelResolver {
	t.Helper()
	if harness == nil || harness.auth == nil || harness.services == nil || harness.sourceAuthFile == "" {
		protocolE2EFatal(t, "catalog-harness")
	}
	auth := harness.auth
	services := harness.services
	authFile := harness.sourceAuthFile
	auth.mu.Lock()
	uid := ""
	if auth.ui != nil {
		uid = auth.ui.UID
	}
	auth.mu.Unlock()
	if uid == "" {
		t.Skip("authorized catalog UID prerequisite unavailable")
	}
	if services.modelCache == nil || harness.capabilities == nil {
		protocolE2EFatal(t, "catalog-decryptor")
	}
	beforeDecrypt := harness.capabilities.modelCacheDecrypt.Load()
	merged := false
	catalog := loadCatalog(ctx, services.modelCache, authFile, uid, "", func(format string, _ ...any) {
		if format == "catalog merged: %d models" {
			merged = true
		}
	})
	afterDecrypt := harness.capabilities.modelCacheDecrypt.Load()
	if afterDecrypt == beforeDecrypt {
		t.Skip("authorized encrypted local catalog prerequisite unavailable")
	}
	if !merged || !protocolHarnessCapabilityCallAdvanced(beforeDecrypt, afterDecrypt) {
		protocolE2EFatal(t, "catalog-decrypt-or-schema")
	}
	resolver := newModelResolver(catalog, nil, "auto", "ultimate")
	if resolver == nil || len(resolver.byKey) == 0 {
		protocolE2EFatal(t, "model-resolver-empty")
	}
	return resolver
}

func protocolE2ERouteSpecs() []protocolE2ERouteSpec {
	return []protocolE2ERouteSpec{
		{
			name: "anthropic_messages",
			path: "/v1/messages",
			json: protocolE2EJSONExpectation{
				strings: []protocolE2EJSONField{
					{key: "type", allowed: []string{"message"}},
					{key: "role", allowed: []string{"assistant"}},
				},
				arrays: []string{"content"},
			},
			sse: protocolE2ESSEExpectation{
				events:            []string{"message_start", "message_stop"},
				validateEventData: protocolHarnessAnthropicStreamFrameValid,
			},
		},
		{
			name: "openai_chat_completions",
			path: "/v1/chat/completions",
			json: protocolE2EJSONExpectation{
				strings: []protocolE2EJSONField{{key: "object", allowed: []string{"chat.completion"}}},
				arrays:  []string{"choices"},
			},
			sse: protocolE2ESSEExpectation{
				requireDone:  true,
				validateData: protocolHarnessChatStreamFrameValid,
			},
		},
		{
			name: "openai_responses",
			path: "/v1/responses",
			json: protocolE2EJSONExpectation{
				strings: []protocolE2EJSONField{
					{key: "object", allowed: []string{"response"}},
					{key: "status", allowed: []string{"completed", "incomplete"}},
				},
				arrays: []string{"output"},
			},
			sse: protocolE2ESSEExpectation{
				events:            []string{"response.created", "response.completed"},
				validateEventData: protocolHarnessResponsesStreamFrameValid,
			},
		},
	}
}

func protocolE2ERequestBody(route string, stream bool) ([]byte, error) {
	switch route {
	case "anthropic_messages":
		return json.Marshal(map[string]any{
			"model":      "auto",
			"max_tokens": 8,
			"stream":     stream,
			"messages": []map[string]any{{
				"role": "user", "content": protocolE2EPrompt,
			}},
		})
	case "openai_chat_completions":
		return json.Marshal(map[string]any{
			"model":      "auto",
			"max_tokens": 8,
			"stream":     stream,
			"messages": []map[string]any{{
				"role": "user", "content": protocolE2EPrompt,
			}},
		})
	case "openai_responses":
		return json.Marshal(map[string]any{
			"model":             "auto",
			"max_output_tokens": 8,
			"stream":            stream,
			"input":             protocolE2EPrompt,
		})
	default:
		return nil, errors.New("unknown synthetic route")
	}
}

func newProtocolE2EResponseProbe(stream bool, jsonExpectation protocolE2EJSONExpectation, sseExpectation protocolE2ESSEExpectation) *protocolE2EResponseProbe {
	reader, writer := io.Pipe()
	validation := make(chan protocolE2EValidation, 1)
	go func() {
		defer reader.Close()
		if stream {
			validation <- validateProtocolE2ESSE(reader, sseExpectation)
			return
		}
		validation <- validateProtocolE2EJSON(reader, jsonExpectation)
	}()
	return &protocolE2EResponseProbe{
		header:     make(http.Header),
		pipe:       writer,
		validation: validation,
	}
}

func (p *protocolE2EResponseProbe) Header() http.Header {
	return p.header
}

func (p *protocolE2EResponseProbe) WriteHeader(status int) {
	if p.status == 0 {
		p.status = status
	}
}

func (p *protocolE2EResponseProbe) Write(payload []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	p.length += int64(len(payload))
	return p.pipe.Write(payload)
}

func (*protocolE2EResponseProbe) Flush() {}

func (p *protocolE2EResponseProbe) finish() protocolE2EValidation {
	_ = p.pipe.Close()
	return <-p.validation
}

func (p *protocolE2EResponseProbe) statusCode() int {
	if p.status == 0 {
		return http.StatusOK
	}
	return p.status
}

func validateProtocolE2EJSON(reader io.Reader, expectation protocolE2EJSONExpectation) protocolE2EValidation {
	defer func() {
		_, _ = io.Copy(io.Discard, reader)
	}()
	decoder := json.NewDecoder(reader)
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return protocolE2EValidation{category: "json-object"}
	}
	seenStrings := make([]bool, len(expectation.strings))
	seenArrays := make([]bool, len(expectation.arrays))
	valid := true
	category := ""
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, keyOK := keyToken.(string)
		if err != nil || !keyOK {
			valid = false
			category = "json-schema"
			break
		}
		matched := false
		for index, field := range expectation.strings {
			if key != field.key {
				continue
			}
			matched = true
			value, err := decoder.Token()
			if err != nil {
				valid = false
				category = "json-schema"
				break
			}
			if opening, ok := value.(json.Delim); ok {
				_ = discardProtocolE2EJSONContainer(decoder, opening)
				valid = false
				category = "json-discriminator"
				break
			}
			stringValue, ok := value.(string)
			if !ok || !protocolE2EStringAllowed(stringValue, field.allowed) {
				valid = false
				category = "json-discriminator"
				break
			}
			seenStrings[index] = true
			break
		}
		if !valid {
			break
		}
		if matched {
			continue
		}
		for index, arrayKey := range expectation.arrays {
			if key != arrayKey {
				continue
			}
			matched = true
			value, err := decoder.Token()
			if err != nil {
				valid = false
				category = "json-schema"
				break
			}
			opening, ok := value.(json.Delim)
			if !ok || opening != json.Delim('[') {
				if ok {
					_ = discardProtocolE2EJSONContainer(decoder, opening)
				}
				valid = false
				category = "json-array"
				break
			}
			seenArrays[index] = true
			if err := discardProtocolE2EJSONContainer(decoder, opening); err != nil {
				valid = false
				category = "json-schema"
			}
			break
		}
		if !valid {
			break
		}
		if matched {
			continue
		}
		if err := discardProtocolE2EJSONValue(decoder); err != nil {
			valid = false
			category = "json-schema"
			break
		}
	}
	if valid {
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			valid = false
			category = "json-schema"
		}
	}
	if valid {
		if _, err := decoder.Token(); err != io.EOF {
			valid = false
			category = "json-trailing"
		}
	}
	if valid {
		for _, seen := range seenStrings {
			if !seen {
				valid = false
				category = "json-discriminator"
				break
			}
		}
	}
	if valid {
		for _, seen := range seenArrays {
			if !seen {
				valid = false
				category = "json-array"
				break
			}
		}
	}
	if !valid {
		return protocolE2EValidation{category: category}
	}
	return protocolE2EValidation{ok: true}
}

func protocolE2EStringAllowed(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func discardProtocolE2EJSONValue(decoder *json.Decoder) error {
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	opening, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	return discardProtocolE2EJSONContainer(decoder, opening)
}

func discardProtocolE2EJSONContainer(decoder *json.Decoder, opening json.Delim) error {
	switch opening {
	case json.Delim('{'):
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			if _, ok := key.(string); !ok {
				return errors.New("invalid JSON object key")
			}
			if err := discardProtocolE2EJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid JSON object close")
		}
		return nil
	case json.Delim('['):
		for decoder.More() {
			if err := discardProtocolE2EJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array close")
		}
		return nil
	default:
		return errors.New("invalid JSON container")
	}
}

func validateProtocolE2ESSE(reader io.Reader, expectation protocolE2ESSEExpectation) protocolE2EValidation {
	defer func() {
		_, _ = io.Copy(io.Discard, reader)
	}()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 512<<10)
	seenEvents := make([]bool, len(expectation.events))
	sawData := false
	sawFrame := false
	frameHasData := false
	sawDone := false
	sawValidatedData := false
	dataValid := true
	currentEvent := ""
	for scanner.Scan() {
		line := bytes.TrimSuffix(scanner.Bytes(), []byte{'\r'})
		if len(line) == 0 {
			if frameHasData {
				sawFrame = true
			}
			frameHasData = false
			currentEvent = ""
			continue
		}
		if bytes.HasPrefix(line, []byte("event:")) {
			event := bytes.TrimSpace(line[len("event:"):])
			currentEvent = string(event)
			for index, required := range expectation.events {
				if bytes.Equal(event, []byte(required)) {
					seenEvents[index] = true
				}
			}
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			data := bytes.TrimSpace(line[len("data:"):])
			if len(data) > 0 {
				sawData = true
				frameHasData = true
			}
			if bytes.Equal(data, []byte("[DONE]")) {
				sawDone = true
				continue
			}
			if expectation.validateData != nil && len(data) > 0 {
				if expectation.validateData(data) {
					sawValidatedData = true
				} else {
					dataValid = false
				}
			}
			if expectation.validateEventData != nil && len(data) > 0 {
				if expectation.validateEventData(currentEvent, data) {
					sawValidatedData = true
				} else {
					dataValid = false
				}
			}
		}
	}
	if frameHasData {
		sawFrame = true
	}
	if scanner.Err() != nil {
		return protocolE2EValidation{category: "sse-read"}
	}
	if !sawData || !sawFrame {
		return protocolE2EValidation{category: "sse-framing"}
	}
	if !dataValid || ((expectation.validateData != nil || expectation.validateEventData != nil) && !sawValidatedData) {
		return protocolE2EValidation{category: "sse-payload"}
	}
	for _, seen := range seenEvents {
		if !seen {
			return protocolE2EValidation{category: "sse-event"}
		}
	}
	if expectation.requireDone && !sawDone {
		return protocolE2EValidation{category: "sse-terminal"}
	}
	return protocolE2EValidation{ok: true}
}

func protocolE2EContentTypeOK(stream bool, contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if stream {
		return mediaType == "text/event-stream"
	}
	return mediaType == "application/json"
}

func (h *protocolE2EHarness) runRoute(t *testing.T, spec protocolE2ERouteSpec, stream bool) protocolE2EResult {
	t.Helper()
	body, err := protocolE2ERequestBody(spec.name, stream)
	if err != nil {
		protocolE2EFatal(t, "synthetic-request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), protocolE2ERouteTimeout)
	defer cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, spec.path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	probe := newProtocolE2EResponseProbe(stream, spec.json, spec.sse)
	beforeCalls := h.transport.calls.Load()
	beforeReadFailures := h.transport.readFailures.Load()
	beforeUpstream := h.transport.upstreamSnapshot()
	beforePrepare := h.capabilities.contextPrepare.Load()
	beforeRefresh := int64(0)
	if h.denyRefresh != nil {
		beforeRefresh = h.denyRefresh.calls.Load()
	}
	started := time.Now()
	h.handler.ServeHTTP(probe, request)
	validation := probe.finish()
	duration := time.Since(started).Round(time.Millisecond)
	afterCalls := h.transport.calls.Load()
	afterPrepare := h.capabilities.contextPrepare.Load()
	afterRefresh := beforeRefresh
	if h.denyRefresh != nil {
		afterRefresh = h.denyRefresh.calls.Load()
	}
	status := probe.statusCode()
	httpSuccess := status == http.StatusOK
	schemaSuccess := validation.ok && protocolE2EContentTypeOK(stream, probe.header.Get("Content-Type"))
	afterUpstream := h.transport.upstreamSnapshot()
	upstreamReason := protocolHarnessUpstreamReasonDelta(beforeUpstream, afterUpstream)
	upstreamShapes := protocolHarnessUpstreamShapeDelta(beforeUpstream, afterUpstream)
	result := protocolE2EResult{
		Route:          spec.name,
		Stream:         stream,
		HTTPStatus:     status,
		HTTPSuccess:    httpSuccess,
		SchemaSuccess:  schemaSuccess,
		Duration:       duration,
		UpstreamShapes: upstreamShapes,
	}
	protocolE2ELogResult(t, result)

	category := ""
	switch {
	case ctx.Err() != nil:
		category = "route-timeout"
	case !httpSuccess:
		category = "http-status"
	case !protocolE2EContentTypeOK(stream, probe.header.Get("Content-Type")):
		category = "content-type"
	case upstreamReason != "":
		category = "upstream-sse-" + string(upstreamReason)
	case h.transport.readFailures.Load() != beforeReadFailures:
		category = "upstream-body-read"
	case !validation.ok:
		category = validation.category
	case !protocolHarnessPrimaryAttemptsValid(afterPrepare-beforePrepare, afterCalls-beforeCalls):
		category = "primary-attempt-count"
	case afterRefresh != beforeRefresh:
		category = "unexpected-refresh"
	}
	if category != "" {
		t.Errorf(
			"protocol E2E route failed: backend=native route=%s stream=%t status=%d category=%s length=%d",
			result.Route,
			result.Stream,
			result.HTTPStatus,
			category,
			probe.length,
		)
	}
	return result
}

func protocolE2ELogResult(t *testing.T, result protocolE2EResult) {
	t.Helper()
	upstreamShapes := strings.Join(result.UpstreamShapes, ",")
	if upstreamShapes == "" {
		upstreamShapes = "none"
	}
	t.Logf(
		"protocol_e2e backend=native route=%s stream=%t status=%d http_success=%t schema_success=%t duration=%s upstream_shapes=%s",
		result.Route,
		result.Stream,
		result.HTTPStatus,
		result.HTTPSuccess,
		result.SchemaSuccess,
		result.Duration,
		upstreamShapes,
	)
}

func runProtocolE2ENative(t *testing.T) {
	t.Helper()
	requireProtocolE2E(t)
	harness := newProtocolE2EHarness(t, false)
	for _, spec := range protocolE2ERouteSpecs() {
		for _, stream := range []bool{false, true} {
			name := spec.name + "/nonstream"
			if stream {
				name = spec.name + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				harness.runRoute(t, spec, stream)
			})
		}
	}
	if harness.Close() {
		t.Errorf("protocol E2E cleanup failed: status=0 category=cleanup length=0")
	}
	if !harness.capabilities.snapshot().complete(false) {
		t.Errorf("protocol E2E native gate failed: status=0 category=capability-not-executed length=0")
	}
}

func runProtocolE2ERefresh(t *testing.T) {
	t.Helper()
	requireProtocolE2E(t)
	if os.Getenv("QODER2API_E2E_REFRESH") != "1" {
		t.Skip("authorized refresh E2E disabled; set QODER2API_E2E_REFRESH=1")
	}
	harness := newProtocolE2EHarness(t, true)
	if !protocolE2EHasRefreshToken(harness.auth) {
		t.Skip("authorized refresh token prerequisite unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), protocolE2ERefreshTimeout)
	beforeRefresh := protocolHarnessRefreshCounts{
		HTTP:    harness.refreshTransport.calls.Load(),
		Encrypt: harness.capabilities.credentialEncrypt.Load(),
		Runtime: harness.capabilities.runtimeGenerate.Load(),
		Context: harness.capabilities.contextNew.Load(),
	}
	started := time.Now()
	err := harness.auth.forceRefresh(ctx)
	duration := time.Since(started).Round(time.Millisecond)
	cancel()
	if err != nil {
		t.Fatalf("protocol E2E refresh failed: status=0 category=refresh-transaction length=0")
	}
	afterRefresh := protocolHarnessRefreshCounts{
		HTTP:    harness.refreshTransport.calls.Load(),
		Encrypt: harness.capabilities.credentialEncrypt.Load(),
		Runtime: harness.capabilities.runtimeGenerate.Load(),
		Context: harness.capabilities.contextNew.Load(),
	}
	if !protocolHarnessRefreshAccountingValid(beforeRefresh, afterRefresh) {
		t.Fatalf("protocol E2E refresh failed: status=0 category=refresh-accounting length=0")
	}
	harness.denyRefresh = &protocolHarnessDenyTransport{}
	harness.auth.httpc = &http.Client{
		Transport:     harness.denyRefresh,
		Timeout:       protocolE2ERefreshTimeout,
		CheckRedirect: protocolHarnessRejectRedirect,
	}
	protocolE2ELogResult(t, protocolE2EResult{
		Route:         "force_refresh",
		HTTPStatus:    http.StatusOK,
		HTTPSuccess:   true,
		SchemaSuccess: true,
		Duration:      duration,
	})
	beforePostRefreshRoute := harness.denyRefresh.calls.Load()
	harness.runRoute(t, protocolE2ERouteSpecs()[0], false)
	if harness.denyRefresh.calls.Load() != beforePostRefreshRoute {
		t.Errorf("protocol E2E refresh failed: status=0 category=post-refresh-attempt-count length=0")
	}
	if harness.Close() {
		t.Errorf("protocol E2E cleanup failed: status=0 category=cleanup length=0")
	}
}

func (h *protocolE2EHarness) Close() bool {
	if h == nil {
		return false
	}
	h.closeOnce.Do(func() {
		if h.auth != nil {
			var authCloseErr error
			if h.readOnlyAuth {
				authCloseErr = closeAuthManagerReadOnlyForTest(h.auth)
			} else {
				authCloseErr = h.auth.Close()
			}
			if authCloseErr != nil {
				h.closeFailed = true
			}
		}
		if h.services != nil && h.services.Close(context.Background()) != nil {
			h.closeFailed = true
		}
		for _, closeIdle := range h.closeIdle {
			if closeIdle != nil {
				closeIdle()
			}
		}
	})
	return h.closeFailed
}

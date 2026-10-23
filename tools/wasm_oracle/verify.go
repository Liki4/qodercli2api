package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type credentialInput struct {
	MachineKey string `json:"machine_key"`
	Plain      string `json:"plain"`
}
type credentialExpected struct {
	Decrypted string `json:"decrypted"`
	Encrypted string `json:"encrypted"`
}
type runtimeInput struct {
	Raw string `json:"raw"`
}
type runtimeExpected struct {
	Raw             string `json:"raw"`
	EncryptUserInfo string `json:"encrypt_user_info"`
	Key             string `json:"key"`
}
type modelInput struct {
	Plain string `json:"plain"`
	UID   string `json:"uid"`
}
type modelExpected struct {
	Decrypted string `json:"decrypted"`
	Encrypted string `json:"encrypted"`
}
type inferInput struct {
	MachineID   string          `json:"machine_id"`
	Version     string          `json:"version"`
	User        json.RawMessage `json:"user"`
	Scene       json.RawMessage `json:"scene"`
	Endpoint    string          `json:"endpoint"`
	BodyRaw     string          `json:"body_raw"`
	ModelKey    string          `json:"model_key"`
	ModelSource string          `json:"model_source"`
}
type inferExpected struct {
	URL        string              `json:"url"`
	Header     map[string][]string `json:"header"`
	BodyString string              `json:"body_string"`
	BodyBytes  string              `json:"body_bytes"`
}

func verifyFixtures(ctx context.Context, source []byte, fixtures fixtureSet, out io.Writer) (freeAccounting, error) {
	for _, fixture := range fixtures {
		if err := validateWASMForIdentity(source, fixture.Oracle); err != nil {
			return freeAccounting{}, err
		}
	}
	backend, err := newWASMBackend(ctx, source)
	if err != nil {
		return freeAccounting{}, err
	}
	defer backend.Close(ctx)
	credential, err := mustDecode[credentialInput](fixtures["credential.json"].Input)
	if err != nil {
		return freeAccounting{}, err
	}
	credentialWant, _ := mustDecode[credentialExpected](fixtures["credential.json"].Expected)
	replay := newOrderedReplay(fixtures["credential.json"].Transcript, nil)
	backend.setReplay(replay)
	encrypted, err := backend.callString(ctx, "credential_storage_encrypt", credential.Plain, credential.MachineKey)
	if err != nil {
		return backend.accounting, err
	}
	decrypted, err := backend.callString(ctx, "credential_storage_decrypt", encrypted, credential.MachineKey)
	if err != nil {
		return backend.accounting, err
	}
	if err = replay.Exhausted(); err != nil {
		return backend.accounting, err
	}
	if encrypted != credentialWant.Encrypted || decrypted != credentialWant.Decrypted {
		return backend.accounting, fail("credential-output")
	}
	emitStatus(out, statusLine{"credential", transcriptShape(fixtures["credential.json"].Transcript), "PASS", ""})
	runtime, err := mustDecode[runtimeInput](fixtures["runtime-fields.json"].Input)
	if err != nil {
		return backend.accounting, err
	}
	runtimeWant, _ := mustDecode[runtimeExpected](fixtures["runtime-fields.json"].Expected)
	runtimeTranscript := fixtures["runtime-fields.json"].Transcript
	replay = newOrderedReplay(runtimeTranscript, entropyCalls(runtimeTranscript))
	backend.setReplay(replay)
	runtimeRaw, err := backend.callString(ctx, "generate_runtime_auth_fields", runtime.Raw)
	if err != nil {
		return backend.accounting, err
	}
	if err = replay.Exhausted(); err != nil {
		return backend.accounting, err
	}
	if runtimeRaw != runtimeWant.Raw {
		return backend.accounting, fail("runtime-output")
	}
	emitStatus(out, statusLine{"runtime", transcriptShape(runtimeTranscript), "PASS", ""})
	model, err := mustDecode[modelInput](fixtures["model-cache.json"].Input)
	if err != nil {
		return backend.accounting, err
	}
	modelWant, _ := mustDecode[modelExpected](fixtures["model-cache.json"].Expected)
	modelTranscript := fixtures["model-cache.json"].Transcript
	replay = newOrderedReplay(modelTranscript, entropyCalls(modelTranscript))
	backend.setReplay(replay)
	modelEncrypted, err := backend.callString(ctx, "model_cache_encrypt", model.Plain, model.UID)
	if err != nil {
		return backend.accounting, err
	}
	modelDecrypted, err := backend.callString(ctx, "model_cache_decrypt", modelEncrypted, model.UID)
	if err != nil {
		return backend.accounting, err
	}
	if err = replay.Exhausted(); err != nil {
		return backend.accounting, err
	}
	if modelEncrypted != modelWant.Encrypted || modelDecrypted != modelWant.Decrypted {
		return backend.accounting, fail("model-cache-output")
	}
	emitStatus(out, statusLine{"model-cache", transcriptShape(modelTranscript), "PASS", ""})
	if err := verifyInferFixture(ctx, backend, fixtures["infer-user.json"], "infer", out); err != nil {
		return backend.accounting, err
	}
	if err := verifyInferFixture(ctx, backend, fixtures["infer-user-no-org.json"], "infer-no-org", out); err != nil {
		return backend.accounting, err
	}
	if backend.accounting.ResultStrings != 9 || backend.accounting.Contexts != 2 || backend.accounting.RequestResults != 2 {
		return backend.accounting, fail("free-accounting")
	}
	if fixture, ok := fixtures["compatibility.json"]; ok {
		if err := verifyCompatibility(ctx, source, fixture, fixture.Oracle.Version); err != nil {
			return backend.accounting, err
		}
		emitStatus(out, statusLine{"compatibility", "cases:33", "PASS", ""})
	}
	return backend.accounting, nil
}

func verifyInferFixture(ctx context.Context, backend *wasmBackend, fixture fixtureDocument, operation string, out io.Writer) error {
	infer, err := mustDecode[inferInput](fixture.Input)
	if err != nil {
		return err
	}
	inferWant, err := mustDecode[inferExpected](fixture.Expected)
	if err != nil {
		return err
	}
	userJSON, err := compactJSON(infer.User)
	if err != nil {
		return err
	}
	sceneJSON, err := compactJSON(infer.Scene)
	if err != nil {
		return err
	}
	inferTranscript := fixture.Transcript
	if len(inferTranscript.EntropyReads) != 3 || len(inferTranscript.UnixMilli) != 1 {
		return fail("infer-transcript-shape")
	}
	calls := []hostCall{{Kind: hostEntropy, Length: inferTranscript.EntropyReads[0].Length}, {Kind: hostEntropy, Length: inferTranscript.EntropyReads[1].Length}, {Kind: hostClock}, {Kind: hostEntropy, Length: inferTranscript.EntropyReads[2].Length}}
	replay := newOrderedReplay(inferTranscript, calls)
	backend.setReplay(replay)
	contextPtr, err := backend.newContext(ctx, infer.MachineID, infer.Version, userJSON, sceneJSON)
	if err != nil {
		return err
	}
	defer func() {
		if contextPtr != 0 {
			_ = backend.freeContext(ctx, contextPtr)
		}
	}()
	prepared, err := backend.prepareInfer(ctx, contextPtr, infer.Endpoint, infer.BodyRaw, infer.ModelKey, infer.ModelSource)
	if err != nil {
		return err
	}
	if err = replay.Exhausted(); err != nil {
		return err
	}
	if prepared.URL != inferWant.URL || prepared.Body != inferWant.BodyString || !equalHeaders(prepared.Headers, inferWant.Header) {
		return fail("infer-output")
	}
	if err := backend.freeContext(ctx, contextPtr); err != nil {
		return err
	}
	contextPtr = 0
	shape := fmt.Sprintf("new[clock:0,entropy:%d,%d],prepare[clock:1,entropy:%d]", inferTranscript.EntropyReads[0].Length, inferTranscript.EntropyReads[1].Length, inferTranscript.EntropyReads[2].Length)
	emitStatus(out, statusLine{operation, shape, "PASS", ""})
	return nil
}
func equalHeaders(actual map[string]string, expected map[string][]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	normalized := map[string]string{}
	for key, value := range actual {
		normalized[strings.ToLower(key)] = value
	}
	for key, values := range expected {
		if len(values) != 1 || normalized[strings.ToLower(key)] != values[0] {
			return false
		}
	}
	return true
}

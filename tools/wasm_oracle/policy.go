package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

const (
	syntheticUID            = "synthetic-user-0001"
	syntheticOrg            = "synthetic-org-0001"
	syntheticMachineID      = "00000000-1111-4222-8333-444444444444"
	syntheticMachineKey     = "00000000-1111-42"
	syntheticEndpoint       = "https://example.invalid/base"
	syntheticUnixMilli      = int64(1781000123456)
	noOrgCallerInfo         = "synthetic-caller-info-not-effective"
	noOrgCallerKey          = "synthetic-caller-key-not-effective"
	credentialPlain         = `{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001","access_token":"synthetic-access-token-0001"}`
	runtimePlain            = `{"uid":"synthetic-user-0001","organization_id":"synthetic-org-0001","organization_tags":["synthetic-a","b"],"data_policy_agreed":true}`
	modelCachePlain         = `{"models":[{"id":"synthetic-model-0001"}]}`
	credentialEncryptedHash = "a0e4deb360797432176c394c52f217c7d02aae3264295ca5cfd54b177ea088a8"
	runtimeInfoHash         = "bc0fab36a0cc8df0676966ec3dd6fec41a80413237593cc056ab2b1d1a6296e5"
	runtimeKeyHash          = "5a898f95266409233c74ee7c69df167412b0cdf6df8aac6df77b3f13e153c140"
	runtimeRawHash          = "4367b54de3dd237fb6ecb87154b3ffc2240f36f1c378a89eaf0543fe5e56a4f0"
	modelEncryptedHash      = "2e1a24e5a6642ba6c93b2fdfc153eac7ca1c1903304d482b725870c9280d190b"
	inferBodyRawHash        = "2ba9677dfcb2f7ddc399a5f15ff4f398a35f5da2b84d58d5bee6c7af3f0c5076"
	inferBodyHash           = "fa5e0fe9f1b4288e9a552542d9066613bf6cbf6ed72a3d4acb4e09a54fbb097f"
	inferAuthorizationHash  = "0a3e0f29b2aaf2ee237cddde7118a3b04ef9751eade4da4e2f9916d9fd6295c4"
)

type credentialFixtureInput struct {
	MachineKey string `json:"machine_key"`
	Plain      string `json:"plain"`
}
type credentialFixtureExpected struct {
	Decrypted string `json:"decrypted"`
	Encrypted string `json:"encrypted"`
}
type runtimeFixtureInput struct {
	Raw string `json:"raw"`
}
type runtimeFixtureExpected struct {
	Raw             string `json:"raw"`
	EncryptUserInfo string `json:"encrypt_user_info"`
	Key             string `json:"key"`
}
type modelFixtureInput struct {
	Plain string `json:"plain"`
	UID   string `json:"uid"`
}
type modelFixtureExpected struct {
	Decrypted string `json:"decrypted"`
	Encrypted string `json:"encrypted"`
}
type runtimePlainObject struct {
	UID              string   `json:"uid"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationTags []string `json:"organization_tags"`
	DataPolicyAgreed bool     `json:"data_policy_agreed"`
}
type credentialPlainObject struct {
	UID            string `json:"uid"`
	OrganizationID string `json:"organization_id"`
	AccessToken    string `json:"access_token"`
}
type modelPlainObject struct {
	Models []struct {
		ID string `json:"id"`
	} `json:"models"`
}
type inferUser struct {
	UID              string   `json:"uid"`
	EncryptUserInfo  string   `json:"encrypt_user_info"`
	Key              string   `json:"key"`
	OrganizationID   string   `json:"organization_id"`
	OrganizationTags []string `json:"organization_tags"`
	DataPolicyAgreed bool     `json:"data_policy_agreed"`
}
type inferScene struct {
	ClientType      string `json:"client_type"`
	BusinessProduct string `json:"business_product"`
	BusinessType    string `json:"business_type"`
	Scene           string `json:"scene"`
}
type inferFixtureInputPolicy struct {
	MachineID   string     `json:"machine_id"`
	Version     string     `json:"version"`
	User        inferUser  `json:"user"`
	Scene       inferScene `json:"scene"`
	Endpoint    string     `json:"endpoint"`
	BodyRaw     string     `json:"body_raw"`
	ModelKey    string     `json:"model_key"`
	ModelSource string     `json:"model_source"`
}
type inferFixtureExpectedPolicy struct {
	URL        string              `json:"url"`
	Header     map[string][]string `json:"header"`
	BodyString string              `json:"body_string"`
	BodyBytes  string              `json:"body_bytes"`
}
type inferAuthorizationPayloadPolicy struct {
	Version     string `json:"version"`
	RequestID   string `json:"requestId"`
	Info        string `json:"info"`
	CosyVersion string `json:"cosyVersion"`
	IDEVersion  string `json:"ideVersion"`
}
type remoteBody struct {
	AgentID        string          `json:"agent_id"`
	AliyunUserType string          `json:"aliyun_user_type"`
	Business       remoteBusiness  `json:"business"`
	ChatContext    json.RawMessage `json:"chat_context"`
	ChatRecordID   string          `json:"chat_record_id"`
	ChatTask       string          `json:"chat_task"`
	CustomModel    json.RawMessage `json:"custom_model"`
	IsReply        bool            `json:"is_reply"`
	IsRetry        bool            `json:"is_retry"`
	Messages       []remoteMessage `json:"messages"`
	ModelConfig    remoteModel     `json:"model_config"`
	Parameters     remoteParams    `json:"parameters"`
	RequestID      string          `json:"request_id"`
	RequestSetID   string          `json:"request_set_id"`
	SessionID      string          `json:"session_id"`
	SessionType    string          `json:"session_type"`
	Source         int             `json:"source"`
	Stream         bool            `json:"stream"`
	System         string          `json:"system"`
	TaskID         string          `json:"task_id"`
	Tools          []remoteTool    `json:"tools"`
	Version        string          `json:"version"`
}
type remoteBusiness struct {
	BeginAt int64  `json:"begin_at"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Product string `json:"product"`
	Stage   string `json:"stage"`
	Type    string `json:"type"`
	Version string `json:"version"`
}
type remoteMessage struct {
	Role     string          `json:"role"`
	Content  string          `json:"content"`
	Contents []remoteContent `json:"contents,omitempty"`
}
type remoteContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type remoteModel struct {
	Key            string `json:"key"`
	Format         string `json:"format"`
	Source         string `json:"source"`
	Enable         bool   `json:"enable"`
	DisplayName    string `json:"display_name"`
	IsVL           bool   `json:"is_vl"`
	IsReasoning    bool   `json:"is_reasoning"`
	MaxInputTokens int    `json:"max_input_tokens"`
}
type remoteParams struct {
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
}
type remoteTool struct {
	Function remoteFunction `json:"function"`
	Type     string         `json:"type"`
}
type remoteFunction struct {
	Description string           `json:"description"`
	Name        string           `json:"name"`
	Parameters  remoteToolParams `json:"parameters"`
}
type remoteToolParams struct {
	Properties map[string]remoteProperty `json:"properties"`
	Required   []string                  `json:"required"`
	Type       string                    `json:"type"`
}
type remoteProperty struct {
	Type string `json:"type"`
}

func decodeStrictValue(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fail("fixture-synthetic-schema")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fail("fixture-synthetic-schema")
	}
	return nil
}

func stringHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func validateTranscript(name string, value transcript) error {
	var lengths []int
	var starts []byte
	var clocks []int64
	switch name {
	case "credential.json":
		lengths, starts = []int{}, []byte{}
	case "runtime-fields.json":
		lengths, starts = []int{16, 109}, []byte{1, 17}
	case "model-cache.json":
		lengths, starts = []int{12}, []byte{1}
	case "infer-user.json", "infer-user-no-org.json":
		lengths, starts, clocks = []int{16, 109, 16}, []byte{1, 17, 126}, []int64{syntheticUnixMilli}
	default:
		return fail("fixture-schema")
	}
	if !reflect.DeepEqual(value.UnixMilli, clocks) && !(len(value.UnixMilli) == 0 && len(clocks) == 0) {
		return fail("fixture-transcript-shape")
	}
	if len(value.EntropyReads) != len(lengths) {
		return fail("fixture-transcript-shape")
	}
	for i, read := range value.EntropyReads {
		if read.Length != lengths[i] || len(read.Bytes) != lengths[i] {
			return fail("fixture-transcript-shape")
		}
		for j, got := range read.Bytes {
			if got != starts[i]+byte(j) {
				return fail("fixture-transcript-bytes")
			}
		}
	}
	return nil
}

func validateNestedFixture(name string, fixture fixtureDocument) error {
	if _, err := policyForIdentity(fixture.Oracle); err != nil {
		return err
	}
	if name == "compatibility.json" {
		return validateCompatibilityFixture(fixture)
	}
	if err := validateTranscript(name, fixture.Transcript); err != nil {
		return err
	}
	switch name {
	case "credential.json":
		var input credentialFixtureInput
		var expected credentialFixtureExpected
		var plain credentialPlainObject
		if decodeStrictValue(fixture.Input, &input) != nil || decodeStrictValue(fixture.Expected, &expected) != nil || decodeStrictValue([]byte(input.Plain), &plain) != nil {
			return fail("fixture-synthetic-schema")
		}
		if input.MachineKey != syntheticMachineKey || input.Plain != credentialPlain || expected.Decrypted != credentialPlain || stringHash(expected.Encrypted) != credentialEncryptedHash || plain != (credentialPlainObject{syntheticUID, syntheticOrg, "synthetic-access-token-0001"}) {
			return fail("fixture-synthetic-schema")
		}
	case "runtime-fields.json":
		var input runtimeFixtureInput
		var expected runtimeFixtureExpected
		var raw runtimePlainObject
		if decodeStrictValue(fixture.Input, &input) != nil || decodeStrictValue(fixture.Expected, &expected) != nil || decodeStrictValue([]byte(input.Raw), &raw) != nil {
			return fail("fixture-synthetic-schema")
		}
		want := runtimePlainObject{syntheticUID, syntheticOrg, []string{"synthetic-a", "b"}, true}
		if input.Raw != runtimePlain || !reflect.DeepEqual(raw, want) || stringHash(expected.Raw) != runtimeRawHash || stringHash(expected.EncryptUserInfo) != runtimeInfoHash || stringHash(expected.Key) != runtimeKeyHash || expected.Raw != `{"encrypt_user_info":"`+expected.EncryptUserInfo+`","key":"`+expected.Key+`"}` {
			return fail("fixture-synthetic-schema")
		}
	case "model-cache.json":
		var input modelFixtureInput
		var expected modelFixtureExpected
		var plain modelPlainObject
		if decodeStrictValue(fixture.Input, &input) != nil || decodeStrictValue(fixture.Expected, &expected) != nil || decodeStrictValue([]byte(input.Plain), &plain) != nil {
			return fail("fixture-synthetic-schema")
		}
		if input.UID != syntheticUID || input.Plain != modelCachePlain || expected.Decrypted != modelCachePlain || stringHash(expected.Encrypted) != modelEncryptedHash || len(plain.Models) != 1 || plain.Models[0].ID != "synthetic-model-0001" {
			return fail("fixture-synthetic-schema")
		}
	case "infer-user.json":
		var input inferFixtureInputPolicy
		var expected inferFixtureExpectedPolicy
		var body remoteBody
		if decodeStrictValue(fixture.Input, &input) != nil || decodeStrictValue(fixture.Expected, &expected) != nil || decodeStrictValue([]byte(input.BodyRaw), &body) != nil {
			return fail("fixture-synthetic-schema")
		}
		if err := validateInferInput(input, body, fixture.Oracle.Version); err != nil {
			return err
		}
		if err := validateInferExpected(input, expected); err != nil {
			return err
		}
	case "infer-user-no-org.json":
		var input inferFixtureInputPolicy
		var expected inferFixtureExpectedPolicy
		var body remoteBody
		if decodeStrictValue(fixture.Input, &input) != nil || decodeStrictValue(fixture.Expected, &expected) != nil || decodeStrictValue([]byte(input.BodyRaw), &body) != nil {
			return fail("fixture-synthetic-schema")
		}
		if err := validateNoOrgInferInput(input, body, fixture.Oracle.Version); err != nil {
			return err
		}
		if err := validateNoOrgInferExpected(input, expected); err != nil {
			return err
		}
	default:
		return fail("fixture-schema")
	}
	return nil
}

func inferHashesForVersion(version string) (raw, body, authorization string) {
	if version == upgradeVersion {
		return "37e850fcf89472f0d097b99f68b74129ac9fe20e4d1e0e45b421e0d85e3eeeb6", "3d9ab43b07b0b47d402dbd2041e7d1f375304c0aa1ffb2857070b05da5d3adc5", "f8aa36989b61e90e663d34ea73c0c9ce03409ac469e292fd510919947a5043c6"
	}
	return inferBodyRawHash, inferBodyHash, inferAuthorizationHash
}

func validateInferInput(input inferFixtureInputPolicy, body remoteBody, version string) error {
	rawHash, _, _ := inferHashesForVersion(version)
	wantUser := inferUser{syntheticUID, input.User.EncryptUserInfo, input.User.Key, syntheticOrg, []string{"synthetic-a", "b"}, true}
	wantScene := inferScene{"5", "cli", "agent", "assistant"}
	if input.MachineID != syntheticMachineID || input.Version != version || !reflect.DeepEqual(input.User, wantUser) || stringHash(input.User.EncryptUserInfo) != runtimeInfoHash || stringHash(input.User.Key) != runtimeKeyHash || input.Scene != wantScene || input.Endpoint != syntheticEndpoint || input.ModelKey != "auto" || input.ModelSource != "system" || stringHash(input.BodyRaw) != rawHash {
		return fail("fixture-synthetic-schema")
	}
	return validateInferBody(body, version)
}

func validateNoOrgInferInput(input inferFixtureInputPolicy, body remoteBody, version string) error {
	rawHash, _, _ := inferHashesForVersion(version)
	wantUser := inferUser{syntheticUID, noOrgCallerInfo, noOrgCallerKey, "", []string{}, false}
	wantScene := inferScene{"5", "cli", "agent", "assistant"}
	if input.MachineID != syntheticMachineID || input.Version != version || !reflect.DeepEqual(input.User, wantUser) || input.Scene != wantScene || input.Endpoint != syntheticEndpoint || input.ModelKey != "" || input.ModelSource != "system" || stringHash(input.BodyRaw) != rawHash {
		return fail("fixture-synthetic-schema")
	}
	return validateInferBody(body, version)
}

func validateInferBody(body remoteBody, version string) error {
	if body.AgentID != "agent_common" || body.AliyunUserType != "" || body.Business != (remoteBusiness{syntheticUnixMilli, "synthetic-business-0001", "synthetic-", "cli", "start", "agent", version}) || string(body.ChatContext) != "{}" || body.ChatRecordID != "synthetic-request-0001" || body.ChatTask != "FREE_INPUT" || string(body.CustomModel) != "null" || !body.IsReply || body.IsRetry || body.RequestID != "synthetic-request-0001" || body.RequestSetID != "synthetic-request-0001" || body.SessionID != "synthetic-session-0001" || body.SessionType != "qodercli" || body.Source != 1 || !body.Stream || body.System != "synthetic-system-prompt-0001" || body.TaskID != "common" || body.Version != "3" {
		return fail("fixture-synthetic-schema")
	}
	if len(body.Messages) != 2 || body.Messages[0].Role != "system" || body.Messages[0].Content != "synthetic-system-prompt-0001" || len(body.Messages[0].Contents) != 0 || body.Messages[1].Role != "user" || body.Messages[1].Content != "synthetic-user-message-0001" || !reflect.DeepEqual(body.Messages[1].Contents, []remoteContent{{"text", "synthetic-user-message-0001"}}) {
		return fail("fixture-synthetic-schema")
	}
	if body.ModelConfig != (remoteModel{"synthetic-model-0001", "openai", "system", true, "Synthetic Model", false, false, 4096}) || body.Parameters != (remoteParams{321, 0.25, 0.75}) {
		return fail("fixture-synthetic-schema")
	}
	if len(body.Tools) != 1 || body.Tools[0].Type != "function" || body.Tools[0].Function.Name != "synthetic_tool_0001" || body.Tools[0].Function.Description != "synthetic tool description" || body.Tools[0].Function.Parameters.Type != "object" || !reflect.DeepEqual(body.Tools[0].Function.Parameters.Required, []string{"value"}) || !reflect.DeepEqual(body.Tools[0].Function.Parameters.Properties, map[string]remoteProperty{"value": {"string"}}) {
		return fail("fixture-synthetic-schema")
	}
	return nil
}

func validateInferExpected(input inferFixtureInputPolicy, expected inferFixtureExpectedPolicy) error {
	const expectedURL = "https://example.invalid/base/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	_, bodyHash, _ := inferHashesForVersion(input.Version)
	decodedBody, err := base64.StdEncoding.Strict().DecodeString(expected.BodyBytes)
	if err != nil || string(decodedBody) != expected.BodyString || stringHash(expected.BodyString) != bodyHash || expected.URL != expectedURL {
		return fail("fixture-synthetic-schema")
	}
	want := map[string]string{
		"Accept": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", "Content-Type": "application/json",
		"Cosy-Business-Product": "cli", "Cosy-Business-Type": "agent", "Cosy-Clienttype": "5", "Cosy-Data-Policy": "agree",
		"Cosy-Date": "1781000123", "Cosy-Key": input.User.Key, "Cosy-Machineid": syntheticMachineID, "Cosy-Machinetoken": syntheticMachineID,
		"Cosy-Machinetype": "5", "Cosy-Organization-Id": syntheticOrg, "Cosy-Organization-Tags": "synthetic-a,b", "Cosy-Scene": "assistant",
		"Cosy-User": syntheticUID, "Cosy-Version": input.Version, "Login-Version": "v2", "X-Model-Key": "auto", "X-Model-Source": "system",
	}
	if len(expected.Header) != len(want)+1 {
		return fail("fixture-synthetic-schema")
	}
	for key, value := range want {
		if !reflect.DeepEqual(expected.Header[key], []string{value}) {
			return fail("fixture-synthetic-schema")
		}
	}
	auth := expected.Header["Authorization"]
	_, _, authorizationHash := inferHashesForVersion(input.Version)
	if len(auth) != 1 || stringHash(auth[0]) != authorizationHash {
		return fail("fixture-synthetic-schema")
	}
	return nil
}

func inferExpectedHeader(header map[string][]string, name string) ([]string, bool) {
	for key, values := range header {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}

func inferExpectedAuthorizationPayload(expected inferFixtureExpectedPolicy) (inferAuthorizationPayloadPolicy, error) {
	var payload inferAuthorizationPayloadPolicy
	auth, ok := inferExpectedHeader(expected.Header, "Authorization")
	if !ok || len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer COSY.") {
		return payload, fail("fixture-synthetic-schema")
	}
	parts := strings.Split(strings.TrimPrefix(auth[0], "Bearer COSY."), ".")
	if len(parts) != 2 || len(parts[1]) != 32 {
		return payload, fail("fixture-synthetic-schema")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[0])
	if err != nil || decodeStrictValue(raw, &payload) != nil {
		return payload, fail("fixture-synthetic-schema")
	}
	return payload, nil
}

func validateNoOrgInferExpected(input inferFixtureInputPolicy, expected inferFixtureExpectedPolicy) error {
	const expectedURL = "https://example.invalid/base/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	_, bodyHash, _ := inferHashesForVersion(input.Version)
	decodedBody, err := base64.StdEncoding.Strict().DecodeString(expected.BodyBytes)
	if err != nil || string(decodedBody) != expected.BodyString || stringHash(expected.BodyString) != bodyHash || expected.URL != expectedURL {
		return fail("fixture-synthetic-schema")
	}
	want := map[string]string{
		"Accept": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", "Content-Type": "application/json",
		"Cosy-Business-Product": "cli", "Cosy-Business-Type": "agent", "Cosy-ClientType": "5", "Cosy-Data-Policy": "disagree",
		"Cosy-Date": "1781000123", "Cosy-Key": input.User.Key, "Cosy-MachineId": syntheticMachineID, "Cosy-MachineToken": syntheticMachineID,
		"Cosy-MachineType": "5", "Cosy-Scene": "assistant", "Cosy-User": syntheticUID, "Cosy-Version": input.Version, "Login-Version": "v2",
	}
	if len(expected.Header) != len(want)+1 {
		return fail("fixture-synthetic-schema")
	}
	for key, value := range want {
		values, ok := inferExpectedHeader(expected.Header, key)
		if !ok || !reflect.DeepEqual(values, []string{value}) {
			return fail("fixture-synthetic-schema")
		}
	}
	for _, name := range []string{"Cosy-Organization-Id", "Cosy-Organization-Tags", "X-Model-Key", "X-Model-Source"} {
		if _, ok := inferExpectedHeader(expected.Header, name); ok {
			return fail("fixture-synthetic-schema")
		}
	}
	payload, err := inferExpectedAuthorizationPayload(expected)
	if err != nil || payload.Version != "v1" || payload.RequestID != "8d8c8b8a-8988-4786-8584-838281807f7e" || payload.Info != input.User.EncryptUserInfo || payload.CosyVersion != input.Version || payload.IDEVersion != "" {
		return fail("fixture-synthetic-schema")
	}
	return nil
}

func validateCrossFixtureRelationships(fixtures fixtureSet) error {
	var runtimeExpected runtimeFixtureExpected
	var inferInput inferFixtureInputPolicy
	var noOrgInput inferFixtureInputPolicy
	var noOrgExpected inferFixtureExpectedPolicy
	if decodeStrictValue(fixtures["runtime-fields.json"].Expected, &runtimeExpected) != nil ||
		decodeStrictValue(fixtures["infer-user.json"].Input, &inferInput) != nil ||
		decodeStrictValue(fixtures["infer-user-no-org.json"].Input, &noOrgInput) != nil ||
		decodeStrictValue(fixtures["infer-user-no-org.json"].Expected, &noOrgExpected) != nil {
		return fail("fixture-synthetic-schema")
	}
	if inferInput.User.EncryptUserInfo != runtimeExpected.EncryptUserInfo || inferInput.User.Key != runtimeExpected.Key {
		return fail("fixture-synthetic-schema")
	}
	if noOrgInput.User.EncryptUserInfo == runtimeExpected.EncryptUserInfo || noOrgInput.User.Key == runtimeExpected.Key {
		return fail("fixture-synthetic-schema")
	}
	payload, err := inferExpectedAuthorizationPayload(noOrgExpected)
	key, ok := inferExpectedHeader(noOrgExpected.Header, "Cosy-Key")
	if err != nil || !ok || len(key) != 1 || payload.Info != noOrgInput.User.EncryptUserInfo || key[0] != noOrgInput.User.Key {
		return fail("fixture-synthetic-schema")
	}
	return nil
}

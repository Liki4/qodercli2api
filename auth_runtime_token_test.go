package main

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// Captured from official 1.1.74 WASM (SHA256
// 6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d),
// independently replayed in fresh Python/wasmtime and Go/wazero instances.
// Every identifier/token and every entropy byte below is synthetic.
func TestAuthRuntimeTokenFieldsMatchOfficial1174ExactVector(t *testing.T) {
	const raw = `{"uid":"synthetic-user-0001","security_oauth_token":"synthetic-security-oauth-token-0001","organization_id":"synthetic-org-0001","organization_tags":["synthetic-a","b"],"data_policy_agreed":true}`
	const transcriptJSON = `{"unix_milli":null,"entropy_reads":[{"length":16,"bytes":"AQIDBAUGBwgJCgsMDQ4PEA=="},{"length":109,"bytes":"ERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fQ=="}]}`
	const expectedJSON = `{"encrypt_user_info":"A2MBsulMvdx5p3X6li/3gpFXYnL+eYRR7P93RGyyKpBbcj5DBEoFhpMLzbAGN/hQr3b3vypLVbI5eWAAvaSOewofVOqKjVlrZjyqrhzIRbJd5x4dt+fsU+3tjPjBzT1pBSMHxuno8MYdY6d0OZfsPEyrwJaWfRE2CpjBvWr/CQ8s1fnmZpSvrIyjderfLqSKvtffZH6r7G5EZ5rR7wvPbmkixasTKY94ZfrCDhCEcPVEtr1Lok9E/fP8t+ZCc7AeF6fL6OT0dzvcoq5R/1vvkg==","key":"nKeC6jJtXTWF4TpnVNnxMT/6jY0gBZfCPfjQaKbIi0lS+j2REWVXO5f6BzlvfEvHCrC+UY7rBMZfYs/C72KNYVIH2HLAR8E1yPDAGvV2xViMw029bXcMVa9ib0vyaM4IEu7HJlNHzUXTJOvEBB4YUAyxTCysQ/oYct/JIpRNg7I="}`
	input := runtimeFieldInput{UID: "synthetic-user-0001", SecurityOAuthToken: "synthetic-security-oauth-token-0001", OrganizationID: "synthetic-org-0001", OrganizationTags: []string{"synthetic-a", "b"}, DataPolicyAgreed: true}
	encoded, err := json.Marshal(input)
	if err != nil || string(encoded) != raw {
		t.Fatal("typed runtime JSON does not match official field order/input")
	}
	var transcript protocolTranscript
	if err := json.Unmarshal([]byte(transcriptJSON), &transcript); err != nil {
		t.Fatal("decode synthetic entropy transcript")
	}
	var expected runtimeFieldOutput
	if err := json.Unmarshal([]byte(expectedJSON), &expected); err != nil {
		t.Fatal("decode synthetic expected runtime output")
	}
	replay := newTranscriptReplay(transcript)
	generator := &nativeRuntimeFieldGenerator{host: protocolHostDeps{Clock: replay, Entropy: replay}}
	got, err := generator.Generate(context.Background(), input)
	if err != nil {
		t.Fatalf("token-bound runtime generation error kind %q", protocolErrorKindOf(err))
	}
	if got != expected {
		t.Fatal("token-bound runtime output differs from official exact vector")
	}
	encoded, err = json.Marshal(got)
	if err != nil || string(encoded) != expectedJSON {
		t.Fatal("runtime output serialization differs from official vector")
	}
	if !reflect.DeepEqual(entropyReadLengths(transcript), []int{16, 109}) || len(transcript.UnixMilli) != 0 {
		t.Fatal("unexpected transcript shape")
	}
	assertReplayExhausted(t, replay)
}

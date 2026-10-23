package main

import (
	"context"
	"testing"
)

// Independently captured with Python/wasmtime from the pinned 1.1.74 module.
// Keep this auth-input regression separate from the frozen fixture inventories.
const syntheticTokenRuntimeRaw = `{"uid":"synthetic-user-0001","security_oauth_token":"synthetic-security-oauth-token-0001","organization_id":"synthetic-org-0001","organization_tags":["synthetic-a","b"],"data_policy_agreed":true}`

const syntheticTokenRuntimeExpected = `{"encrypt_user_info":"A2MBsulMvdx5p3X6li/3gpFXYnL+eYRR7P93RGyyKpBbcj5DBEoFhpMLzbAGN/hQr3b3vypLVbI5eWAAvaSOewofVOqKjVlrZjyqrhzIRbJd5x4dt+fsU+3tjPjBzT1pBSMHxuno8MYdY6d0OZfsPEyrwJaWfRE2CpjBvWr/CQ8s1fnmZpSvrIyjderfLqSKvtffZH6r7G5EZ5rR7wvPbmkixasTKY94ZfrCDhCEcPVEtr1Lok9E/fP8t+ZCc7AeF6fL6OT0dzvcoq5R/1vvkg==","key":"nKeC6jJtXTWF4TpnVNnxMT/6jY0gBZfCPfjQaKbIi0lS+j2REWVXO5f6BzlvfEvHCrC+UY7rBMZfYs/C72KNYVIH2HLAR8E1yPDAGvV2xViMw029bXcMVa9ib0vyaM4IEu7HJlNHzUXTJOvEBB4YUAyxTCysQ/oYct/JIpRNg7I="}`

func TestAuthorizedTokenBearingRuntimeVector(t *testing.T) {
	wasmPath, fixturePath := authorizedPaths(t)
	policy, err := policyForDirectory(fixturePath)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	if policy.Identity.Version != upgradeVersion {
		t.Skip("token-bearing auth input requires the explicit 1.1.74 oracle")
	}
	fixtures, err := validateFixtureSet(fixturePath, policy)
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	source, err := readBoundedRegularFile(wasmPath, int64(policy.Identity.Size), "wasm-read")
	if err != nil {
		t.Fatal(categoryOf(err))
	}
	if err := validateWASMForIdentity(source, policy.Identity); err != nil {
		t.Fatal(categoryOf(err))
	}
	for _, name := range []string{"first-instance", "fresh-instance-replay"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			backend, err := newWASMBackend(ctx, source)
			if err != nil {
				t.Fatal(categoryOf(err))
			}
			defer func() {
				if err := backend.Close(ctx); err != nil {
					t.Error("token-bearing runtime backend cleanup failed")
				}
			}()
			tape := fixtures["runtime-fields.json"].Transcript
			replay := newOrderedReplay(tape, entropyCalls(tape))
			backend.setReplay(replay)
			got, err := backend.callString(ctx, "generate_runtime_auth_fields", syntheticTokenRuntimeRaw)
			if err != nil {
				t.Fatal(categoryOf(err))
			}
			if err := replay.Exhausted(); err != nil {
				t.Fatal(categoryOf(err))
			}
			if got != syntheticTokenRuntimeExpected {
				t.Fatal("token-bearing runtime output differs from independent oracle capture")
			}
		})
	}
}

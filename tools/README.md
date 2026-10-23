# Optional external WASM oracle

`wasm_harness.py` is an analysis-only interoperability tool. It is not imported by the Go production build and is not required by ordinary Go tests.

The operator must supply an authorized external copy of a registered `qoder_auth` WASM. The harness has no repository-asset fallback and validates the exact version/size/SHA-256 tuple before instantiation:

| Fixture version | WASM bytes | SHA-256 |
| --- | ---: | --- |
| Historical `1.1.34` | 297238 | `b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4` |
| `1.1.74` (global and official CN) | 298606 | `6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d` |

Unknown versions, mixed tuples, a correct module paired with the wrong fixture version, and recomputed/tampered fixture manifests are rejected. These historical identities are independent of the live production version. The default fixture path and benchmark identity remain `1.1.34`.

The binary is read in place. The harness does not copy it into `tools/` or anywhere else in the repository.

### Extraction provenance

The 1.1.74 fixtures were independently recorded from the local `qodercli-1.1.74` auth module, statically extracted from ASCII Base64 at offset `0x8faddf9`, length `398144`. The [2026-10-20 version analysis](../docs/qodercli-1.1.74-analysis.md) independently checked the global and official CN auth modules against the same size/hash above; they share this oracle, not necessarily the surrounding JavaScript behavior. These static and synthetic checks do not establish live global/CN account compatibility; no 1.1.74 account login, refresh, or inference acceptance test has been performed.

For historical verification, the local **`qodercli-1.1.12`** was scanned for ASCII `AGFzbQEAAAA` candidates, selecting the module containing `credential_storage_encrypt` and matching the historical pin exactly (Base64 offset `0x5a2e65d`, length `396320`). Those bytes match the existing `1.1.34` manifest. This is byte-identity evidence from a **1.1.12 source**, not a claim that the source binary is 1.1.34. The existing `testdata/protocol/1.1.34` files are unchanged.

Extraction does not execute either CLI. Keep extracted modules outside the repository in an operator-owned mode-0700 temporary directory, with mode-0600 files. No credentials, `.env`, account access, or network calls are needed.

## Safe self-test

The dependency-free self-test covers pinned-identity rejection, the separate 16-byte string Result and 12-byte object Result layouts, deterministic transcript ordering/exhaustion, and content-free output formatting:

```bash
python3 -B tools/wasm_harness.py --self-test
```

Expected output:

```text
self-test transcript=static result=PASS
```

## Verify the frozen synthetic fixtures

Run the command from the repository root. The Python launcher first invokes the standalone module's `validate-fixtures` command, so one recursive exact policy validates every nested fixture field and transcript before either runtime backend can instantiate WASM. If the pinned Python `wasmtime` dependency from `tools/requirements.txt` is already available in an operator-managed environment, the harness then uses its corrected wasm-bindgen host glue. Otherwise it invokes the fully standalone Go module in `tools/wasm_oracle` with an explicit argument vector. The nested module has its own `go.mod` and `go.sum`, pins wazero v1.12.0, imports nothing from the root module, and runs with both `GOWORK=off` and `GOPROXY=off`; dependencies must already be cached. Neither path performs a network install.

```bash
python3 -B tools/wasm_harness.py \
  --wasm /authorized/path/qoder_auth.wasm \
  --fixtures testdata/protocol/1.1.34 \
  verify-fixtures
```

Use `--fixtures testdata/protocol/1.1.74` with the matching 1.1.74 module to verify that version's fixtures. Before launching either backend, the harness verifies the manifest identity, exact inventory and hashes (six files for 1.1.34; seven for 1.1.74), per-document oracle identity, synthetic schema, canonical JSON, LF line endings, and transcript encoding. The standalone Go backend independently repeats those checks using bounded no-symlink regular-file reads, then replays the frozen credential, runtime-field, model-cache, full-org infer, and no-org infer transcripts in exact global host-call order and verifies wasm-bindgen result/object layouts plus cleanup accounting. Its ordered operations are `credential`, `runtime`, `model-cache`, `infer`, and `infer-no-org`; 1.1.74 additionally verifies `compatibility` (33 body/malformed-input cases, with individual clock/entropy transcripts).

Go output is newline-delimited JSON containing only operation names, transcript shapes, PASS/FAIL, and fixed categories; the Python fallback parses and validates those records before forwarding them. The Python runtime backend emits the equivalent content-free status lines. Neither path prints fixture inputs or outputs, keys, encrypted values, Authorization data, request bodies, user IDs, organization IDs, exception text, or tracebacks.

The standalone validator and verifier can also be invoked directly:

```bash
GOWORK=off GOPROXY=off go -C tools/wasm_oracle run . \
  --fixtures /external/path/to/frozen-fixtures \
  validate-fixtures

GOWORK=off GOPROXY=off go -C tools/wasm_oracle run . \
  --wasm /authorized/path/qoder_auth.wasm \
  --fixtures /external/path/to/frozen-fixtures \
  verify-fixtures
```

Run its short tests without an authorized WASM:

```bash
GOWORK=off GOPROXY=off go -C tools/wasm_oracle test ./...
```

The authorized integration test is opt-in and requires both explicit paths:

```bash
QODER2API_WASM_ORACLE=/authorized/path/qoder_auth.wasm \
QODER2API_WASM_ORACLE_FIXTURES=/external/path/to/frozen-fixtures \
GOWORK=off GOPROXY=off go -C tools/wasm_oracle test -run TestAuthorizedWASMFixtureIntegration -v
```

Use synthetic repository fixtures only. Do not supply real credentials, captures, tokens, request bodies, or user data to this tool. It performs no network requests.

## Reproduce the independent 1.1.74 capture

The isolated Go tool has an explicit, opt-in capture command. It accepts only the pinned historical synthetic seed directory, only the registered 1.1.74 target module, and a **new, nonexistent** output directory. It never overwrites existing fixtures. The seeds supply input shapes, not expected outputs: credential encrypt/decrypt, runtime generation, model-cache encrypt/decrypt, context construction, and infer outputs all come from actual new WASM calls. Only the synthetic context/business version is advanced; raw body JSON ordering is preserved. Host clock/entropy calls are recorded, then a fresh WASM instance replays the results before publication. Output files use mode 0600 in a mode-0700 directory.

```bash
GOWORK=off GOPROXY=off go -C tools/wasm_oracle run . \
  --wasm /authorized/temp/qoder-auth-1.1.74.wasm \
  --fixtures "$PWD/testdata/protocol/1.1.34" \
  --version 1.1.74 \
  --output /authorized/temp/new-synthetic-1.1.74 \
  capture-fixtures
```

The frozen 1.1.74 manifest SHA-256 is `221df106e219afb2313b183a1b440a92dd6e973d9077e8b905595d4c6c1bc34a`. Capture is not part of normal root or standalone tests. All secret-looking fixture values are synthetic.

### Valid-input compatibility and strict-native rejection policy

Both versions' valid inputs are checked byte-for-byte against native output. Raw prepared WASM/native headers retain `Cosy-MachineToken` and `Cosy-MachineType`; these fixtures do **not** model the newer JavaScript outer-wire header stripping.

The new compatibility corpus was also replayed against the historical module, without changing or relabeling historical fixtures. Both modules agree on all 33 results. The native implementation deliberately retains these **seven existing strict-validation differences**, covered by individually named tests rather than a generic error exemption:

| Synthetic malformed input | Both pinned WASM modules | Native policy |
| --- | --- | --- |
| Body `ab` | Accept short unpadded data | Reject `invalid-input` |
| Body `_$__` | Accept misplaced padding | Reject `invalid-input` |
| Body `kwm` | Accept missing padding | Reject `invalid-input` |
| Body `$k\rwm` | Accept carriage return | Reject `invalid-input` |
| Body `$k\nwm` | Accept line feed | Reject `invalid-input` |
| Body `$d$_` | Accept noncanonical trailing bits | Reject `invalid-input` |
| Model-cache `!!!!` | Return non-Base64 input unchanged | Reject `backend-incompatible` |

These native rejections return no partial output. Other cases must match the recorded outputs and success/failure exactly. In particular, malformed JSON passed to the raw runtime-field export is treated as UTF-8 data and encrypted by both WASM and native; it is not a JSON-parser rejection.

To replay the **same** new compatibility corpus against either version, provide that version's matching oracle/fixture paths plus the new corpus path:

```bash
QODER2API_WASM_ORACLE=/authorized/temp/historical-pin.wasm \
QODER2API_WASM_ORACLE_FIXTURES="$PWD/testdata/protocol/1.1.34" \
QODER2API_WASM_COMPATIBILITY_FIXTURES="$PWD/testdata/protocol/1.1.74" \
GOWORK=off GOPROXY=off go -C tools/wasm_oracle test \
  -run 'TestAuthorizedWASMCompatibility|TestAuthorizedWASMFixtureIntegration' -v
```

## Historical 1.1.34 benchmark runner

Unlike the fixture verifier, which accepts matching **1.1.34 or 1.1.74** tuples, `benchmark.py` accepts **only the historical 1.1.34 WASM pin and fixtures**. It does not benchmark the 1.1.74 oracle. [`BENCHMARK.md`](../BENCHMARK.md) is the retained 2026-09-01 snapshot from commit `c79c82001aa6` with a dirty working tree, not a performance claim about current 1.1.74 code.

For a separately authorized rerun, start at the repository root and select a new output file outside the repository to preserve that historical report:

```bash
python3 -B tools/benchmark.py \
  --wasm /authorized/path/qoder-auth-1.1.34.wasm \
  --output /authorized/path/new-benchmark.md
```

The runner verifies the historical pinned WASM size/SHA, uses frozen synthetic fixtures, runs Native and WASM sequentially with `GOMAXPROCS=1`, and atomically writes the report only after both suites succeed. **Without `--output`, it overwrites the root `BENCHMARK.md`.** It performs no network requests and does not print or persist the external WASM path.

Defaults are ten one-second samples per benchmark. For a shorter diagnostic run:

```bash
python3 -B tools/benchmark.py \
  --wasm /authorized/path/qoder-auth-1.1.34.wasm \
  --count 1 \
  --benchtime 10x \
  --output /authorized/path/new-benchmark-smoke.md
```

Use `--count` and `--benchtime` only to change sampling depth; the benchmark operations, fixtures, single-CPU execution, and Native/WASM ordering stay fixed. Keep the generated commit/dirty metadata with any new results; historical fixture identity alone does not make a rerun reproduce the old source snapshot.

## Redistribution and licensing

Only use a WASM binary that you are authorized to possess and execute. Do not copy or redistribute it without confirming the applicable license and permissions. Current production is native-only and the root module has no WASM or wazero dependency; this independent tool workflow always requires an external operator-supplied binary. The external module is not covered by the project's AGPL-3.0 license. The current-source-tree and historical-asset boundaries are described in [NOTICE](../NOTICE); contributor checks and account-test gates are in the [development guide](../docs/development.md).

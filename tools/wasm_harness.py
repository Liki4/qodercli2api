#!/usr/bin/env python3
"""Optional, external-path qoder_auth WASM oracle for synthetic frozen fixtures."""

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile

PINNED_WASM_SIZE = 297238
PINNED_WASM_SHA256 = "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FIXTURES = os.path.join(REPO_ROOT, "testdata", "protocol", "1.1.34")
FIXTURE_NAMES = ("runtime-fields.json", "credential.json", "model-cache.json", "infer-user.json", "infer-user-no-org.json")
FIXTURE_JSON_NAMES = frozenset(FIXTURE_NAMES + ("manifest.json",))
ORACLE_IDENTITY = {"version": "1.1.34", "size": PINNED_WASM_SIZE, "sha256": PINNED_WASM_SHA256}
PINNED_FIXTURE_HASHES = {
    "credential.json": "07b80f1d48141d763dab7065465b0bd531ae8e490f56a1999322b2faa1d29574",
    "infer-user-no-org.json": "1f7d66201ff1b3d25890cd4399d2aca67b582d938d715f2f0fb048a62e0e78d6",
    "infer-user.json": "9732d0ca933bcf53e2e26e09b0e6a8ec46bd310ce925a8c2b74f24ab6f9b99ed",
    "model-cache.json": "7c9dd168e83f6461b1826aae6b475c6ed419f5b9f45b4bfbecfbfd9617407cc8",
    "runtime-fields.json": "9ab327de55b7ece6d429783152b77298c3b0eb1a51776213741ba8784954aaf0",
}

# Historical benchmark/default identity is deliberately not the live version.
ORACLE_REGISTRY = {
    "1.1.34": (ORACLE_IDENTITY, PINNED_FIXTURE_HASHES),
    "1.1.74": ({"version": "1.1.74", "size": 298606, "sha256": "6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d"}, {
        "compatibility.json": "867fc46e79433a4b5c0c18eda59118203a064884408b31c0d2f1cb28940ef320",
        "credential.json": "f976e8464cc3984269fa986538892e231ce0763c757a3ca2175b995a8ecce6e2",
        "infer-user-no-org.json": "65447bc0e8ec7be7f5687b04b7bbfe08d98b2aea1ec8e5dffe8171a897dfd668",
        "infer-user.json": "a9e7341e45cc32a81ef814bd79bb8c833972796f7fe34d55e90cf36aeb11f549",
        "model-cache.json": "0344ac2f3680cd29ea3fddd69d57ca5923ab0e3cf62891e29a16970a295e03a0",
        "runtime-fields.json": "bbc45fab848a4aee116ed0670d51b0e14e66494c1ef4d8df9e0e2da6239eb734",
    }),
}


def registered_policy(identity):
    if not isinstance(identity, dict):
        raise HarnessError("fixture-oracle-identity")
    policy = ORACLE_REGISTRY.get(identity.get("version"))
    if policy is None or identity != policy[0]:
        raise HarnessError("fixture-oracle-identity")
    return policy


class HarnessError(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def decode_string_result(data):
    if len(data) < 16:
        raise HarnessError("abi-string-result-length")
    return struct.unpack("<IIII", data[:16])


def decode_object_result(data):
    if len(data) < 12:
        raise HarnessError("abi-object-result-length")
    return struct.unpack("<III", data[:12])


def validate_wasm_bytes(data, identity=None):
    if identity is not None:
        registered_policy(identity)
        candidates = [identity]
    else:
        candidates = [policy[0] for policy in ORACLE_REGISTRY.values()]
    candidates = [candidate for candidate in candidates if len(data) == candidate["size"]]
    if not candidates:
        raise HarnessError("wasm-identity-size")
    if not any(hashlib.sha256(data).hexdigest() == candidate["sha256"] for candidate in candidates):
        raise HarnessError("wasm-identity-sha256")


def read_bounded_regular_file(path, maximum, category):
    try:
        metadata = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise HarnessError(category)
        with open(path, "rb") as source:
            data = source.read(maximum + 1)
    except HarnessError:
        raise
    except OSError as error:
        raise HarnessError(category) from error
    if len(data) > maximum:
        raise HarnessError(category)
    return data


def load_authorized_wasm(path, identity=None):
    maximum = identity["size"] if identity is not None else max(policy[0]["size"] for policy in ORACLE_REGISTRY.values())
    data = read_bounded_regular_file(path, maximum, "wasm-read")
    validate_wasm_bytes(data, identity)
    return data


def safe_line(operation, transcript_shape, passed, category=None):
    result = "PASS" if passed else "FAIL"
    line = f"{operation} transcript={transcript_shape} result={result}"
    if category:
        line += f" category={category}"
    return line


def js_utf16_length(value):
    if not isinstance(value, str):
        return len(value)
    try:
        return len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError as error:
        raise HarnessError("unicode-invalid") from error


class TranscriptReplay:
    def __init__(self, unix_milli, entropy_reads, order):
        self.unix_milli = list(unix_milli or [])
        self.entropy_reads = [(length, bytes(data)) for length, data in entropy_reads]
        self.order = list(order)
        self.time_cursor = 0
        self.entropy_cursor = 0
        self.order_cursor = 0

    @classmethod
    def from_fixture(cls, transcript, order):
        reads = []
        for entry in transcript.get("entropy_reads") or []:
            try:
                data = base64.b64decode(entry["bytes"], validate=True)
                length = int(entry["length"])
            except (KeyError, TypeError, ValueError) as error:
                raise HarnessError("transcript-schema") from error
            if len(data) != length:
                raise HarnessError("transcript-byte-count")
            reads.append((length, data))
        return cls(transcript.get("unix_milli") or [], reads, order)

    def _expect(self, kind, length=None):
        if self.order_cursor >= len(self.order):
            raise HarnessError("transcript-order-exhausted")
        expected = self.order[self.order_cursor]
        actual = (kind, length) if length is not None else (kind,)
        if expected != actual:
            raise HarnessError("transcript-order")
        self.order_cursor += 1

    def read(self, length):
        self._expect("entropy", length)
        if self.entropy_cursor >= len(self.entropy_reads):
            raise HarnessError("transcript-entropy-exhausted")
        expected_length, data = self.entropy_reads[self.entropy_cursor]
        self.entropy_cursor += 1
        if expected_length != length:
            raise HarnessError("transcript-entropy-length")
        return data

    def now(self):
        self._expect("clock")
        if self.time_cursor >= len(self.unix_milli):
            raise HarnessError("transcript-clock-exhausted")
        value = self.unix_milli[self.time_cursor]
        self.time_cursor += 1
        return float(value)

    def exhausted(self):
        if self.order_cursor != len(self.order):
            raise HarnessError("transcript-order-unconsumed")
        if self.time_cursor != len(self.unix_milli):
            raise HarnessError("transcript-clock-unconsumed")
        if self.entropy_cursor != len(self.entropy_reads):
            raise HarnessError("transcript-entropy-unconsumed")

    def shape(self):
        lengths = ",".join(str(length) for length, _ in self.entropy_reads) or "none"
        return f"clock:{len(self.unix_milli)},entropy:{lengths}"


class FakeU8:
    def __init__(self, n_or_bytes, harness=None, ptr=None):
        self.harness = harness
        self.ptr = ptr
        if ptr is not None:
            self.n = n_or_bytes if isinstance(n_or_bytes, int) else len(n_or_bytes)
            self.buf = None
        else:
            self.buf = bytearray(n_or_bytes)
            self.n = len(self.buf)

    def __len__(self):
        return self.n

    def read(self):
        if self.ptr is not None:
            return bytearray(self.harness.mem_read(self.ptr, self.n))
        return bytearray(self.buf)

    def write(self, data):
        if len(data) != self.n:
            raise HarnessError("host-array-length")
        if self.ptr is not None:
            self.harness.mem_write(self.ptr, bytes(data))
        else:
            self.buf[:] = data


class FakeMap(dict):
    pass


UNDEFINED = None


class _Null:
    pass


NULL = _Null()
GLOBAL = {"__global__": True}
CRYPTO = {"__crypto__": True}
PROCESS = {"__process__": True}
VERSIONS = {"node": "24.3.0"}


class WasmBound:
    def __init__(self, wasm_bytes):
        try:
            from wasmtime import Func, FuncType, Linker, Module, Store, ValType
        except ImportError as error:
            raise HarnessError("dependency-wasmtime") from error
        self.Func = Func
        self.FuncType = FuncType
        self.ValType = ValType
        self.store = Store()
        self.heap = [UNDEFINED] * 1024 + [UNDEFINED, NULL, True, False]
        self.heap_next = 1028
        self.global_idx = self._add(GLOBAL)
        self.crypto_idx = self._add(CRYPTO)
        self.process_idx = self._add(PROCESS)
        self.versions_idx = self._add(VERSIONS)
        self.replay = None
        self.module = Module(self.store.engine, wasm_bytes)
        self.linker = Linker(self.store.engine)
        self._define_imports()
        self.instance = self.linker.instantiate(self.store, self.module)
        self.ex = self.instance.exports(self.store)
        self.mem = self.ex["memory"]
        self.malloc = self.ex["__wbindgen_export2"]
        self.free = self.ex["__wbindgen_export4"]
        self.ssp = self.ex["__wbindgen_add_to_stack_pointer"]

    def set_replay(self, replay):
        self.replay = replay

    def _entropy(self, length):
        if self.replay is None:
            raise HarnessError("transcript-missing")
        return self.replay.read(length)

    def _now(self):
        if self.replay is None:
            raise HarnessError("transcript-missing")
        return self.replay.now()

    def _add(self, value):
        if self.heap_next == len(self.heap):
            self.heap.append(len(self.heap) + 1)
        index = self.heap_next
        self.heap_next = self.heap[index] if index < len(self.heap) else len(self.heap)
        if not isinstance(self.heap_next, int):
            self.heap_next = len(self.heap)
        while len(self.heap) <= index:
            self.heap.append(UNDEFINED)
        self.heap[index] = value
        return index

    def _drop(self, index):
        if index < 1028 or index >= len(self.heap):
            return
        self.heap[index] = self.heap_next
        self.heap_next = index

    def _get(self, index):
        if 0 <= index < len(self.heap):
            return self.heap[index]
        return UNDEFINED

    def _take(self, index):
        value = self._get(index)
        self._drop(index)
        return value

    def mem_read(self, ptr, length):
        return self.mem.read(self.store, ptr, ptr + length)

    def mem_write(self, ptr, data):
        self.mem.write(self.store, data, ptr)

    def read_str(self, ptr, length):
        return bytes(self.mem_read(ptr, length)).decode("utf-8")

    def pass_str(self, value):
        data = value.encode("utf-8")
        ptr = self.malloc(self.store, len(data), 1)
        self.mem_write(ptr, data)
        return ptr, len(data)

    def _read_guest_string(self, ptr, length):
        if ptr == 0:
            if length != 0:
                raise HarnessError("abi-zero-string-pointer")
            return ""
        try:
            return self.read_str(ptr, length)
        finally:
            self.free(self.store, ptr, length, 1)

    def _define_imports(self):
        linker = self.linker
        store = self.store
        module = "./qoder_auth_wasm_bg.js"
        i32 = self.ValType.i32()
        f64 = self.ValType.f64()

        def define(name, params, results, function):
            linker.define(store, module, name, self.Func(store, self.FuncType(params, results), function))

        define("__wbindgen_object_drop_ref", [i32], [], lambda index: self._drop(index))

        def map_set(map_index, key_index, value_index):
            target = self._get(map_index)
            if isinstance(target, (FakeMap, dict)):
                target[self._get(key_index)] = self._get(value_index)
            return self._add(target)

        define("__wbg_set_08463b1df38a7e29", [i32, i32, i32], [i32], map_set)
        define("__wbg_getRandomValues_d49329ff89a07af1", [i32, i32], [], lambda ptr, length: self.mem_write(ptr, self._entropy(length)))

        def fill_array(_crypto_index, array_index):
            array = self._get(array_index)
            if not isinstance(array, FakeU8):
                raise HarnessError("host-random-target")
            array.write(self._entropy(len(array)))

        define("__wbg_getRandomValues_c44a50d8cfdaebeb", [i32, i32], [], fill_array)
        define("__wbg_crypto_38df2bab126b63dc", [i32], [i32], lambda _index: self._add(CRYPTO))
        define("__wbg_process_44c7a14e11e9f69e", [i32], [i32], lambda _index: self._add(PROCESS))
        define("__wbg_versions_276b2795b1c6a219", [i32], [i32], lambda _index: self._add(VERSIONS))
        define("__wbg_node_84ea875411254db1", [i32], [i32], lambda _index: self._add("24.3.0"))
        define("__wbg_require_b4edbdcf3e2a1ef0", [], [i32], lambda: self._add(CRYPTO))
        define("__wbg_msCrypto_bd5a034af96bcba6", [i32], [i32], lambda _index: self._add(CRYPTO))

        def random_fill_sync(_module_index, array_index):
            array = self._get(array_index)
            try:
                if not isinstance(array, FakeU8):
                    raise HarnessError("host-random-target")
                array.write(self._entropy(len(array)))
            finally:
                self._drop(array_index)

        define("__wbg_randomFillSync_6c25eac9869eb53c", [i32, i32], [], random_fill_sync)

        def call(function_index, _this_index, argument_index):
            function = self._get(function_index)
            argument = self._get(argument_index)
            if function == "getRandomValues" and isinstance(argument, FakeU8):
                argument.write(self._entropy(len(argument)))
            return 0

        define("__wbg_call_d578befcc3145dee", [i32, i32, i32], [i32], call)
        define("__wbindgen_object_clone_ref", [i32], [i32], lambda index: self._add(self._get(index)))
        define("__wbg_new_with_length_9cedd08484b73942", [i32], [i32], lambda length: self._add(FakeU8(length)))

        def length(index):
            value = self._get(index)
            return js_utf16_length(value) if isinstance(value, (FakeU8, str, bytes, list, dict)) else 0

        define("__wbg_length_0c32cb8543c8e4c8", [i32], [i32], length)

        def set_call(ptr, length, array_index):
            source = self._get(array_index)
            if not isinstance(source, FakeU8) or len(source) != length:
                raise HarnessError("host-array-length")
            self.mem_write(ptr, bytes(source.read()))

        define("__wbg_prototypesetcall_3e05eb9545565046", [i32, i32, i32], [], set_call)

        def subarray(array_index, begin, end):
            array = self._get(array_index)
            if not isinstance(array, FakeU8) or begin < 0 or end < begin or end > len(array):
                raise HarnessError("host-subarray-bounds")
            if array.ptr is not None:
                return self._add(FakeU8(end - begin, harness=self, ptr=array.ptr + begin))
            return self._add(FakeU8(array.read()[begin:end]))

        define("__wbg_subarray_0f98d3fb634508ad", [i32, i32, i32], [i32], subarray)
        define("__wbg_new_99cabae501c0a8a0", [], [i32], lambda: self._add(FakeMap()))
        define("__wbg_now_88621c9c9a4f3ffc", [], [f64], self._now)
        define("__wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f", [], [i32], lambda: self._add(GLOBAL))
        define("__wbg_static_accessor_SELF_24f78b6d23f286ea", [], [i32], lambda: self._add(GLOBAL))
        define("__wbg_static_accessor_GLOBAL_f2e0f995a21329ff", [], [i32], lambda: self._add(GLOBAL))
        define("__wbg_static_accessor_WINDOW_59fd959c540fe405", [], [i32], lambda: 0)
        define("__wbg___wbindgen_throw_81fc77679af83bc6", [i32, i32], [], lambda _ptr, _length: (_ for _ in ()).throw(HarnessError("wasm-throw")))
        define("__wbg_Error_2e59b1b37a9a34c3", [i32, i32], [i32], lambda _ptr, _length: self._add({"error": True}))
        define("__wbg___wbindgen_is_object_40c5a80572e8f9d3", [i32], [i32], lambda index: 1 if isinstance(self._get(index), (dict, FakeU8, FakeMap)) and self._get(index) is not NULL else 0)
        define("__wbg___wbindgen_is_string_b29b5c5a8065ba1a", [i32], [i32], lambda index: 1 if isinstance(self._get(index), str) else 0)
        define("__wbg___wbindgen_is_function_49868bde5eb1e745", [i32], [i32], lambda _index: 0)
        define("__wbg___wbindgen_is_undefined_c0cca72b82b86f4d", [i32], [i32], lambda index: 1 if self._get(index) is UNDEFINED else 0)
        define("__wbindgen_cast_0000000000000001", [i32, i32], [i32], lambda ptr, length: self._add(FakeU8(length, harness=self, ptr=ptr)))
        define("__wbindgen_cast_0000000000000002", [i32, i32], [i32], lambda ptr, length: self._add(self.read_str(ptr, length)))

    def call_str_fn(self, name, *values):
        retptr = self.ssp(self.store, -16)
        try:
            args = [retptr]
            for value in values:
                ptr, length = self.pass_str(value)
                args.extend((ptr, length))
            self.ex[name](self.store, *args)
            ptr, length, error_ref, error_flag = decode_string_result(self.mem_read(retptr, 16))
            if error_flag:
                self._take(error_ref)
                raise HarnessError("wasm-result-error")
            return self._read_guest_string(ptr, length)
        finally:
            self.ssp(self.store, 16)

    def credential_encrypt(self, plain, key):
        return self.call_str_fn("credential_storage_encrypt", plain, key)

    def credential_decrypt(self, encrypted, key):
        return self.call_str_fn("credential_storage_decrypt", encrypted, key)

    def gen_runtime_auth_fields(self, raw):
        return self.call_str_fn("generate_runtime_auth_fields", raw)

    def model_cache_encrypt(self, plain, uid):
        return self.call_str_fn("model_cache_encrypt", plain, uid)

    def model_cache_decrypt(self, encrypted, uid):
        return self.call_str_fn("model_cache_decrypt", encrypted, uid)

    def new_context(self, machine_id, version, user_json, scene_json):
        retptr = self.ssp(self.store, -16)
        try:
            args = [retptr]
            for value in (machine_id, version, user_json, scene_json):
                ptr, length = self.pass_str(value)
                args.extend((ptr, length))
            self.ex["qodercontext_new"](self.store, *args)
            ptr, error_ref, error_flag = decode_object_result(self.mem_read(retptr, 12))
            if error_flag:
                self._take(error_ref)
                raise HarnessError("wasm-result-error")
            return ptr
        finally:
            self.ssp(self.store, 16)

    def free_context(self, ptr):
        self.ex["__wbg_qodercontext_free"](self.store, ptr, 0)

    def prepare_infer_request(self, context_ptr, endpoint, body_json, model_key, model_source):
        retptr = self.ssp(self.store, -16)
        try:
            args = [retptr, context_ptr]
            for value in (endpoint, body_json, model_key, model_source):
                ptr, length = self.pass_str(value)
                args.extend((ptr, length))
            self.ex["qodercontext_prepareInferRequest"](self.store, *args)
            ptr, error_ref, error_flag = decode_object_result(self.mem_read(retptr, 12))
            if error_flag:
                self._take(error_ref)
                raise HarnessError("wasm-result-error")
            return ptr
        finally:
            self.ssp(self.store, 16)

    def free_request_result(self, ptr):
        self.ex["__wbg_requestresult_free"](self.store, ptr, 0)

    def result_string(self, name, result_ptr):
        retptr = self.ssp(self.store, -16)
        try:
            self.ex[name](self.store, retptr, result_ptr)
            ptr, length = struct.unpack("<II", self.mem_read(retptr, 8))
            return self._read_guest_string(ptr, length)
        finally:
            self.ssp(self.store, 16)

    def result_headers(self, result_ptr):
        index = self.ex["requestresult_headers"](self.store, result_ptr)
        try:
            value = self._get(index)
            if not isinstance(value, FakeMap):
                raise HarnessError("abi-header-map")
            return dict(value)
        finally:
            self._drop(index)


def load_fixture_document(directory, name):
    try:
        encoded = read_bounded_regular_file(os.path.join(directory, name), 2 * 1024 * 1024, "fixture-read")
        if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n") or b"\r\n" in encoded:
            raise HarnessError("fixture-line-endings")
        text = encoded.decode("utf-8")
        return encoded, json.loads(text)
    except HarnessError:
        raise
    except UnicodeDecodeError as error:
        raise HarnessError("unicode-invalid") from error
    except ValueError as error:
        raise HarnessError("fixture-read") from error


def require_exact_keys(value, keys, category="fixture-schema"):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise HarnessError(category)


def expected_single_header(headers, name):
    matches = [values for key, values in headers.items() if str(key).lower() == name.lower()]
    if len(matches) != 1 or not isinstance(matches[0], list) or len(matches[0]) != 1 or not isinstance(matches[0][0], str):
        raise HarnessError("fixture-synthetic-schema")
    return matches[0][0]


def expected_authorization_payload(headers):
    authorization = expected_single_header(headers, "Authorization")
    prefix = "Bearer COSY."
    if not authorization.startswith(prefix):
        raise HarnessError("fixture-synthetic-schema")
    parts = authorization[len(prefix):].split(".")
    if len(parts) != 2 or len(parts[1]) != 32:
        raise HarnessError("fixture-synthetic-schema")
    try:
        raw = base64.b64decode(parts[0], validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        raise HarnessError("fixture-synthetic-schema") from error
    require_exact_keys(payload, ("version", "requestId", "info", "cosyVersion", "ideVersion"), "fixture-synthetic-schema")
    return payload


def validate_fixture_schema(name, fixture):
    require_exact_keys(fixture, ("oracle", "input", "transcript", "expected"))
    identity, _ = registered_policy(fixture["oracle"])
    version = identity["version"]
    transcript = fixture["transcript"]
    require_exact_keys(transcript, ("unix_milli", "entropy_reads"))
    if transcript["unix_milli"] is not None and not isinstance(transcript["unix_milli"], list):
        raise HarnessError("fixture-schema")
    if not isinstance(transcript["entropy_reads"], list):
        raise HarnessError("fixture-schema")
    for entry in transcript["entropy_reads"]:
        require_exact_keys(entry, ("length", "bytes"))
        if not isinstance(entry["length"], int) or entry["length"] < 0 or not isinstance(entry["bytes"], str):
            raise HarnessError("fixture-schema")
        try:
            decoded = base64.b64decode(entry["bytes"], validate=True)
        except (ValueError, TypeError) as error:
            raise HarnessError("fixture-schema") from error
        if len(decoded) != entry["length"]:
            raise HarnessError("fixture-schema")
    input_value = fixture["input"]
    expected = fixture["expected"]
    if name == "credential.json":
        require_exact_keys(input_value, ("machine_key", "plain"))
        require_exact_keys(expected, ("decrypted", "encrypted"))
        if input_value["machine_key"] != "00000000-1111-42" or input_value["plain"] != expected["decrypted"]:
            raise HarnessError("fixture-synthetic-schema")
    elif name == "runtime-fields.json":
        require_exact_keys(input_value, ("raw",))
        require_exact_keys(expected, ("raw", "encrypt_user_info", "key"))
        try:
            runtime_input = json.loads(input_value["raw"])
        except (TypeError, ValueError) as error:
            raise HarnessError("fixture-synthetic-schema") from error
        if runtime_input.get("uid") != "synthetic-user-0001" or runtime_input.get("organization_id") != "synthetic-org-0001":
            raise HarnessError("fixture-synthetic-schema")
    elif name == "model-cache.json":
        require_exact_keys(input_value, ("plain", "uid"))
        require_exact_keys(expected, ("decrypted", "encrypted"))
        if input_value["uid"] != "synthetic-user-0001" or input_value["plain"] != expected["decrypted"]:
            raise HarnessError("fixture-synthetic-schema")
    elif name in ("infer-user.json", "infer-user-no-org.json"):
        require_exact_keys(input_value, ("machine_id", "version", "user", "scene", "endpoint", "body_raw", "model_key", "model_source"))
        require_exact_keys(expected, ("url", "header", "body_string", "body_bytes"))
        if input_value["machine_id"] != "00000000-1111-4222-8333-444444444444" or input_value["version"] != version or input_value["endpoint"] != "https://example.invalid/base":
            raise HarnessError("fixture-synthetic-schema")
        if input_value["user"].get("uid") != "synthetic-user-0001":
            raise HarnessError("fixture-synthetic-schema")
        if name == "infer-user.json":
            if input_value["user"].get("organization_id") != "synthetic-org-0001" or input_value["model_key"] != "auto" or input_value["model_source"] != "system":
                raise HarnessError("fixture-synthetic-schema")
        else:
            want_user = {
                "uid": "synthetic-user-0001",
                "encrypt_user_info": "synthetic-caller-info-not-effective",
                "key": "synthetic-caller-key-not-effective",
                "organization_id": "",
                "organization_tags": [],
                "data_policy_agreed": False,
            }
            if input_value["user"] != want_user or input_value["model_key"] != "" or input_value["model_source"] != "system":
                raise HarnessError("fixture-synthetic-schema")
            headers = expected["header"]
            if not isinstance(headers, dict) or len(headers) != 18:
                raise HarnessError("fixture-synthetic-schema")
            for header in ("Cosy-Organization-Id", "Cosy-Organization-Tags", "X-Model-Key", "X-Model-Source"):
                if any(str(key).lower() == header.lower() for key in headers):
                    raise HarnessError("fixture-synthetic-schema")
            if expected_single_header(headers, "Cosy-Key") != want_user["key"] or expected_single_header(headers, "Cosy-Data-Policy") != "disagree":
                raise HarnessError("fixture-synthetic-schema")
            payload = expected_authorization_payload(headers)
            if payload != {
                "version": "v1",
                "requestId": "8d8c8b8a-8988-4786-8584-838281807f7e",
                "info": want_user["encrypt_user_info"],
                "cosyVersion": version,
                "ideVersion": "",
            }:
                raise HarnessError("fixture-synthetic-schema")
    elif name == "compatibility.json" and version == "1.1.74":
        require_exact_keys(input_value, ("cases",))
        require_exact_keys(expected, ("results",))
        if len(input_value["cases"]) != 33 or len(expected["results"]) != 33:
            raise HarnessError("fixture-synthetic-schema")
        for case, result in zip(input_value["cases"], expected["results"]):
            require_exact_keys(case, ("operation", "args"))
            require_exact_keys(result, ("output", "decoded", "failed", "transcript"))
            require_exact_keys(result["transcript"], ("unix_milli", "entropy_reads"))
    else:
        raise HarnessError("fixture-schema")


def validate_fixture_set(directory):
    try:
        present = {name for name in os.listdir(directory) if name.endswith(".json")}
    except OSError as error:
        raise HarnessError("fixture-read") from error
    manifest_bytes, manifest = load_fixture_document(directory, "manifest.json")
    del manifest_bytes
    require_exact_keys(manifest, ("version", "size", "sha256", "documents"), "fixture-manifest-schema")
    identity, hashes = registered_policy({key: manifest[key] for key in ("version", "size", "sha256")})
    if present != set(hashes) | {"manifest.json"}:
        raise HarnessError("fixture-inventory")
    if manifest["documents"] != hashes:
        raise HarnessError("fixture-manifest-hash")
    fixtures = {}
    for name in hashes:
        encoded, fixture = load_fixture_document(directory, name)
        if hashlib.sha256(encoded).hexdigest() != hashes[name]:
            raise HarnessError("fixture-document-hash")
        if fixture.get("oracle") != identity:
            raise HarnessError("fixture-oracle-identity")
        validate_fixture_schema(name, fixture)
        fixtures[name] = fixture
    runtime_expected = fixtures["runtime-fields.json"]["expected"]
    infer_user = fixtures["infer-user.json"]["input"]["user"]
    no_org_user = fixtures["infer-user-no-org.json"]["input"]["user"]
    if infer_user["encrypt_user_info"] != runtime_expected["encrypt_user_info"] or infer_user["key"] != runtime_expected["key"]:
        raise HarnessError("fixture-synthetic-schema")
    if no_org_user["encrypt_user_info"] == runtime_expected["encrypt_user_info"] or no_org_user["key"] == runtime_expected["key"]:
        raise HarnessError("fixture-synthetic-schema")
    return fixtures


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def expected_header_map(value):
    return {key.lower(): entries[0] for key, entries in value.items()}


def actual_header_map(value):
    return {str(key).lower(): str(entry) for key, entry in value.items()}


def verify_infer_fixture(wasm, fixture, operation):
    transcript = fixture["transcript"]
    reads = transcript["entropy_reads"]
    new_transcript = {"unix_milli": [], "entropy_reads": reads[:2]}
    new_order = [("entropy", entry["length"]) for entry in reads[:2]]
    new_replay = TranscriptReplay.from_fixture(new_transcript, new_order)
    wasm.set_replay(new_replay)
    context_ptr = wasm.new_context(
        fixture["input"]["machine_id"],
        fixture["input"]["version"],
        compact_json(fixture["input"]["user"]),
        compact_json(fixture["input"]["scene"]),
    )
    try:
        new_replay.exhausted()
        prepare_transcript = {"unix_milli": transcript["unix_milli"], "entropy_reads": reads[2:]}
        prepare_order = [("clock",)] + [("entropy", entry["length"]) for entry in reads[2:]]
        prepare_replay = TranscriptReplay.from_fixture(prepare_transcript, prepare_order)
        wasm.set_replay(prepare_replay)
        result_ptr = wasm.prepare_infer_request(
            context_ptr,
            fixture["input"]["endpoint"],
            fixture["input"]["body_raw"],
            fixture["input"]["model_key"],
            fixture["input"]["model_source"],
        )
        try:
            url = wasm.result_string("requestresult_url", result_ptr)
            headers = wasm.result_headers(result_ptr)
            body = wasm.result_string("requestresult_body", result_ptr)
        finally:
            wasm.free_request_result(result_ptr)
        prepare_replay.exhausted()
    finally:
        wasm.free_context(context_ptr)
    expected = fixture["expected"]
    if url != expected["url"] or body != expected["body_string"]:
        raise HarnessError("infer-output")
    if actual_header_map(headers) != expected_header_map(expected["header"]):
        raise HarnessError("infer-headers")
    combined_shape = f"new[{new_replay.shape()}],prepare[{prepare_replay.shape()}]"
    print(safe_line(operation, combined_shape, True))


def verify_fixtures(wasm_bytes, fixtures):
    validate_wasm_bytes(wasm_bytes, fixtures["credential.json"]["oracle"])
    wasm = WasmBound(wasm_bytes)

    fixture = fixtures["credential.json"]
    replay = TranscriptReplay.from_fixture(fixture["transcript"], [])
    wasm.set_replay(replay)
    encrypted = wasm.credential_encrypt(fixture["input"]["plain"], fixture["input"]["machine_key"])
    decrypted = wasm.credential_decrypt(encrypted, fixture["input"]["machine_key"])
    replay.exhausted()
    if encrypted != fixture["expected"]["encrypted"] or decrypted != fixture["expected"]["decrypted"]:
        raise HarnessError("credential-output")
    print(safe_line("credential", replay.shape(), True))

    fixture = fixtures["runtime-fields.json"]
    entropy_lengths = [entry["length"] for entry in fixture["transcript"]["entropy_reads"]]
    replay = TranscriptReplay.from_fixture(fixture["transcript"], [("entropy", length) for length in entropy_lengths])
    wasm.set_replay(replay)
    raw = wasm.gen_runtime_auth_fields(fixture["input"]["raw"])
    replay.exhausted()
    if raw != fixture["expected"]["raw"]:
        raise HarnessError("runtime-output")
    print(safe_line("runtime", replay.shape(), True))

    fixture = fixtures["model-cache.json"]
    entropy_lengths = [entry["length"] for entry in fixture["transcript"]["entropy_reads"]]
    replay = TranscriptReplay.from_fixture(fixture["transcript"], [("entropy", length) for length in entropy_lengths])
    wasm.set_replay(replay)
    encrypted = wasm.model_cache_encrypt(fixture["input"]["plain"], fixture["input"]["uid"])
    replay.exhausted()
    decrypt_replay = TranscriptReplay([], [], [])
    wasm.set_replay(decrypt_replay)
    decrypted = wasm.model_cache_decrypt(encrypted, fixture["input"]["uid"])
    decrypt_replay.exhausted()
    if encrypted != fixture["expected"]["encrypted"] or decrypted != fixture["expected"]["decrypted"]:
        raise HarnessError("model-cache-output")
    print(safe_line("model-cache", replay.shape(), True))

    verify_infer_fixture(wasm, fixtures["infer-user.json"], "infer")
    verify_infer_fixture(wasm, fixtures["infer-user-no-org.json"], "infer-no-org")
    if "compatibility.json" in fixtures:
        verify_compatibility(wasm, fixtures["compatibility.json"], fixtures["infer-user-no-org.json"]["input"])


def verify_compatibility(wasm, fixture, infer_input):
    operations = {
        "body-decode": "decrypt_server_response",
        "credential-encrypt": "credential_storage_encrypt",
        "credential-decrypt": "credential_storage_decrypt",
        "runtime": "generate_runtime_auth_fields",
        "model-decrypt": "model_cache_decrypt",
    }
    for case, expected in zip(fixture["input"]["cases"], fixture["expected"]["results"]):
        operation = case["operation"]
        order = [("entropy", 16), ("entropy", 109)] if operation in ("runtime", "body-roundtrip") else []
        if operation == "body-roundtrip":
            order += [("clock",), ("entropy", 16)]
        replay = TranscriptReplay.from_fixture(expected["transcript"], order)
        wasm.set_replay(replay)
        output, decoded, failed = "", "", False
        try:
            if operation == "body-roundtrip":
                context_ptr = wasm.new_context(infer_input["machine_id"], infer_input["version"], compact_json(infer_input["user"]), compact_json(infer_input["scene"]))
                try:
                    result_ptr = wasm.prepare_infer_request(context_ptr, infer_input["endpoint"], case["args"][0], "", "system")
                    try:
                        output = wasm.result_string("requestresult_body", result_ptr)
                    finally:
                        wasm.free_request_result(result_ptr)
                finally:
                    wasm.free_context(context_ptr)
                decoded = wasm.call_str_fn("decrypt_server_response", output)
            else:
                output = wasm.call_str_fn(operations[operation], *case["args"])
        except HarnessError as error:
            if error.category != "wasm-result-error":
                raise
            failed = True
        replay.exhausted()
        if output != expected["output"] or decoded != expected["decoded"] or failed != expected["failed"]:
            raise HarnessError("compatibility-output")
    print(safe_line("compatibility", "cases:33", True))


def isolated_go_environment(source=None):
    environment = dict(os.environ if source is None else source)
    environment["GOWORK"] = "off"
    environment["GOPROXY"] = "off"
    return environment


def run_go_oracle(arguments):
    module_directory = os.path.join(REPO_ROOT, "tools", "wasm_oracle")
    argv = ["go", "run", "."] + list(arguments)
    try:
        return subprocess.run(
            argv,
            cwd=module_directory,
            env=isolated_go_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HarnessError("backend-go-launch") from error


def parse_go_records(completed, expected_records, category):
    try:
        lines = completed.stdout.decode("utf-8").splitlines()
        records = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, ValueError) as error:
        raise HarnessError("backend-go-output") from error
    if completed.returncode != 0 or records != expected_records or completed.stderr:
        raise HarnessError(category)
    return lines


def validate_with_go_backend(fixture_directory):
    completed = run_go_oracle([
        "--fixtures",
        os.path.abspath(fixture_directory),
        "validate-fixtures",
    ])
    parse_go_records(
        completed,
        [{"operation": "validate-fixtures", "transcript": "static", "result": "PASS"}],
        "backend-go-validation",
    )


def verify_with_go_backend(wasm_path, fixture_directory):
    completed = run_go_oracle([
        "--wasm",
        os.path.abspath(wasm_path),
        "--fixtures",
        os.path.abspath(fixture_directory),
        "verify-fixtures",
    ])
    expected_records = [
        {"operation": "credential", "transcript": "clock:0,entropy:none", "result": "PASS"},
        {"operation": "runtime", "transcript": "clock:0,entropy:16,109", "result": "PASS"},
        {"operation": "model-cache", "transcript": "clock:0,entropy:12", "result": "PASS"},
        {"operation": "infer", "transcript": "new[clock:0,entropy:16,109],prepare[clock:1,entropy:16]", "result": "PASS"},
        {"operation": "infer-no-org", "transcript": "new[clock:0,entropy:16,109],prepare[clock:1,entropy:16]", "result": "PASS"},
    ]
    if "compatibility.json" in validate_fixture_set(fixture_directory):
        expected_records.append({"operation": "compatibility", "transcript": "cases:33", "result": "PASS"})
    lines = parse_go_records(completed, expected_records, "backend-go-verify")
    for line in lines:
        print(line)


def run_guarded(action):
    try:
        action()
        return 0
    except HarnessError as error:
        print(safe_line("verify-fixtures", "unavailable", False, error.category))
        return 1
    except Exception:
        print(safe_line("verify-fixtures", "unavailable", False, "internal"))
        return 1


def run_self_tests():
    for version in ("1.1.34", "1.1.74"):
        fixtures = validate_fixture_set(os.path.join(REPO_ROOT, "testdata", "protocol", version))
        if fixtures["infer-user.json"]["input"]["version"] != version:
            raise HarnessError("self-test-fixture-version")
    for invalid in (
        {**ORACLE_IDENTITY, "version": "unknown"},
        {**ORACLE_IDENTITY, "version": "1.1.74"},
        {**ORACLE_IDENTITY, "size": 298606},
        {**ORACLE_IDENTITY, "sha256": ORACLE_REGISTRY["1.1.74"][0]["sha256"]},
    ):
        try:
            registered_policy(invalid)
        except HarnessError as error:
            if error.category != "fixture-oracle-identity":
                raise
        else:
            raise HarnessError("self-test-mixed-identity")
    encoded = struct.pack("<IIII", 11, 22, 33, 44)
    if decode_string_result(encoded) != (11, 22, 33, 44):
        raise HarnessError("self-test-string-layout")
    if decode_object_result(encoded[:12]) != (11, 22, 33):
        raise HarnessError("self-test-object-layout")
    try:
        validate_wasm_bytes(bytes(PINNED_WASM_SIZE))
    except HarnessError as error:
        if error.category != "wasm-identity-sha256":
            raise
    else:
        raise HarnessError("self-test-identity")
    replay = TranscriptReplay([1234], [(2, b"ab")], [("clock",), ("entropy", 2)])
    if replay.now() != 1234.0 or replay.read(2) != b"ab":
        raise HarnessError("self-test-replay")
    replay.exhausted()
    line = safe_line("synthetic", "clock:0,entropy:none", False, "synthetic-category")
    for forbidden in ("Authorization", "secret", "uid", "organization"):
        if forbidden in line:
            raise HarnessError("self-test-redaction")
    with tempfile.NamedTemporaryFile() as temporary:
        temporary.write(b"not-wasm")
        temporary.flush()
        try:
            load_authorized_wasm(temporary.name)
        except HarnessError as error:
            if error.category != "wasm-identity-size":
                raise
        else:
            raise HarnessError("self-test-path-identity")
    if js_utf16_length("A\U0001f600B") != 4:
        raise HarnessError("self-test-utf16-length")
    try:
        js_utf16_length("\ud800")
    except HarnessError as error:
        if error.category != "unicode-invalid":
            raise
    else:
        raise HarnessError("self-test-unicode-invalid")
    try:
        validate_fixture_schema("credential.json", {"oracle": ORACLE_IDENTITY})
    except HarnessError as error:
        if error.category != "fixture-schema":
            raise
    else:
        raise HarnessError("self-test-schema")
    with tempfile.TemporaryDirectory() as directory:
        for name in FIXTURE_JSON_NAMES:
            with open(os.path.join(DEFAULT_FIXTURES, name), "rb") as source:
                data = source.read()
            with open(os.path.join(directory, name), "wb") as destination:
                destination.write(data)
        credential_path = os.path.join(directory, "credential.json")
        with open(credential_path, encoding="utf-8") as source:
            credential = json.load(source)
        credential["expected"]["encrypted"] = "synthetic-tampered-value"
        credential_bytes = (json.dumps(credential, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        with open(credential_path, "wb") as destination:
            destination.write(credential_bytes)
        manifest_path = os.path.join(directory, "manifest.json")
        with open(manifest_path, encoding="utf-8") as source:
            manifest = json.load(source)
        manifest["documents"]["credential.json"] = hashlib.sha256(credential_bytes).hexdigest()
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as destination:
            destination.write(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        try:
            validate_fixture_set(directory)
        except HarnessError as error:
            if error.category != "fixture-manifest-hash":
                raise
        else:
            raise HarnessError("self-test-recomputed-manifest")
    hostile_workspace = "/nonexistent/private/workspace-leak"
    isolated = isolated_go_environment({"GOWORK": hostile_workspace, "GOPROXY": "https://example.invalid/proxy", "PATH": os.environ.get("PATH", "")})
    if isolated.get("GOWORK") != "off" or isolated.get("GOPROXY") != "off" or hostile_workspace in repr(isolated):
        raise HarnessError("self-test-go-isolation")
    stdout = io.StringIO()
    stderr = io.StringIO()
    sentinel = "Authorization synthetic-access-token traceback-sentinel"
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = run_guarded(lambda: (_ for _ in ()).throw(ValueError(sentinel)))
    guarded_output = stdout.getvalue() + stderr.getvalue()
    if status != 1 or "category=internal" not in guarded_output:
        raise HarnessError("self-test-unexpected-error")
    if any(value in guarded_output for value in (sentinel, "Traceback", "Authorization", "synthetic-access-token")):
        raise HarnessError("self-test-redaction")
    print(safe_line("self-test", "static", True))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Verify synthetic frozen fixtures with an operator-supplied authorized WASM oracle.")
    parser.add_argument("--self-test", action="store_true", help="run dependency-free harness unit tests")
    parser.add_argument("--wasm", help="mandatory external path to the authorized pinned WASM for verify-fixtures")
    parser.add_argument("--fixtures", default=DEFAULT_FIXTURES, help="path to the non-secret frozen fixture directory")
    parser.add_argument("command", nargs="?", choices=("verify-fixtures",))
    args = parser.parse_args(argv)
    if args.self_test:
        if args.command is not None or args.wasm is not None:
            parser.error("--self-test cannot be combined with --wasm or a command")
        return args
    if args.command != "verify-fixtures":
        parser.error("verify-fixtures is required unless --self-test is used")
    if not args.wasm:
        parser.error("--wasm PATH is required for verify-fixtures")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.self_test:
        return run_guarded(run_self_tests)

    def verify():
        fixture_directory = os.path.abspath(args.fixtures)
        validate_with_go_backend(fixture_directory)
        fixtures = validate_fixture_set(fixture_directory)
        wasm_bytes = load_authorized_wasm(args.wasm, fixtures["credential.json"]["oracle"])
        if importlib.util.find_spec("wasmtime") is not None:
            verify_fixtures(wasm_bytes, fixtures)
        else:
            verify_with_go_backend(args.wasm, fixture_directory)

    return run_guarded(verify)


if __name__ == "__main__":
    sys.exit(main())

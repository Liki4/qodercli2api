#!/usr/bin/env python3
"""Harness to run qoder_auth_wasm (wasm-bindgen module) under wasmtime."""
import os, sys, time, json, struct
from wasmtime import Store, Module, Linker, Func, FuncType, ValType

WASM = os.path.join(os.path.dirname(__file__), 'extracted', 'wasm_0.wasm')
I32 = ValType.i32()
F64 = ValType.f64()

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
        if self.ptr is not None:
            self.harness.mem_write(self.ptr, bytes(data))
        else:
            self.buf[:] = data

class FakeMap(dict):
    pass

UNDEFINED = None
class _Null:
    def __repr__(self): return 'null'
NULL = _Null()
GLOBAL = {'__global__': True}
CRYPTO = {'__crypto__': True}
PROCESS = {'__process__': True}
VERSIONS = {'node': '24.3.0'}

class WasmBound:
    def __init__(self):
        self.store = Store()
        self.heap = [UNDEFINED] * 1024 + [UNDEFINED, NULL, True, False]
        self.heap_next = 1028
        self.global_idx = self._add(GLOBAL)
        self.crypto_idx = self._add(CRYPTO)
        self.process_idx = self._add(PROCESS)
        self.versions_idx = self._add(VERSIONS)
        self.log_calls = os.environ.get('WASM_LOG') == '1'
        engine = self.store.engine
        self.module = Module(engine, open(WASM, 'rb').read())
        self.linker = Linker(engine)
        self._define_imports()
        self.instance = self.linker.instantiate(self.store, self.module)
        ex = self.instance.exports(self.store)
        self.mem = ex['memory']
        self.malloc = ex['__wbindgen_export2']
        self.realloc = ex['__wbindgen_export3']
        self.free = ex['__wbindgen_export4']
        self.ssp = ex['__wbindgen_add_to_stack_pointer']
        self.ex = ex

    # ---- heap ----
    def _add(self, val):
        if self.heap_next == len(self.heap):
            self.heap.append(len(self.heap) + 1)
        h = self.heap_next
        self.heap_next = self.heap[h] if h < len(self.heap) else len(self.heap)
        if not isinstance(self.heap_next, int):
            self.heap_next = len(self.heap)
        while len(self.heap) <= h:
            self.heap.append(UNDEFINED)
        self.heap[h] = val
        return h

    def _drop(self, i):
        if i < 1028 or i >= len(self.heap):
            return
        self.heap[i] = self.heap_next
        self.heap_next = i

    def _get(self, i):
        if 0 <= i < len(self.heap):
            return self.heap[i]
        if self.log_calls:
            print(f'  [heap?] read unallocated idx {i} (len={len(self.heap)})', file=sys.stderr)
        return UNDEFINED

    # ---- memory helpers ----
    def mem_read(self, ptr, n):
        return self.mem.read(self.store, ptr, ptr + n)

    def mem_write(self, ptr, data):
        self.mem.write(self.store, data, ptr)

    def read_str(self, ptr, n):
        return bytes(self.mem_read(ptr, n)).decode('utf-8')

    def pass_str(self, s):
        b = s.encode('utf-8')
        ptr = self.malloc(self.store, len(b), 1)
        self.mem_write(ptr, b)
        return ptr, len(b)

    def ret_str(self, retptr):
        data = self.mem_read(retptr, 8)
        ptr, ln = struct.unpack('<II', data)
        s = self.read_str(ptr, ln)
        self.free(self.store, ptr, ln, 1)
        return s

    # ---- imports ----
    def _define_imports(self):
        L = self.linker
        S = self.store
        mod = './qoder_auth_wasm_bg.js'

        def deff(name, params, results, fn):
            t = FuncType(params, results)
            L.define(S, mod, name, Func(S, t, fn))

        def log(*a):
            if self.log_calls:
                print('  [import]', *a, file=sys.stderr)

        deff('__wbindgen_object_drop_ref', [I32], [], lambda i: self._drop(i))

        def map_set(m, k, v):
            mv = self._get(m)
            log('map.set on', m, type(mv).__name__, self._get(k), self._get(v))
            if isinstance(mv, (FakeMap, dict)):
                mv[self._get(k)] = self._get(v)
            return self._add(mv)
        deff('__wbg_set_08463b1df38a7e29', [I32, I32, I32], [I32], map_set)

        def grv_mem(ptr, ln):
            # globalThis.crypto.getRandomValues(IEA(ptr, len)): fill wasm memory directly
            self.mem_write(ptr, os.urandom(ln))
        deff('__wbg_getRandomValues_d49329ff89a07af1', [I32, I32], [], grv_mem)

        def grv_arr(crypto_i, arr_i):
            arr = self._get(arr_i)
            log('getRandomValues(arr)', type(arr), len(arr) if isinstance(arr, FakeU8) else None)
            if isinstance(arr, FakeU8):
                arr.write(os.urandom(len(arr)))
        deff('__wbg_getRandomValues_c44a50d8cfdaebeb', [I32, I32], [], grv_arr)

        deff('__wbg_crypto_38df2bab126b63dc', [I32], [I32], lambda g: self._add(CRYPTO))
        deff('__wbg_process_44c7a14e11e9f69e', [I32], [I32], lambda g: self._add(PROCESS))
        deff('__wbg_versions_276b2795b1c6a219', [I32], [I32], lambda p: self._add(VERSIONS))
        deff('__wbg_node_84ea875411254db1', [I32], [I32], lambda v: self._add('24.3.0'))
        deff('__wbg_require_b4edbdcf3e2a1ef0', [], [I32], lambda: self._add(CRYPTO))
        deff('__wbg_msCrypto_bd5a034af96bcba6', [I32], [I32], lambda g: self._add(CRYPTO))

        def rfs(mod_i, arr_i):
            arr = self._get(arr_i)
            log('randomFillSync', type(arr))
            if isinstance(arr, FakeU8):
                arr.write(os.urandom(len(arr)))
            self._drop(arr_i)
        deff('__wbg_randomFillSync_6c25eac9869eb53c', [I32, I32], [], rfs)

        def call_(fn_i, this_i, arg_i):
            fn, this, arg = self._get(fn_i), self._get(this_i), self._get(arg_i)
            log('call', fn, this, arg)
            if fn == 'getRandomValues' and isinstance(arg, FakeU8):
                arg.write(os.urandom(len(arg)))
                return 0
            return 0
        deff('__wbg_call_d578befcc3145dee', [I32, I32, I32], [I32], call_)

        deff('__wbindgen_object_clone_ref', [I32], [I32], lambda i: self._add(self._get(i)))
        deff('__wbg_new_with_length_9cedd08484b73942', [I32], [I32], lambda n: self._add(FakeU8(n)))

        def length_(i):
            v = self._get(i)
            if isinstance(v, FakeU8):
                return len(v)
            if isinstance(v, (str, bytes, list, dict)):
                return len(v)
            return 0
        deff('__wbg_length_0c32cb8543c8e4c8', [I32], [I32], length_)

        def setcall(ptr, ln, arr_i):
            # Uint8Array.prototype.set.call(IEA(ptr,len), heap[arr_i]): copy JS array into wasm mem
            src = self._get(arr_i)
            log('u8.set into mem', ptr, ln, type(src))
            if isinstance(src, FakeU8):
                self.mem_write(ptr, bytes(src.read()))
        deff('__wbg_prototypesetcall_3e05eb9545565046', [I32, I32, I32], [], setcall)

        def subarray(arr_i, begin, end):
            arr = self._get(arr_i)
            if isinstance(arr, FakeU8):
                if arr.ptr is not None:
                    return self._add(FakeU8(end - begin, harness=self, ptr=arr.ptr + begin))
                return self._add(FakeU8(arr.read()[begin:end]))
            return self._add(FakeU8(0))
        deff('__wbg_subarray_0f98d3fb634508ad', [I32, I32, I32], [I32], subarray)

        deff('__wbg_new_99cabae501c0a8a0', [], [I32], lambda: self._add(FakeMap()))
        deff('__wbg_now_88621c9c9a4f3ffc', [], [F64], lambda: time.time() * 1000.0)

        deff('__wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f', [], [I32], lambda: self._add(GLOBAL))
        deff('__wbg_static_accessor_SELF_24f78b6d23f286ea', [], [I32], lambda: self._add(GLOBAL))
        deff('__wbg_static_accessor_GLOBAL_f2e0f995a21329ff', [], [I32], lambda: self._add(GLOBAL))
        deff('__wbg_static_accessor_WINDOW_59fd959c540fe405', [], [I32], lambda: 0)

        def throw_(ptr, ln):
            msg = self.read_str(ptr, ln)
            raise RuntimeError('wasm throw: ' + msg)
        deff('__wbg___wbindgen_throw_81fc77679af83bc6', [I32, I32], [], throw_)

        def error_(ptr, ln):
            return self._add({'error': self.read_str(ptr, ln)})
        deff('__wbg_Error_2e59b1b37a9a34c3', [I32, I32], [I32], error_)

        deff('__wbg___wbindgen_is_object_40c5a80572e8f9d3', [I32], [I32],
             lambda i: 1 if isinstance(self._get(i), (dict, FakeU8, FakeMap)) and self._get(i) is not NULL else 0)
        deff('__wbg___wbindgen_is_string_b29b5c5a8065ba1a', [I32], [I32],
             lambda i: 1 if isinstance(self._get(i), str) else 0)
        deff('__wbg___wbindgen_is_function_49868bde5eb1e745', [I32], [I32], lambda i: 0)
        deff('__wbg___wbindgen_is_undefined_c0cca72b82b86f4d', [I32], [I32],
             lambda i: 1 if self._get(i) is UNDEFINED else 0)

        def cast1(ptr, ln):
            return self._add(FakeU8(ln, harness=self, ptr=ptr))
        deff('__wbindgen_cast_0000000000000001', [I32, I32], [I32], cast1)

        def cast2(ptr, ln):
            return self._add(self.read_str(ptr, ln))
        deff('__wbindgen_cast_0000000000000002', [I32, I32], [I32], cast2)

    # ---- public API ----
    def call_str_fn(self, name, *strs, extra_check=True):
        """call exported fn(retptr, ptr,len ...) -> string via [retptr],[retptr+4]; err flag at +8"""
        fn = self.ex[name]
        retptr = self.ssp(self.store, -16)
        args = [retptr]
        for s in strs:
            p, l = self.pass_str(s)
            args += [p, l]
        fn(self.store, *args)
        flag = struct.unpack('<I', self.mem_read(retptr + 8, 4))[0]
        if flag and extra_check:
            self.ssp(self.store, 16)
            raise RuntimeError(f'{name} returned error flag')
        s = self.ret_str(retptr)
        self.ssp(self.store, 16)
        return s

    def credential_encrypt(self, json_str, key16):
        return self.call_str_fn('credential_storage_encrypt', json_str, key16)

    def credential_decrypt(self, blob_str, key16):
        return self.call_str_fn('credential_storage_decrypt', blob_str, key16)

    def gen_runtime_auth_fields(self, userinfo_json):
        return self.call_str_fn('generate_runtime_auth_fields', userinfo_json)

    def new_context(self, machine_id, version, userinfo_json, scene_json):
        retptr = self.ssp(self.store, -16)
        args = [retptr]
        for s in (machine_id, version, userinfo_json, scene_json):
            p, l = self.pass_str(s)
            args += [p, l]
        self.ex['qodercontext_new'](self.store, *args)
        ptr, err, flag = struct.unpack('<III', self.mem_read(retptr, 12))
        self.ssp(self.store, 16)
        if flag:
            raise RuntimeError(f'qodercontext_new failed: {self.heap[err]}')
        return ptr

    def prepare_infer_request(self, ctx, endpoint, body_json, model_key, model_source):
        retptr = self.ssp(self.store, -16)
        args = [retptr, ctx]
        for s in (endpoint, body_json, model_key, model_source):
            p, l = self.pass_str(s)
            args += [p, l]
        self.ex['qodercontext_prepareInferRequest'](self.store, *args)
        ptr, err, flag = struct.unpack('<III', self.mem_read(retptr, 12))
        self.ssp(self.store, 16)
        if flag:
            raise RuntimeError(f'prepareInferRequest failed: {self.heap[err]}')
        return ptr

    def result_url(self, rptr):
        retptr = self.ssp(self.store, -16)
        self.ex['requestresult_url'](self.store, retptr, rptr)
        s = self.ret_str(retptr)
        self.ssp(self.store, 16)
        return s

    def result_headers(self, rptr):
        idx = self.ex['requestresult_headers'](self.store, rptr)
        return dict(self.heap[idx]) if isinstance(self.heap[idx], FakeMap) else self.heap[idx]

    def result_body(self, rptr):
        retptr = self.ssp(self.store, -16)
        self.ex['requestresult_body'](self.store, retptr, rptr)
        ptr, ln = struct.unpack('<II', self.mem_read(retptr, 8))
        self.ssp(self.store, 16)
        if ptr == 0:
            return None
        s = self.read_str(ptr, ln)
        self.free(self.store, ptr, ln, 1)
        return s


if __name__ == '__main__':
    w = WasmBound()
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'demo'
    if cmd == 'decrypt':
        blob = open(sys.argv[2]).read().strip()
        key = open(sys.argv[3]).read().strip()[:16]
        print(w.credential_decrypt(blob, key))
    elif cmd == 'genkey':
        print(w.gen_runtime_auth_fields(sys.argv[2]))
    elif cmd == 'demo':
        print('harness ok; exports:', [n for n in dir(w.ex) if 'qoder' in n or 'request' in n])

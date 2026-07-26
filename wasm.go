package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed assets/qoder_auth_wasm_bg.wasm
var authWasm []byte

// fakeU8 emulates a JS Uint8Array. When memBacked it is a view over wasm memory.
type fakeU8 struct {
	n        int
	buf      []byte // python-side buffer
	mem      api.Memory
	ptr      uint32
	memBack  bool
}

func (f *fakeU8) read() []byte {
	if f.memBack {
		b, ok := f.mem.Read(f.ptr, uint32(f.n))
		if !ok {
			return nil
		}
		out := make([]byte, f.n)
		copy(out, b)
		return out
	}
	return f.buf
}

func (f *fakeU8) write(data []byte) {
	if f.memBack {
		f.mem.Write(f.ptr, data)
		return
	}
	f.buf = append(f.buf[:0], data...)
}

type nullT struct{}
type globalT struct{}
type cryptoT struct{}
type processT struct{}
type errorT struct{ msg string }

var (
	vUndefined any = nil
	vNull      any = nullT{}
	vGlobal    any = globalT{}
	vCrypto    any = cryptoT{}
	vProcess   any = processT{}
	vVersions  any = map[string]any{"node": "24.3.0"}
)

// wasmAuth is a wasmtime-style host for qoder_auth_wasm (wasm-bindgen ABI).
type wasmAuth struct {
	mu   sync.Mutex
	mod  api.Module
	mem  api.Memory
	mall api.Function
	rea  api.Function
	fre  api.Function
	ssp  api.Function
	fns  map[string]api.Function

	heap     []any
	heapNext uint32
}

func newWasmAuth(ctx context.Context) (*wasmAuth, error) {
	w := &wasmAuth{fns: map[string]api.Function{}}
	w.heap = make([]any, 1024)
	w.heap = append(w.heap, vUndefined, vNull, true, false)
	w.heapNext = 1028

	r := wazero.NewRuntime(ctx)
	i32 := api.ValueTypeI32
	f64 := api.ValueTypeF64

	def := func(b wazero.HostModuleBuilder, name string, params, results []api.ValueType, fn func(stack []uint64)) {
		gmf := api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fn(stack)
		})
		b.NewFunctionBuilder().WithGoModuleFunction(gmf, params, results).Export(name)
	}

	hb := r.NewHostModuleBuilder("./qoder_auth_wasm_bg.js")
	p1 := []api.ValueType{i32}
	p2 := []api.ValueType{i32, i32}
	p3 := []api.ValueType{i32, i32, i32}
	r1 := []api.ValueType{i32}
	none := []api.ValueType{}

	def(hb, "__wbindgen_object_drop_ref", p1, none, func(s []uint64) { w.drop(uint32(s[0])) })
	def(hb, "__wbg_set_08463b1df38a7e29", p3, r1, func(s []uint64) {
		m, k, v := uint32(s[0]), uint32(s[1]), uint32(s[2])
		if mv, ok := w.get(m).(map[string]string); ok {
			ks, _ := w.get(k).(string)
			vs, _ := w.get(v).(string)
			mv[ks] = vs
		}
		s[0] = uint64(w.add(w.get(m)))
	})
	def(hb, "__wbg_getRandomValues_d49329ff89a07af1", p2, none, func(s []uint64) {
		ptr, ln := uint32(s[0]), uint32(s[1])
		buf := make([]byte, ln)
		rand.Read(buf)
		w.mem.Write(ptr, buf)
	})
	def(hb, "__wbg_getRandomValues_c44a50d8cfdaebeb", p2, none, func(s []uint64) {
		if arr, ok := w.get(uint32(s[1])).(*fakeU8); ok {
			buf := make([]byte, arr.n)
			rand.Read(buf)
			arr.write(buf)
		}
	})
	def(hb, "__wbg_crypto_38df2bab126b63dc", p1, r1, func(s []uint64) { s[0] = uint64(w.add(vCrypto)) })
	def(hb, "__wbg_process_44c7a14e11e9f69e", p1, r1, func(s []uint64) { s[0] = uint64(w.add(vProcess)) })
	def(hb, "__wbg_versions_276b2795b1c6a219", p1, r1, func(s []uint64) { s[0] = uint64(w.add(vVersions)) })
	def(hb, "__wbg_node_84ea875411254db1", p1, r1, func(s []uint64) { s[0] = uint64(w.add("24.3.0")) })
	def(hb, "__wbg_require_b4edbdcf3e2a1ef0", none, r1, func(s []uint64) { s[0] = uint64(w.add(vCrypto)) })
	def(hb, "__wbg_msCrypto_bd5a034af96bcba6", p1, r1, func(s []uint64) { s[0] = uint64(w.add(vCrypto)) })
	def(hb, "__wbg_randomFillSync_6c25eac9869eb53c", p2, none, func(s []uint64) {
		idx := uint32(s[1])
		if arr, ok := w.get(idx).(*fakeU8); ok {
			buf := make([]byte, arr.n)
			rand.Read(buf)
			arr.write(buf)
		}
		w.drop(idx)
	})
	def(hb, "__wbg_call_d578befcc3145dee", p3, r1, func(s []uint64) {
		fn, arg := w.get(uint32(s[0])), w.get(uint32(s[2]))
		if fn == "getRandomValues" {
			if arr, ok := arg.(*fakeU8); ok {
				buf := make([]byte, arr.n)
				rand.Read(buf)
				arr.write(buf)
			}
		}
		s[0] = 0
	})
	def(hb, "__wbindgen_object_clone_ref", p1, r1, func(s []uint64) { s[0] = uint64(w.add(w.get(uint32(s[0])))) })
	def(hb, "__wbg_new_with_length_9cedd08484b73942", p1, r1, func(s []uint64) {
		s[0] = uint64(w.add(&fakeU8{n: int(uint32(s[0])), buf: make([]byte, int(uint32(s[0])))}))
	})
	def(hb, "__wbg_length_0c32cb8543c8e4c8", p1, r1, func(s []uint64) {
		v := w.get(uint32(s[0]))
		switch t := v.(type) {
		case *fakeU8:
			s[0] = uint64(t.n)
		case string:
			s[0] = uint64(len(t))
		default:
			s[0] = 0
		}
	})
	def(hb, "__wbg_prototypesetcall_3e05eb9545565046", p3, none, func(s []uint64) {
		ptr, ln, idx := uint32(s[0]), uint32(s[1]), uint32(s[2])
		if src, ok := w.get(idx).(*fakeU8); ok {
			data := src.read()
			if len(data) > int(ln) {
				data = data[:ln]
			}
			w.mem.Write(ptr, data)
		}
	})
	def(hb, "__wbg_subarray_0f98d3fb634508ad", p3, r1, func(s []uint64) {
		idx, begin, end := uint32(s[0]), uint32(s[1]), uint32(s[2])
		if arr, ok := w.get(idx).(*fakeU8); ok {
			if arr.memBack {
				s[0] = uint64(w.add(&fakeU8{n: int(end - begin), mem: w.mem, ptr: arr.ptr + begin, memBack: true}))
				return
			}
			b := arr.read()
			if int(end) > len(b) {
				end = uint32(len(b))
			}
			s[0] = uint64(w.add(&fakeU8{n: int(end - begin), buf: append([]byte{}, b[begin:end]...)}))
			return
		}
		s[0] = uint64(w.add(&fakeU8{}))
	})
	def(hb, "__wbg_new_99cabae501c0a8a0", none, r1, func(s []uint64) { s[0] = uint64(w.add(map[string]string{})) })
	def(hb, "__wbg_now_88621c9c9a4f3ffc", none, []api.ValueType{f64}, func(s []uint64) {
		s[0] = api.EncodeF64(float64(time.Now().UnixMilli()))
	})
	for _, name := range []string{"__wbg_static_accessor_GLOBAL_THIS_a1248013d790bf5f", "__wbg_static_accessor_SELF_24f78b6d23f286ea", "__wbg_static_accessor_GLOBAL_f2e0f995a21329ff"} {
		nm := name
		def(hb, nm, none, r1, func(s []uint64) { s[0] = uint64(w.add(vGlobal)) })
	}
	def(hb, "__wbg_static_accessor_WINDOW_59fd959c540fe405", none, r1, func(s []uint64) { s[0] = 0 })
	def(hb, "__wbg___wbindgen_throw_81fc77679af83bc6", p2, none, func(s []uint64) {
		panic(fmt.Errorf("wasm throw: %s", w.readStr(uint32(s[0]), uint32(s[1]))))
	})
	def(hb, "__wbg_Error_2e59b1b37a9a34c3", p2, r1, func(s []uint64) {
		s[0] = uint64(w.add(errorT{w.readStr(uint32(s[0]), uint32(s[1]))}))
	})
	def(hb, "__wbg___wbindgen_is_object_40c5a80572e8f9d3", p1, r1, func(s []uint64) {
		v := w.get(uint32(s[0]))
		_, isMap := v.(map[string]string)
		_, isU8 := v.(*fakeU8)
		_, isGlob := v.(globalT)
		_, isCr := v.(cryptoT)
		_, isPr := v.(processT)
		_, isVer := v.(map[string]any)
		if (isMap || isU8 || isGlob || isCr || isPr || isVer) && v != vNull {
			s[0] = 1
		} else {
			s[0] = 0
		}
	})
	def(hb, "__wbg___wbindgen_is_string_b29b5c5a8065ba1a", p1, r1, func(s []uint64) {
		_, ok := w.get(uint32(s[0])).(string)
		if ok {
			s[0] = 1
		} else {
			s[0] = 0
		}
	})
	def(hb, "__wbg___wbindgen_is_function_49868bde5eb1e745", p1, r1, func(s []uint64) { s[0] = 0 })
	def(hb, "__wbg___wbindgen_is_undefined_c0cca72b82b86f4d", p1, r1, func(s []uint64) {
		if w.get(uint32(s[0])) == vUndefined {
			s[0] = 1
		} else {
			s[0] = 0
		}
	})
	def(hb, "__wbindgen_cast_0000000000000001", p2, r1, func(s []uint64) {
		ptr, ln := uint32(s[0]), uint32(s[1])
		s[0] = uint64(w.add(&fakeU8{n: int(ln), mem: w.mem, ptr: ptr, memBack: true}))
	})
	def(hb, "__wbindgen_cast_0000000000000002", p2, r1, func(s []uint64) {
		s[0] = uint64(w.add(w.readStr(uint32(s[0]), uint32(s[1]))))
	})

	if _, err := hb.Instantiate(ctx); err != nil {
		return nil, fmt.Errorf("host module instantiate: %w", err)
	}
	mod, err := r.InstantiateWithConfig(ctx, authWasm, wazero.NewModuleConfig())
	if err != nil {
		return nil, fmt.Errorf("auth wasm instantiate: %w", err)
	}
	w.mod = mod
	w.mem = mod.Memory()
	w.mall = mod.ExportedFunction("__wbindgen_export2")
	w.rea = mod.ExportedFunction("__wbindgen_export3")
	w.fre = mod.ExportedFunction("__wbindgen_export4")
	w.ssp = mod.ExportedFunction("__wbindgen_add_to_stack_pointer")
	for _, n := range []string{
		"qodercontext_new", "qodercontext_prepareInferRequest", "qodercontext_prepareRequest",
		"qodercontext_refreshAuthFields", "qodercontext_get_external_providers_access",
		"requestresult_url", "requestresult_headers", "requestresult_body", "requestresult_headerCount",
		"credential_storage_encrypt", "credential_storage_decrypt", "generate_runtime_auth_fields",
		"model_cache_decrypt", "decrypt_server_response", "qodercontext_free",
	} {
		if f := mod.ExportedFunction(n); f != nil {
			w.fns[n] = f
		}
	}
	return w, nil
}

// ---- heap ----
func (w *wasmAuth) add(v any) uint32 {
	if w.heapNext == uint32(len(w.heap)) {
		w.heap = append(w.heap, uint64(len(w.heap)+1))
	}
	h := w.heapNext
	next, ok := w.heap[h].(uint64)
	if !ok || h >= uint32(len(w.heap)) {
		w.heapNext = uint32(len(w.heap))
	} else {
		w.heapNext = uint32(next)
	}
	for uint32(len(w.heap)) <= h {
		w.heap = append(w.heap, vUndefined)
	}
	w.heap[h] = v
	return h
}

func (w *wasmAuth) drop(i uint32) {
	if i < 1028 || i >= uint32(len(w.heap)) {
		return
	}
	w.heap[i] = uint64(w.heapNext)
	w.heapNext = i
}

func (w *wasmAuth) get(i uint32) any {
	if i < uint32(len(w.heap)) {
		return w.heap[i]
	}
	return vUndefined
}

// ---- memory / ABI helpers ----
func (w *wasmAuth) readStr(ptr, ln uint32) string {
	b, ok := w.mem.Read(ptr, ln)
	if !ok {
		return ""
	}
	return string(b)
}

func (w *wasmAuth) passStr(s string) (uint32, uint32, error) {
	b := []byte(s)
	res, err := w.mall.Call(context.Background(), uint64(len(b)), 1)
	if err != nil {
		return 0, 0, err
	}
	ptr := uint32(res[0])
	w.mem.Write(ptr, b)
	return ptr, uint32(len(b)), nil
}

func (w *wasmAuth) retStr(retptr uint32) string {
	b, _ := w.mem.Read(retptr, 8)
	ptr := binary.LittleEndian.Uint32(b)
	ln := binary.LittleEndian.Uint32(b[4:])
	s := w.readStr(ptr, ln)
	w.fre.Call(context.Background(), uint64(ptr), uint64(ln), 1)
	return s
}

func (w *wasmAuth) stackAlloc() uint32 {
	res, err := w.ssp.Call(context.Background(), ^uint64(15)) // -16
	if err != nil {
		panic(err)
	}
	return uint32(res[0])
}

func (w *wasmAuth) stackFree() { w.ssp.Call(context.Background(), 16) }

// callStrFn invokes fn(retptr, ptr,len ...), reads string from [retptr], error flag at +8.
func (w *wasmAuth) callStrFn(name string, strs ...string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn, ok := w.fns[name]
	if !ok {
		return "", fmt.Errorf("wasm export %s missing", name)
	}
	retptr := w.stackAlloc()
	defer w.stackFree()
	args := []uint64{uint64(retptr)}
	for _, s := range strs {
		p, l, err := w.passStr(s)
		if err != nil {
			return "", err
		}
		args = append(args, uint64(p), uint64(l))
	}
	if err := fn.CallWithStack(context.Background(), args); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	b, _ := w.mem.Read(retptr+8, 4)
	if binary.LittleEndian.Uint32(b) != 0 {
		return "", fmt.Errorf("%s: wasm returned error", name)
	}
	return w.retStr(retptr), nil
}

func (w *wasmAuth) credentialDecrypt(blob, key16 string) (string, error) {
	return w.callStrFn("credential_storage_decrypt", blob, key16)
}

func (w *wasmAuth) credentialEncrypt(jsonStr, key16 string) (string, error) {
	return w.callStrFn("credential_storage_encrypt", jsonStr, key16)
}

func (w *wasmAuth) genRuntimeAuthFields(userInfoJSON string) (string, error) {
	return w.callStrFn("generate_runtime_auth_fields", userInfoJSON)
}

func (w *wasmAuth) modelCacheDecrypt(blob, key string) (string, error) {
	return w.callStrFn("model_cache_decrypt", blob, key)
}

// newContext creates a QoderContext (machineID, version, userInfoJSON, sceneJSON).
func (w *wasmAuth) newContext(machineID, version, userInfoJSON, sceneJSON string) (uint32, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	retptr := w.stackAlloc()
	defer w.stackFree()
	args := []uint64{uint64(retptr)}
	for _, s := range []string{machineID, version, userInfoJSON, sceneJSON} {
		p, l, err := w.passStr(s)
		if err != nil {
			return 0, err
		}
		args = append(args, uint64(p), uint64(l))
	}
	if err := w.fns["qodercontext_new"].CallWithStack(context.Background(), args); err != nil {
		return 0, err
	}
	b, _ := w.mem.Read(retptr, 12)
	ptr := binary.LittleEndian.Uint32(b)
	flag := binary.LittleEndian.Uint32(b[8:])
	if flag != 0 {
		return 0, fmt.Errorf("qodercontext_new error flag set")
	}
	return ptr, nil
}

type inferResult struct {
	URL     string
	Headers map[string]string
	Body    string
}

func (w *wasmAuth) prepareInferRequest(ctx uint32, endpoint, bodyJSON, modelKey, modelSource string) (*inferResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	retptr := w.stackAlloc()
	defer w.stackFree()
	args := []uint64{uint64(retptr), uint64(ctx)}
	for _, s := range []string{endpoint, bodyJSON, modelKey, modelSource} {
		p, l, err := w.passStr(s)
		if err != nil {
			return nil, err
		}
		args = append(args, uint64(p), uint64(l))
	}
	if err := w.fns["qodercontext_prepareInferRequest"].CallWithStack(context.Background(), args); err != nil {
		return nil, err
	}
	b, _ := w.mem.Read(retptr, 12)
	rptr := binary.LittleEndian.Uint32(b)
	flag := binary.LittleEndian.Uint32(b[8:])
	if flag != 0 {
		return nil, fmt.Errorf("prepareInferRequest error flag set")
	}
	// url
	rp := w.stackAlloc()
	w.fns["requestresult_url"].CallWithStack(context.Background(), []uint64{uint64(rp), uint64(rptr)})
	url := w.retStr(rp)
	w.stackFree()
	// headers
	res, err := w.fns["requestresult_headers"].Call(context.Background(), uint64(rptr))
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	if hm, ok := w.get(uint32(res[0])).(map[string]string); ok {
		for k, v := range hm {
			headers[k] = v
		}
	}
	// body
	rp = w.stackAlloc()
	w.fns["requestresult_body"].CallWithStack(context.Background(), []uint64{uint64(rp), uint64(rptr)})
	bb, _ := w.mem.Read(rp, 8)
	bodyPtr := binary.LittleEndian.Uint32(bb)
	bodyLn := binary.LittleEndian.Uint32(bb[4:])
	var body string
	if bodyPtr != 0 {
		body = w.readStr(bodyPtr, bodyLn)
		w.fre.Call(context.Background(), uint64(bodyPtr), uint64(bodyLn), 1)
	}
	w.stackFree()
	return &inferResult{URL: url, Headers: headers, Body: body}, nil
}

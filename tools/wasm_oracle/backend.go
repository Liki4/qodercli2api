package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type freeAccounting struct{ ResultStrings, Contexts, RequestResults int }
type deterministicHost interface {
	Now() (time.Time, error)
	Read([]byte) error
}
type wasmBackend struct {
	runtime             wazero.Runtime
	compiled            wazero.CompiledModule
	hostModule, module  api.Module
	mem                 api.Memory
	malloc, free, stack api.Function
	functions           map[string]api.Function
	heap                []any
	heapNext            uint32
	replay              deterministicHost
	hostFail            error
	accounting          freeAccounting
}

func newWASMBackend(ctx context.Context, source []byte) (*wasmBackend, error) {
	if err := validateWASM(source); err != nil {
		return nil, err
	}
	w := &wasmBackend{runtime: wazero.NewRuntime(ctx), functions: map[string]api.Function{}}
	w.heap = make([]any, 1024)
	w.heap = append(w.heap, undefinedValue, nullSentinel, true, false)
	w.heapNext = 1028
	failClose := func(err error) (*wasmBackend, error) { _ = w.Close(ctx); return nil, err }
	compiled, err := w.runtime.CompileModule(ctx, source)
	if err != nil {
		return failClose(fail("wasm-compile"))
	}
	w.compiled = compiled
	if err := w.instantiateHost(ctx); err != nil {
		return failClose(fail("wasm-host"))
	}
	module, err := w.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return failClose(fail("wasm-instantiate"))
	}
	w.module = module
	w.mem = module.Memory()
	if w.mem == nil {
		return failClose(fail("wasm-abi"))
	}
	for name, dst := range map[string]*api.Function{"__wbindgen_export2": &w.malloc, "__wbindgen_export4": &w.free, "__wbindgen_add_to_stack_pointer": &w.stack} {
		fn := module.ExportedFunction(name)
		if fn == nil {
			return failClose(fail("wasm-abi"))
		}
		*dst = fn
	}
	for _, name := range []string{"credential_storage_encrypt", "credential_storage_decrypt", "generate_runtime_auth_fields", "model_cache_encrypt", "model_cache_decrypt", "decrypt_server_response", "qodercontext_new", "qodercontext_prepareInferRequest", "requestresult_url", "requestresult_headers", "requestresult_body", "__wbg_qodercontext_free", "__wbg_requestresult_free"} {
		fn := module.ExportedFunction(name)
		if fn == nil {
			return failClose(fail("wasm-abi"))
		}
		w.functions[name] = fn
	}
	return w, nil
}
func (w *wasmBackend) Close(ctx context.Context) error {
	if w.runtime != nil {
		return w.runtime.Close(ctx)
	}
	return nil
}
func (w *wasmBackend) setReplay(replay deterministicHost) { w.replay = replay; w.hostFail = nil }
func (w *wasmBackend) add(v any) uint32 {
	if w.heapNext == uint32(len(w.heap)) {
		w.heap = append(w.heap, uint64(len(w.heap)+1))
	}
	index := w.heapNext
	next, ok := w.heap[index].(uint64)
	if !ok {
		w.heapNext = uint32(len(w.heap))
	} else {
		w.heapNext = uint32(next)
	}
	for uint32(len(w.heap)) <= index {
		w.heap = append(w.heap, undefinedValue)
	}
	w.heap[index] = v
	return index
}
func (w *wasmBackend) drop(index uint32) {
	if index < 1028 || index >= uint32(len(w.heap)) {
		return
	}
	w.heap[index] = uint64(w.heapNext)
	w.heapNext = index
}
func (w *wasmBackend) get(index uint32) any {
	if index < uint32(len(w.heap)) {
		return w.heap[index]
	}
	return undefinedValue
}
func (w *wasmBackend) take(index uint32) any { value := w.get(index); w.drop(index); return value }
func (w *wasmBackend) readString(ptr, length uint32) string {
	data, ok := w.mem.Read(ptr, length)
	if !ok {
		w.hostFail = fail("host-memory")
		return ""
	}
	return string(data)
}
func (w *wasmBackend) passString(ctx context.Context, value string) (uint32, uint32, error) {
	data := []byte(value)
	result, err := w.malloc.Call(ctx, uint64(len(data)), 1)
	if err != nil || len(result) != 1 {
		return 0, 0, fail("wasm-abi")
	}
	ptr := uint32(result[0])
	if !w.mem.Write(ptr, data) {
		return 0, 0, fail("wasm-abi")
	}
	return ptr, uint32(len(data)), nil
}
func (w *wasmBackend) stackAlloc(ctx context.Context) (uint32, error) {
	result, err := w.stack.Call(ctx, ^uint64(15))
	if err != nil || len(result) != 1 {
		return 0, fail("wasm-abi")
	}
	return uint32(result[0]), nil
}
func (w *wasmBackend) stackFree(ctx context.Context) error {
	_, err := w.stack.Call(ctx, 16)
	if err != nil {
		return fail("wasm-cleanup")
	}
	return nil
}
func (w *wasmBackend) freeString(ctx context.Context, ptr, length uint32) error {
	if _, err := w.free.Call(ctx, uint64(ptr), uint64(length), 1); err != nil {
		return fail("wasm-cleanup")
	}
	w.accounting.ResultStrings++
	return nil
}
func (w *wasmBackend) callString(ctx context.Context, name string, values ...string) (value string, err error) {
	w.hostFail = nil
	retptr, err := w.stackAlloc(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if cleanup := w.stackFree(ctx); err == nil {
			err = cleanup
		}
	}()
	args := []uint64{uint64(retptr)}
	for _, input := range values {
		ptr, length, passErr := w.passString(ctx, input)
		if passErr != nil {
			return "", passErr
		}
		args = append(args, uint64(ptr), uint64(length))
	}
	if callErr := w.functions[name].CallWithStack(ctx, args); callErr != nil {
		return "", fail("wasm-call")
	}
	data, ok := w.mem.Read(retptr, 16)
	if !ok {
		return "", fail("wasm-abi")
	}
	result, err := decodeStringResult(data)
	if err != nil {
		return "", err
	}
	if result.errorFlag != 0 {
		w.take(result.errorRef)
		return "", fail("wasm-result")
	}
	if result.ptr == 0 {
		if result.length != 0 {
			return "", fail("wasm-abi")
		}
		if w.hostFail != nil {
			return "", w.hostFail
		}
		return "", nil
	}
	defer func() {
		cleanup := w.freeString(ctx, result.ptr, result.length)
		if err == nil {
			err = cleanup
		}
	}()
	if w.hostFail != nil {
		return "", w.hostFail
	}
	bytes, ok := w.mem.Read(result.ptr, result.length)
	if !ok {
		return "", fail("wasm-abi")
	}
	return string(bytes), nil
}
func (w *wasmBackend) newContext(ctx context.Context, machineID, version, user, scene string) (ptr uint32, err error) {
	w.hostFail = nil
	retptr, err := w.stackAlloc(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup := w.stackFree(ctx)
		if err == nil {
			err = cleanup
		}
	}()
	args := []uint64{uint64(retptr)}
	for _, input := range []string{machineID, version, user, scene} {
		p, n, e := w.passString(ctx, input)
		if e != nil {
			return 0, e
		}
		args = append(args, uint64(p), uint64(n))
	}
	if e := w.functions["qodercontext_new"].CallWithStack(ctx, args); e != nil {
		return 0, fail("wasm-call")
	}
	data, ok := w.mem.Read(retptr, objectResultOffset)
	if !ok {
		return 0, fail("wasm-abi")
	}
	result, e := decodeObjectResult(data)
	if e != nil {
		return 0, e
	}
	if result.errorFlag != 0 {
		w.take(result.errorRef)
		return 0, fail("wasm-result")
	}
	if w.hostFail != nil {
		if result.ptr != 0 {
			_ = w.freeContext(ctx, result.ptr)
		}
		return 0, w.hostFail
	}
	return result.ptr, nil
}
func (w *wasmBackend) freeContext(ctx context.Context, ptr uint32) error {
	if _, err := w.functions["__wbg_qodercontext_free"].Call(ctx, uint64(ptr), 0); err != nil {
		return fail("wasm-cleanup")
	}
	w.accounting.Contexts++
	return nil
}
func (w *wasmBackend) freeRequestResult(ctx context.Context, ptr uint32) error {
	if _, err := w.functions["__wbg_requestresult_free"].Call(ctx, uint64(ptr), 0); err != nil {
		return fail("wasm-cleanup")
	}
	w.accounting.RequestResults++
	return nil
}
func (w *wasmBackend) resultString(ctx context.Context, name string, resultPtr uint32) (value string, err error) {
	retptr, err := w.stackAlloc(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		cleanup := w.stackFree(ctx)
		if err == nil {
			err = cleanup
		}
	}()
	if e := w.functions[name].CallWithStack(ctx, []uint64{uint64(retptr), uint64(resultPtr)}); e != nil {
		return "", fail("wasm-call")
	}
	data, ok := w.mem.Read(retptr, 8)
	if !ok {
		return "", fail("wasm-abi")
	}
	ptr, length := binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:])
	if ptr == 0 {
		if length != 0 {
			return "", fail("wasm-abi")
		}
		return "", nil
	}
	defer func() {
		cleanup := w.freeString(ctx, ptr, length)
		if err == nil {
			err = cleanup
		}
	}()
	bytes, ok := w.mem.Read(ptr, length)
	if !ok {
		return "", fail("wasm-abi")
	}
	return string(bytes), nil
}

type inferOutput struct {
	URL     string
	Headers map[string]string
	Body    string
}

func (w *wasmBackend) prepareInfer(ctx context.Context, contextPtr uint32, endpoint, body, modelKey, modelSource string) (output inferOutput, err error) {
	w.hostFail = nil
	retptr, err := w.stackAlloc(ctx)
	if err != nil {
		return output, err
	}
	defer func() {
		cleanup := w.stackFree(ctx)
		if err == nil {
			err = cleanup
		}
	}()
	args := []uint64{uint64(retptr), uint64(contextPtr)}
	for _, input := range []string{endpoint, body, modelKey, modelSource} {
		p, n, e := w.passString(ctx, input)
		if e != nil {
			return output, e
		}
		args = append(args, uint64(p), uint64(n))
	}
	if e := w.functions["qodercontext_prepareInferRequest"].CallWithStack(ctx, args); e != nil {
		return output, fail("wasm-call")
	}
	data, ok := w.mem.Read(retptr, objectResultOffset)
	if !ok {
		return output, fail("wasm-abi")
	}
	result, e := decodeObjectResult(data)
	if e != nil {
		return output, e
	}
	if result.errorFlag != 0 {
		w.take(result.errorRef)
		return output, fail("wasm-result")
	}
	rptr := result.ptr
	defer func() {
		cleanup := w.freeRequestResult(ctx, rptr)
		if err == nil {
			err = cleanup
		}
	}()
	if w.hostFail != nil {
		return output, w.hostFail
	}
	url, e := w.resultString(ctx, "requestresult_url", rptr)
	if e != nil {
		return output, e
	}
	headerResult, e := w.functions["requestresult_headers"].Call(ctx, uint64(rptr))
	if e != nil || len(headerResult) != 1 {
		return output, fail("wasm-abi")
	}
	index := uint32(headerResult[0])
	defer w.drop(index)
	headers, ok := w.get(index).(map[string]string)
	if !ok {
		return output, fail("wasm-abi")
	}
	copied := map[string]string{}
	for key, value := range headers {
		copied[key] = value
	}
	bodyResult, e := w.resultString(ctx, "requestresult_body", rptr)
	if e != nil {
		return output, e
	}
	return inferOutput{url, copied, bodyResult}, nil
}
func (w *wasmBackend) String() string {
	return fmt.Sprintf("strings=%d contexts=%d results=%d", w.accounting.ResultStrings, w.accounting.Contexts, w.accounting.RequestResults)
}

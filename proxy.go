package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type server struct {
	auth     *authManager
	wasm     *wasmAuth
	sk       string
	models   *modelResolver
	httpc    *http.Client
	logf     func(string, ...any)
	dumpDir  string
	sessMu   sync.Mutex
	sessions map[string]string
	dumpMu   sync.Mutex
	pending  map[string][]byte
}

// rememberBody keeps the plaintext upstream body so a failing request can be
// dumped for offline replay/bisection.
func (s *server) rememberBody(requestID string, body []byte) {
	if s.dumpDir == "" {
		return
	}
	s.dumpMu.Lock()
	defer s.dumpMu.Unlock()
	if s.pending == nil {
		s.pending = map[string][]byte{}
	}
	s.pending[requestID] = body
}

func (s *server) forgetBody(requestID string) {
	if s.dumpDir == "" {
		return
	}
	s.dumpMu.Lock()
	defer s.dumpMu.Unlock()
	delete(s.pending, requestID)
}

// dumpFailure writes the failing request body plus the upstream error message.
func (s *server) dumpFailure(requestID, errMsg string) {
	if s.dumpDir == "" {
		return
	}
	s.dumpMu.Lock()
	body := s.pending[requestID]
	s.dumpMu.Unlock()
	if body == nil {
		return
	}
	if err := os.MkdirAll(s.dumpDir, 0o700); err != nil {
		s.logf("dump mkdir: %v", err)
		return
	}
	base := filepath.Join(s.dumpDir, requestID[:8])
	if err := os.WriteFile(base+".body.json", body, 0o600); err != nil {
		s.logf("dump write: %v", err)
		return
	}
	os.WriteFile(base+".error.txt", []byte(errMsg), 0o600)
	s.logf("req %s failing request dumped to %s.body.json", requestID[:8], base)
}

type modelResolver struct {
	byKey   map[string]*modelConfig
	mapping map[string]string
	def     string
	oneM    string
}

func newModelResolver(catalog []*modelConfig, mapping map[string]string, def string, oneM string) *modelResolver {
	r := &modelResolver{byKey: map[string]*modelConfig{}, mapping: mapping, def: def, oneM: oneM}
	for _, mc := range catalog {
		r.byKey[mc.Key] = mc
	}
	if r.def == "" {
		r.def = "auto"
	}
	if r.oneM == "" {
		r.oneM = "ultimate"
	}
	return r
}

// resolve maps a client model name to a qoder model_config.
// A "[1m]" suffix on the model name requests a 1M-context upstream model.
func (r *modelResolver) resolve(clientModel string) *modelConfig {
	want1M := false
	name := clientModel
	if strings.HasSuffix(name, "[1m]") {
		want1M = true
		name = strings.TrimSuffix(name, "[1m]")
	}
	key := ""
	if r.mapping != nil {
		if v, ok := r.mapping[name]; ok {
			key = v
		} else if v, ok := r.mapping["*"]; ok {
			key = v
		}
	}
	if key == "" {
		if _, ok := r.byKey[name]; ok {
			key = name
		} else {
			key = r.def
		}
	}
	mc := r.byKeyOrSynthetic(key)
	if want1M && mc.MaxInputTokens < 900000 {
		if big := r.byKeyOrSynthetic(r.oneM); big.MaxInputTokens >= 900000 {
			return big
		}
	}
	return mc
}

func (r *modelResolver) byKeyOrSynthetic(key string) *modelConfig {
	if mc, ok := r.byKey[key]; ok {
		cp := *mc
		return &cp
	}
	return &modelConfig{Key: key, Format: "openai", Source: "system", Enable: true, IsVL: true}
}

func (s *server) sessionFor(clientModel string) string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]string{}
	}
	if id, ok := s.sessions[clientModel]; ok {
		return id
	}
	id := "q2a-" + newUUID()
	s.sessions[clientModel] = id
	return id
}

func (s *server) authOK(r *http.Request) bool {
	if s.sk == "" {
		return true
	}
	if v := r.Header.Get("x-api-key"); v == s.sk {
		return true
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") && strings.TrimPrefix(v, "Bearer ") == s.sk {
		return true
	}
	return false
}

func writeAnthropicError(w http.ResponseWriter, status int, errType, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": errType, "message": msg},
	})
}

func (s *server) handleMessages(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid or missing api key")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeAnthropicError(w, 400, "invalid_request_error", err.Error())
		return
	}
	var areq anthropicRequest
	if err := json.Unmarshal(raw, &areq); err != nil {
		writeAnthropicError(w, 400, "invalid_request_error", "invalid JSON: "+err.Error())
		return
	}
	if areq.Model == "" {
		writeAnthropicError(w, 400, "invalid_request_error", "model is required")
		return
	}
	if areq.MaxTokens == 0 {
		areq.MaxTokens = 32000
	}
	mc := s.models.resolve(areq.Model)
	requestID := newUUID()
	sessionID := s.sessionFor(areq.Model)
	body, err := buildUpstreamBody(&areq, mc, sessionID, requestID)
	if err != nil {
		writeAnthropicError(w, 400, "invalid_request_error", err.Error())
		return
	}
	effort := ""
	if req2 := areq.Thinking; req2 != nil {
		effort = fmt.Sprintf(" thinking=%s/%d", req2.Type, req2.BudgetTokens)
	}
	s.logf("req %s model=%s->%s stream=%v bytes=%d msgs=%d tools=%d%s", requestID[:8], areq.Model, mc.Key, areq.Stream, len(raw), len(areq.Messages), len(areq.Tools), effort)
	s.rememberBody(requestID, body)
	defer s.forgetBody(requestID)

	resp, err := s.callUpstream(r.Context(), body, mc, requestID[:8])
	if err != nil {
		s.logf("req %s upstream error: %v", requestID[:8], err)
		writeAnthropicError(w, 502, "api_error", "upstream request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		s.logf("req %s upstream final status %d: %s", requestID[:8], resp.StatusCode, truncate(string(b), 500))
		writeAnthropicError(w, resp.StatusCode, "api_error", fmt.Sprintf("upstream status %d: %s", resp.StatusCode, truncate(string(b), 300)))
		return
	}

	if areq.Stream {
		s.streamAnthropic(w, resp.Body, &areq, requestID)
	} else {
		s.collectAnthropic(w, resp.Body, &areq, requestID)
	}
}

func retryableStatus(code int) bool {
	return code == 408 || code == 429 || (code >= 500 && code < 600)
}

// queueWait extracts server-provided wait time from a queued/overload body.
// Upstream signals queueing with {"code":"10605",...} or {"queue":{"isQueued":true,"waitTime":ms}}.
func queueWait(body []byte) (time.Duration, bool) {
	var parsed struct {
		Code         string `json:"code"`
		RetryAfterMs int64  `json:"retryAfterMs"`
		Queue        *struct {
			IsQueued bool  `json:"isQueued"`
			WaitTime int64 `json:"waitTime"`
		} `json:"queue"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return 0, false
	}
	if parsed.Queue != nil && parsed.Queue.IsQueued {
		ms := parsed.Queue.WaitTime
		if ms <= 0 {
			ms = parsed.RetryAfterMs
		}
		if ms <= 0 {
			ms = 2000
		}
		return time.Duration(ms) * time.Millisecond, true
	}
	if parsed.Code == "10605" {
		ms := parsed.RetryAfterMs
		if ms <= 0 {
			ms = 2000
		}
		return time.Duration(ms) * time.Millisecond, true
	}
	return 0, false
}

func errorResponse(orig *http.Response, body []byte) *http.Response {
	return &http.Response{
		Status:        orig.Status,
		StatusCode:    orig.StatusCode,
		Header:        orig.Header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       orig.Request,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// callUpstream performs the upstream call with retries for auth expiry,
// rate limits, gateway errors and server-side queueing.
func (s *server) callUpstream(ctx context.Context, body []byte, mc *modelConfig, rid string) (*http.Response, error) {
	const maxAttempts = 4
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := s.doUpstream(ctx, body, mc)
		if err != nil {
			if attempt < maxAttempts {
				s.logf("req %s upstream transport error (attempt %d/%d): %v", rid, attempt, maxAttempts, err)
				if !sleepCtx(ctx, time.Duration(attempt)*time.Second) {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, err
		}
		if resp.StatusCode == 200 {
			return resp, nil
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		retryAfter := resp.Header.Get("Retry-After")
		resp.Body.Close()
		if resp.StatusCode == 401 {
			if attempt == 1 {
				s.logf("req %s upstream 401, refreshing token", rid)
				if rerr := s.auth.forceRefresh(ctx); rerr == nil {
					continue
				}
			}
			return errorResponse(resp, raw), nil
		}
		wait, queued := queueWait(raw)
		if retryableStatus(resp.StatusCode) || queued {
			if attempt >= maxAttempts {
				return errorResponse(resp, raw), nil
			}
			if !queued {
				wait = time.Duration(1<<uint(attempt-1)) * time.Second
				if retryAfter != "" {
					if secs, perr := time.ParseDuration(retryAfter + "s"); perr == nil {
						wait = secs
					}
				}
			}
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			s.logf("req %s upstream status %d (attempt %d/%d), retry in %v: %s", rid, resp.StatusCode, attempt, maxAttempts, wait, truncate(string(raw), 300))
			if !sleepCtx(ctx, wait) {
				return nil, ctx.Err()
			}
			continue
		}
		return errorResponse(resp, raw), nil
	}
	return nil, fmt.Errorf("unreachable")
}

func (s *server) doUpstream(ctx context.Context, body []byte, mc *modelConfig) (*http.Response, error) {
	if err := s.auth.ensureFresh(ctx); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	ir, err := s.wasm.prepareInferRequest(s.auth.wasmCtx(), s.auth.inferEndpoint(), string(body), mc.Key, mc.Source)
	if err != nil {
		return nil, fmt.Errorf("prepareInferRequest: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", ir.URL, strings.NewReader(ir.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range ir.Headers {
		req.Header.Set(k, v)
	}
	return s.httpc.Do(req)
}

// ---------- SSE parsing ----------

type sseFrame struct {
	event string
	data  string
}

func readSSE(ctx context.Context, rd io.Reader, fn func(sseFrame) bool) error {
	br := bufio.NewReaderSize(rd, 64*1024)
	var event, data strings.Builder
	flush := func() bool {
		if data.Len() == 0 && event.Len() == 0 {
			return true
		}
		f := sseFrame{event: event.String(), data: data.String()}
		event.Reset()
		data.Reset()
		return fn(f)
	}
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			trim := strings.TrimRight(line, "\r\n")
			switch {
			case trim == "":
				if !flush() {
					return nil
				}
			case strings.HasPrefix(trim, "event:"):
				if event.Len() > 0 {
					event.WriteByte(' ')
				}
				event.WriteString(strings.TrimSpace(strings.TrimPrefix(trim, "event:")))
			case strings.HasPrefix(trim, "data:"):
				d := strings.TrimPrefix(trim, "data:")
				d = strings.TrimPrefix(d, " ")
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(d)
			}
		}
		if err != nil {
			if err == io.EOF {
				flush()
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			return err
		}
	}
}

// ---------- stream conversion ----------

type streamState struct {
	w            http.ResponseWriter
	flusher      http.Flusher
	msgID        string
	model        string
	blockType    string // "", "thinking", "text", "tool_use"
	blockIndex   int
	toolID       string
	toolName     string
	started      bool
	stopped      bool
	inputTokens  int
	outputTokens int
	cacheRead    int
	cacheWrite   int
	stopReason   string
	err          error
}

// setUsage records upstream usage, splitting cached prompt tokens out so the
// Anthropic-shaped usage reports them as cache reads.
func (s *streamState) setUsage(u *upUsage) {
	s.cacheRead = u.cachedTokens()
	s.cacheWrite = u.cacheWriteTokens()
	s.inputTokens = max(u.PromptTokens-s.cacheRead-s.cacheWrite, 0)
	s.outputTokens = u.CompletionTokens
}

func (s *streamState) usagePayload() map[string]int {
	return map[string]int{
		"input_tokens":                s.inputTokens,
		"output_tokens":               s.outputTokens,
		"cache_read_input_tokens":     s.cacheRead,
		"cache_creation_input_tokens": s.cacheWrite,
	}
}

func (s *streamState) finish() {
	if s.stopped {
		return
	}
	s.closeBlock()
	if s.stopReason == "" {
		s.stopReason = "end_turn"
	}
	s.emit("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": s.stopReason, "stop_sequence": nil},
		"usage": s.usagePayload(),
	})
	s.emit("message_stop", map[string]any{"type": "message_stop"})
	s.stopped = true
}

func (s *streamState) emit(event string, payload any) {
	if s.stopped {
		return
	}
	b, _ := json.Marshal(payload)
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, b)
	s.flusher.Flush()
}

func (s *streamState) messageStart() {
	if s.started {
		return
	}
	s.started = true
	s.emit("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": s.msgID, "type": "message", "role": "assistant",
			"content": []any{}, "model": s.model,
			"stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]int{"input_tokens": 0, "output_tokens": 0},
		},
	})
}

func (s *streamState) closeBlock() {
	if s.blockType == "" {
		return
	}
	s.emit("content_block_stop", map[string]any{"type": "content_block_stop", "index": s.blockIndex})
	s.blockType = ""
	s.blockIndex++
}

func (s *streamState) openBlock(kind string, startPayload map[string]any) {
	s.messageStart()
	if s.blockType == kind {
		return
	}
	s.startBlock(kind, startPayload)
}

// startBlock always begins a new content block, even when one of the same kind
// is already open. Parallel tool calls need this: upstream reuses index 0 for
// every call and only signals a new call with a fresh id, so reusing the open
// block would concatenate both calls' arguments into one invalid JSON object.
func (s *streamState) startBlock(kind string, startPayload map[string]any) {
	s.messageStart()
	s.closeBlock()
	s.blockType = kind
	s.emit("content_block_start", map[string]any{
		"type": "content_block_start", "index": s.blockIndex, "content_block": startPayload,
	})
}

func (s *streamState) toolBlockPayload() map[string]any {
	return map[string]any{"type": "tool_use", "id": s.toolID, "name": s.toolName, "input": map[string]any{}}
}

func (s *streamState) handleChunk(c *upChunk) {
	if len(c.Choices) == 0 {
		if c.Usage != nil {
			s.setUsage(c.Usage)
		}
		return
	}
	ch := c.Choices[0]
	d := ch.Delta
	if d.ReasoningContent != "" {
		s.openBlock("thinking", map[string]any{"type": "thinking", "thinking": ""})
		s.emit("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": s.blockIndex,
			"delta": map[string]any{"type": "thinking_delta", "thinking": d.ReasoningContent},
		})
	}
	if d.Content != "" {
		s.openBlock("text", map[string]any{"type": "text", "text": ""})
		s.emit("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": s.blockIndex,
			"delta": map[string]any{"type": "text_delta", "text": d.Content},
		})
	}
	for _, tc := range d.ToolCalls {
		// A non-empty id marks the start of a new tool call; a name without an id
		// only starts one when no tool block is open yet.
		if tc.ID != "" || (tc.Function.Name != "" && s.blockType != "tool_use") {
			if tc.ID != "" {
				s.toolID = tc.ID
			}
			if tc.Function.Name != "" {
				s.toolName = tc.Function.Name
			}
			s.startBlock("tool_use", s.toolBlockPayload())
		}
		if tc.Function.Arguments != "" {
			if s.blockType != "tool_use" {
				s.startBlock("tool_use", s.toolBlockPayload())
			}
			s.emit("content_block_delta", map[string]any{
				"type": "content_block_delta", "index": s.blockIndex,
				"delta": map[string]any{"type": "input_json_delta", "partial_json": tc.Function.Arguments},
			})
		}
	}
	if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
		s.stopReason = mapStopReason(*ch.FinishReason)
		if c.Usage != nil {
			s.setUsage(c.Usage)
		}
		s.closeBlock()
	}
}

func (s *server) streamAnthropic(w http.ResponseWriter, body io.Reader, areq *anthropicRequest, requestID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAnthropicError(w, 500, "api_error", "streaming unsupported")
		return
	}
	w.WriteHeader(200)
	st := &streamState{w: w, flusher: flusher, msgID: "msg_" + strings.ReplaceAll(requestID, "-", ""), model: areq.Model}
	var protoErr error
	err := readSSE(context.Background(), body, func(f sseFrame) bool {
		payload := strings.TrimSpace(f.data)
		if f.event == "finish" {
			st.finish()
			return false
		}
		if payload == "" {
			return true
		}
		var env sseEnvelope
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			return true
		}
		if env.StatusCodeValue != 0 && env.StatusCodeValue != 200 {
			var ebody struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			json.Unmarshal([]byte(env.Body), &ebody)
			msg := ebody.Message
			if msg == "" {
				msg = fmt.Sprintf("upstream error status %d", env.StatusCodeValue)
			}
			st.emit("error", map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": msg},
			})
			protoErr = fmt.Errorf("%s", msg)
			return false
		}
		if env.Body == "" {
			return true
		}
		var chunk upChunk
		if err := json.Unmarshal([]byte(env.Body), &chunk); err != nil {
			return true
		}
		if chunk.Error != nil && chunk.Error.Message != "" {
			st.emit("error", map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": chunk.Error.Message},
			})
			protoErr = fmt.Errorf("%s", chunk.Error.Message)
			return false
		}
		st.handleChunk(&chunk)
		return !st.stopped
	})
	if protoErr != nil {
		s.logf("req %s in-stream upstream error: %s", requestID[:8], truncate(protoErr.Error(), 500))
		s.dumpFailure(requestID, protoErr.Error())
	}
	if err != nil && protoErr == nil && !st.stopped {
		s.logf("req %s stream read error: %v", requestID[:8], err)
	}
	if !st.stopped && protoErr == nil && st.started {
		st.finish()
	}
	if st.cacheRead > 0 || st.inputTokens > 0 {
		s.logf("req %s usage input=%d cache_write=%d cache_read=%d output=%d", requestID[:8], st.inputTokens, st.cacheWrite, st.cacheRead, st.outputTokens)
	}
}

// ---------- non-stream aggregation ----------

func (s *server) collectAnthropic(w http.ResponseWriter, body io.Reader, areq *anthropicRequest, requestID string) {
	var textBuf, thinkBuf strings.Builder
	type toolAcc struct {
		id, name, args strings.Builder
	}
	var tools []struct {
		id, name, args string
	}
	var curTool *struct {
		id, name, args string
	}
	flushTool := func() {
		if curTool != nil {
			tools = append(tools, *curTool)
			curTool = nil
		}
	}
	stopReason := "end_turn"
	inTok, outTok, cacheRead, cacheWrite := 0, 0, 0, 0
	var firstErr string

	readSSE(context.Background(), body, func(f sseFrame) bool {
		payload := strings.TrimSpace(f.data)
		if payload == "" {
			return true
		}
		if f.event == "finish" {
			return false
		}
		var env sseEnvelope
		if json.Unmarshal([]byte(payload), &env) != nil {
			return true
		}
		if env.StatusCodeValue != 0 && env.StatusCodeValue != 200 {
			var ebody struct {
				Message string `json:"message"`
			}
			json.Unmarshal([]byte(env.Body), &ebody)
			firstErr = ebody.Message
			if firstErr == "" {
				firstErr = fmt.Sprintf("upstream error status %d", env.StatusCodeValue)
			}
			return false
		}
		if env.Body == "" {
			return true
		}
		var chunk upChunk
		if json.Unmarshal([]byte(env.Body), &chunk) != nil {
			return true
		}
		if chunk.Error != nil && chunk.Error.Message != "" {
			firstErr = chunk.Error.Message
			return false
		}
		if len(chunk.Choices) == 0 {
			if chunk.Usage != nil {
				cacheRead = chunk.Usage.cachedTokens()
				cacheWrite = chunk.Usage.cacheWriteTokens()
				inTok = max(chunk.Usage.PromptTokens-cacheRead-cacheWrite, 0)
				outTok = chunk.Usage.CompletionTokens
			}
			return true
		}
		ch := chunk.Choices[0]
		d := ch.Delta
		if d.ReasoningContent != "" {
			thinkBuf.WriteString(d.ReasoningContent)
		}
		if d.Content != "" {
			textBuf.WriteString(d.Content)
		}
		for _, tc := range d.ToolCalls {
			if tc.ID != "" || tc.Function.Name != "" {
				flushTool()
				curTool = &struct{ id, name, args string }{}
				if tc.ID != "" {
					curTool.id = tc.ID
				}
				if tc.Function.Name != "" {
					curTool.name = tc.Function.Name
				}
			}
			if tc.Function.Arguments != "" && curTool != nil {
				curTool.args += tc.Function.Arguments
			}
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
			stopReason = mapStopReason(*ch.FinishReason)
			if chunk.Usage != nil {
				cacheRead = chunk.Usage.cachedTokens()
				cacheWrite = chunk.Usage.cacheWriteTokens()
				inTok = max(chunk.Usage.PromptTokens-cacheRead-cacheWrite, 0)
				outTok = chunk.Usage.CompletionTokens
			}
		}
		return true
	})
	flushTool()

	if firstErr != "" {
		s.logf("req %s in-stream upstream error: %s", requestID[:8], truncate(firstErr, 500))
		s.dumpFailure(requestID, firstErr)
		writeAnthropicError(w, 502, "api_error", firstErr)
		return
	}
	var content []map[string]any
	if thinkBuf.Len() > 0 {
		content = append(content, map[string]any{"type": "thinking", "thinking": thinkBuf.String()})
	}
	if textBuf.Len() > 0 {
		content = append(content, map[string]any{"type": "text", "text": textBuf.String()})
	}
	for _, t := range tools {
		input := json.RawMessage(`{}`)
		if t.args != "" && json.Valid([]byte(t.args)) {
			input = json.RawMessage(t.args)
		}
		content = append(content, map[string]any{
			"type": "tool_use", "id": t.id, "name": t.name, "input": input,
		})
	}
	if content == nil {
		content = []map[string]any{}
	}
	resp := anthropicResponse{
		ID:         "msg_" + strings.ReplaceAll(requestID, "-", ""),
		Type:       "message",
		Role:       "assistant",
		Content:    content,
		Model:      areq.Model,
		StopReason: stopReason,
		Usage: map[string]int{
			"input_tokens":                inTok,
			"output_tokens":               outTok,
			"cache_read_input_tokens":     cacheRead,
			"cache_creation_input_tokens": cacheWrite,
		},
	}
	s.logf("req %s usage input=%d cache_write=%d cache_read=%d output=%d", requestID[:8], inTok, cacheWrite, cacheRead, outTok)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *server) handleModels(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid or missing api key")
		return
	}
	var list []map[string]any
	for _, mc := range s.models.byKey {
		list = append(list, map[string]any{
			"id": mc.Key, "object": "model", "created": 0, "owned_by": "qoder",
			"type": "model", "display_name": mc.DisplayName,
			"max_tokens": mc.MaxInputTokens,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": list})
}

func (s *server) handleCountTokens(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid or missing api key")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeAnthropicError(w, 400, "invalid_request_error", err.Error())
		return
	}
	// rough estimate: ~4 chars per token, floor at message count
	est := len(raw) / 4
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"input_tokens": est})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		s.logf("http %s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/messages", s.handleMessages)
	mux.HandleFunc("POST /v1/messages/count_tokens", s.handleCountTokens)
	mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("POST /v1/responses", s.handleResponses)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"authenticated":%v}`, s.auth.loggedIn())
	})
	return mux
}

func (s *server) handler() http.Handler {
	return s.logMiddleware(s.routes())
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---------- shared upstream body construction ----------

// businessInfo builds the `business` field. Upstream requires it: some models
// (e.g. ultimate) are routed through a node that rejects requests without it
// with `[FAIL]node:oa_qwen-plus... Execution failed: null`.
func businessInfo(msgs []upMessage) map[string]any {
	name := lastUserText(msgs)
	if len(name) > 10 {
		name = name[:10]
	}
	return map[string]any{
		"product":  "cli",
		"version":  cliVersion,
		"type":     "agent",
		"id":       newUUID(),
		"name":     name,
		"begin_at": time.Now().UnixMilli(),
		"stage":    "start",
	}
}

func lastUserText(msgs []upMessage) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != "user" {
			continue
		}
		switch c := msgs[i].Content.(type) {
		case string:
			if c != "" {
				return c
			}
		case []upContentPart:
			for _, p := range c {
				if p.Type == "text" && p.Text != "" {
					return p.Text
				}
			}
		}
	}
	return ""
}

func remoteChatAskBody(system string, msgs []upMessage, tools []map[string]any, params map[string]any, mc *modelConfig, sessionID, requestID string) ([]byte, error) {
	if tools == nil {
		tools = []map[string]any{}
	}
	// Upstream reads the system prompt from messages[0], not the top-level
	// `system` field; the official client sends both. Sending only the top-level
	// field silently drops the system prompt.
	if system != "" {
		msgs = append([]upMessage{{Role: "system", Content: system}}, msgs...)
	}
	body := map[string]any{
		"business":         businessInfo(msgs),
		"request_id":       requestID,
		"request_set_id":   requestID,
		"chat_record_id":   requestID,
		"session_id":       sessionID,
		"stream":           true,
		"chat_task":        "FREE_INPUT",
		"chat_context":     map[string]any{},
		"is_reply":         true,
		"is_retry":         false,
		"source":           1,
		"version":          "3",
		"agent_id":         "agent_common",
		"task_id":          "common",
		"session_type":     "qodercli",
		"aliyun_user_type": "",
		"model_config":     mc,
		"custom_model":     nil,
		"system":           system,
		"messages":         msgs,
		"tools":            tools,
		"parameters":       params,
	}
	return json.Marshal(body)
}

// upstreamChunks turns an upstream SSE body into a channel of parsed chunks.
// The channel is closed after the finish event, an error, or EOF.
// errRet (if non-nil) receives the terminal error / protocol error message.
func upstreamChunks(ctx context.Context, body io.Reader) (<-chan *upChunk, <-chan error) {
	out := make(chan *upChunk, 16)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		err := readSSE(ctx, body, func(f sseFrame) bool {
			payload := strings.TrimSpace(f.data)
			if f.event == "finish" {
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
					Message string `json:"message"`
				}
				json.Unmarshal([]byte(env.Body), &ebody)
				if ebody.Message == "" {
					ebody.Message = fmt.Sprintf("upstream error status %d", env.StatusCodeValue)
				}
				errc <- fmt.Errorf("%s", ebody.Message)
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
				errc <- fmt.Errorf("%s", chunk.Error.Message)
				return false
			}
			select {
			case out <- &chunk:
			case <-ctx.Done():
				return false
			}
			return true
		})
		if err != nil {
			select {
			case errc <- err:
			default:
			}
		}
	}()
	return out, errc
}

// toolIndexer renumbers upstream tool_call indexes. Upstream emits index 0 for
// every parallel tool call and only signals a new call with a fresh id, so
// clients that accumulate by index would merge distinct calls into one.
type toolIndexer struct {
	cur  int
	seen bool
}

func (t *toolIndexer) remap(c *upChunk) {
	for ci := range c.Choices {
		tcs := c.Choices[ci].Delta.ToolCalls
		for i := range tcs {
			if tcs[i].ID != "" {
				if t.seen {
					t.cur++
				} else {
					t.seen = true
				}
			}
			tcs[i].Index = t.cur
		}
	}
}

// ---------- OpenAI chat completions types ----------

type oaiRequest struct {
	Model               string           `json:"model"`
	Messages            []oaiMessage     `json:"messages"`
	Tools               []map[string]any `json:"tools,omitempty"`
	ToolChoice          json.RawMessage  `json:"tool_choice,omitempty"`
	MaxTokens           int              `json:"max_tokens,omitempty"`
	MaxCompletionTokens int              `json:"max_completion_tokens,omitempty"`
	Stream              bool             `json:"stream,omitempty"`
	StreamOptions       *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options,omitempty"`
	Temperature     *float64        `json:"temperature,omitempty"`
	TopP            *float64        `json:"top_p,omitempty"`
	Stop            json.RawMessage `json:"stop,omitempty"`
	ReasoningEffort string          `json:"reasoning_effort,omitempty"`
}

type oaiMessage struct {
	Role       string       `json:"role"`
	Content    any          `json:"content"`
	Name       string       `json:"name,omitempty"`
	ToolCalls  []upToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

func normalizeEffort(e string) string {
	switch e {
	case "minimal":
		return "low"
	case "none", "low", "medium", "high", "xhigh", "max":
		return e
	}
	return ""
}

func stopFromRaw(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	return nil
}

// oaiToUpstream converts OpenAI messages to upstream messages + system string.
func oaiToUpstream(msgs []oaiMessage) (string, []upMessage) {
	var sysParts []string
	var out []upMessage
	for _, m := range msgs {
		if m.Role == "system" || m.Role == "developer" {
			if s, ok := m.Content.(string); ok {
				sysParts = append(sysParts, s)
			}
			continue
		}
		um := upMessage{Role: m.Role, Name: m.Name, ToolCallID: m.ToolCallID}
		if txt, ok := m.Content.(string); ok && txt != "" && m.Role != "tool" {
			um.Contents = []upPart{{Type: "text", Text: txt}}
		}
		if len(m.ToolCalls) > 0 {
			um.ToolCalls = m.ToolCalls
			if m.Content == nil {
				um.Content = ""
			} else {
				um.Content = m.Content
			}
		} else {
			um.Content = m.Content
		}
		out = append(out, um)
	}
	ensureCacheMarker(out)
	return strings.Join(sysParts, "\n\n"), out
}

func writeOAIError(w http.ResponseWriter, status int, errType, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": errType, "code": code},
	})
}

func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		writeOAIError(w, http.StatusUnauthorized, "authentication_error", "invalid_api_key", "invalid or missing api key")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	var req oaiRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", "invalid JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		writeOAIError(w, 400, "invalid_request_error", "", "model is required")
		return
	}
	mc := s.models.resolve(req.Model)
	maxTok := req.MaxTokens
	if req.MaxCompletionTokens > 0 {
		maxTok = req.MaxCompletionTokens
	}
	if maxTok == 0 {
		maxTok = 32000
	}
	params := map[string]any{"max_tokens": maxTok}
	if mc.MaxInputTokens > 0 {
		params["context_length"] = mc.MaxInputTokens
	}
	if e := normalizeEffort(req.ReasoningEffort); e != "" {
		params["reasoning_effort"] = e
	}
	if req.Temperature != nil {
		params["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		params["top_p"] = *req.TopP
	}
	if st := stopFromRaw(req.Stop); st != nil {
		params["stop"] = st
	}
	if len(req.ToolChoice) > 0 {
		var tc any
		if json.Unmarshal(req.ToolChoice, &tc) == nil {
			params["tool_choice"] = tc
		}
	}
	system, upMsgs := oaiToUpstream(req.Messages)
	requestID := newUUID()
	body, err := remoteChatAskBody(system, upMsgs, req.Tools, params, mc, s.sessionFor(req.Model), requestID)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	s.logf("req %s chat model=%s->%s stream=%v bytes=%d msgs=%d tools=%d", requestID[:8], req.Model, mc.Key, req.Stream, len(raw), len(req.Messages), len(req.Tools))
	resp, err := s.callUpstream(r.Context(), body, mc, requestID[:8])
	if err != nil {
		s.logf("req %s upstream error: %v", requestID[:8], err)
		writeOAIError(w, 502, "api_error", "", "upstream request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		s.logf("req %s upstream final status %d: %s", requestID[:8], resp.StatusCode, truncate(string(b), 500))
		writeOAIError(w, resp.StatusCode, "api_error", "", fmt.Sprintf("upstream status %d: %s", resp.StatusCode, truncate(string(b), 300)))
		return
	}

	chunks, errc := upstreamChunks(r.Context(), resp.Body)
	if req.Stream {
		s.streamOAI(w, chunks, errc, &req, requestID)
	} else {
		s.collectOAI(w, chunks, errc, &req, requestID)
	}
}

// rewriteModel returns a copy of the chunk with the client-requested model name.
func rewriteModel(c *upChunk, model string) *upChunk {
	cp := *c
	cp.Model = model
	return &cp
}

func (s *server) streamOAI(w http.ResponseWriter, chunks <-chan *upChunk, errc <-chan error, req *oaiRequest, requestID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOAIError(w, 500, "api_error", "", "streaming unsupported")
		return
	}
	w.WriteHeader(200)
	writeChunk := func(c *upChunk) {
		b, _ := json.Marshal(rewriteModel(c, req.Model))
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	idx := &toolIndexer{}
	for c := range chunks {
		idx.remap(c)
		writeChunk(c)
	}
	select {
	case err := <-errc:
		if err != nil {
			b, _ := json.Marshal(map[string]any{
				"error": map[string]any{"message": err.Error(), "type": "api_error"},
			})
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
	default:
	}
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func (s *server) collectOAI(w http.ResponseWriter, chunks <-chan *upChunk, errc <-chan error, req *oaiRequest, requestID string) {
	var content, reasoning strings.Builder
	toolMap := map[int]*upToolCall{}
	var toolOrder []int
	finishReason := "stop"
	var usage *upUsage
	var firstErr string
	idx := &toolIndexer{}
	for c := range chunks {
		if c.Usage != nil {
			u := *c.Usage
			usage = &u
		}
		if len(c.Choices) == 0 {
			continue
		}
		idx.remap(c)
		ch := c.Choices[0]
		d := ch.Delta
		content.WriteString(d.Content)
		reasoning.WriteString(d.ReasoningContent)
		for _, tc := range d.ToolCalls {
			acc, ok := toolMap[tc.Index]
			if !ok {
				acc = &upToolCall{Type: "function"}
				toolMap[tc.Index] = acc
				toolOrder = append(toolOrder, tc.Index)
			}
			if tc.ID != "" {
				acc.ID = tc.ID
			}
			if tc.Type != "" {
				acc.Type = tc.Type
			}
			if tc.Function.Name != "" {
				acc.Function.Name = tc.Function.Name
			}
			acc.Function.Arguments += tc.Function.Arguments
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
			finishReason = *ch.FinishReason
		}
	}
	select {
	case err := <-errc:
		if err != nil && firstErr == "" {
			firstErr = err.Error()
		}
	default:
	}
	if firstErr != "" {
		writeOAIError(w, 502, "api_error", "", firstErr)
		return
	}
	var toolCalls []upToolCall
	for _, idx := range toolOrder {
		toolCalls = append(toolCalls, *toolMap[idx])
	}
	msg := map[string]any{"role": "assistant"}
	if content.Len() > 0 {
		msg["content"] = content.String()
	} else {
		msg["content"] = nil
	}
	if reasoning.Len() > 0 {
		msg["reasoning_content"] = reasoning.String()
	}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
	}
	resp := map[string]any{
		"id":      "chatcmpl-" + strings.ReplaceAll(requestID, "-", ""),
		"object":  "chat.completion",
		"created": nowUnix(),
		"model":   req.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       msg,
			"finish_reason": finishReason,
		}},
	}
	if usage != nil {
		u := map[string]any{
			"prompt_tokens":     usage.PromptTokens,
			"completion_tokens": usage.CompletionTokens,
			"total_tokens":      usage.TotalTokens,
		}
		if cached := usage.cachedTokens(); cached > 0 {
			u["prompt_tokens_details"] = map[string]int{"cached_tokens": cached}
		}
		resp["usage"] = u
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func nowUnix() int64 {
	return time.Now().Unix()
}

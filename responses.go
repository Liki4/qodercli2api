package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ---------- Responses API types ----------

type respRequest struct {
	Model           string           `json:"model"`
	Instructions    string           `json:"instructions,omitempty"`
	Input           json.RawMessage  `json:"input,omitempty"`
	Tools           []respTool       `json:"tools,omitempty"`
	ToolChoice      json.RawMessage  `json:"tool_choice,omitempty"`
	MaxOutputTokens int              `json:"max_output_tokens,omitempty"`
	Stream          bool             `json:"stream,omitempty"`
	Reasoning       *struct {
		Effort string `json:"effort,omitempty"`
	} `json:"reasoning,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
}

type respTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type respInputItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments string          `json:"arguments,omitempty"`
	Output    string          `json:"output,omitempty"`
	ID        string          `json:"id,omitempty"`
	Status    string          `json:"status,omitempty"`
}

type respContentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

// respToUpstream converts Responses input to (system, []upMessage).
func respToUpstream(instructions string, input json.RawMessage) (string, []upMessage, error) {
	sysParts := []string{}
	if instructions != "" {
		sysParts = append(sysParts, instructions)
	}
	var msgs []upMessage
	if len(input) == 0 {
		return strings.Join(sysParts, "\n\n"), msgs, nil
	}
	var asString string
	if err := json.Unmarshal(input, &asString); err == nil {
		msgs = append(msgs, upMessage{Role: "user", Content: asString})
		return strings.Join(sysParts, "\n\n"), msgs, nil
	}
	var items []respInputItem
	if err := json.Unmarshal(input, &items); err != nil {
		return "", nil, fmt.Errorf("invalid input: %w", err)
	}
	var pendingAssistant *upMessage
	flushAssistant := func() {
		if pendingAssistant != nil {
			msgs = append(msgs, *pendingAssistant)
			pendingAssistant = nil
		}
	}
	for _, it := range items {
		switch it.Type {
		case "message":
			flushAssistant()
			if it.Role == "system" || it.Role == "developer" {
				sysParts = append(sysParts, respPartsText(it.Content))
				continue
			}
			um := upMessage{Role: it.Role}
			if it.Role == "assistant" {
				um.Content = respPartsText(it.Content)
			} else {
				um.Content = respPartsToOAI(it.Content)
			}
			msgs = append(msgs, um)
		case "function_call":
			if pendingAssistant == nil {
				pendingAssistant = &upMessage{Role: "assistant", Content: ""}
			}
			var tc upToolCall
			tc.ID = it.CallID
			tc.Type = "function"
			tc.Function.Name = it.Name
			tc.Function.Arguments = it.Arguments
			pendingAssistant.ToolCalls = append(pendingAssistant.ToolCalls, tc)
		case "function_call_output":
			flushAssistant()
			msgs = append(msgs, upMessage{Role: "tool", ToolCallID: it.CallID, Content: it.Output})
		case "reasoning", "item_reference":
			// not forwarded upstream
		default:
			flushAssistant()
		}
	}
	flushAssistant()
	return strings.Join(sysParts, "\n\n"), msgs, nil
}

func respPartsText(raw json.RawMessage) string {
	parts := parseRespParts(raw)
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "input_text" || p.Type == "output_text" || p.Type == "text" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

func respPartsToOAI(raw json.RawMessage) any {
	parts := parseRespParts(raw)
	if len(parts) == 0 {
		return ""
	}
	hasImage := false
	for _, p := range parts {
		if p.Type == "input_image" {
			hasImage = true
		}
	}
	if !hasImage {
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "input_text" || p.Type == "output_text" || p.Type == "text" {
				b.WriteString(p.Text)
			}
		}
		return b.String()
	}
	var out []upContentPart
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text":
			out = append(out, upContentPart{Type: "text", Text: p.Text})
		case "input_image":
			pp := upContentPart{Type: "image_url"}
			pp.ImageURL = &struct {
				URL string `json:"url"`
			}{URL: p.ImageURL}
			out = append(out, pp)
		}
	}
	return out
}

func parseRespParts(raw json.RawMessage) []respContentPart {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []respContentPart{{Type: "text", Text: s}}
	}
	var parts []respContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}
	return parts
}

func respToolsToOAI(tools []respTool) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		if t.Type != "function" {
			continue
		}
		params := t.Parameters
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object"}`)
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  params,
			},
		})
	}
	return out
}

// ---------- Responses API emission ----------

type respStreamState struct {
	w          http.ResponseWriter
	flusher    http.Flusher
	respID     string
	model      string
	seq        int
	outIndex   int
	curKind    string // "", "reasoning", "message", "function_call"
	curItemID  string
	fcCallID   string
	fcName     string
	textBuf    strings.Builder
	reasonBuf  strings.Builder
	argsBuf    strings.Builder
	items      []map[string]any
	inTok      int
	outTok     int
	stopReason string
}

func (st *respStreamState) emit(event string, payload map[string]any) {
	st.seq++
	payload["type"] = event
	payload["sequence_number"] = st.seq
	b, _ := json.Marshal(payload)
	fmt.Fprintf(st.w, "event: %s\ndata: %s\n\n", event, b)
	st.flusher.Flush()
}

func (st *respStreamState) baseResponse(status string) map[string]any {
	return map[string]any{
		"id": st.respID, "object": "response", "created_at": nowUnix(),
		"status": status, "model": st.model,
		"output":             []any{},
		"error":              nil,
		"incomplete_details": nil,
		"instructions":       nil,
		"metadata":           map[string]any{},
		"parallel_tool_calls": true,
		"tools":              []any{},
		"tool_choice":        "auto",
		"store":              false,
	}
}

func (st *respStreamState) closeItem() {
	switch st.curKind {
	case "reasoning":
		full := st.reasonBuf.String()
		part := map[string]any{"type": "summary_text", "text": full}
		st.emit("response.reasoning_summary_text.done", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "summary_index": 0, "text": full,
		})
		st.emit("response.reasoning_summary_part.done", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "summary_index": 0, "part": part,
		})
		item := map[string]any{"id": st.curItemID, "type": "reasoning", "summary": []any{part}}
		st.emit("response.output_item.done", map[string]any{"output_index": st.outIndex, "item": item})
		st.items = append(st.items, item)
	case "message":
		full := st.textBuf.String()
		part := map[string]any{"type": "output_text", "text": full, "annotations": []any{}}
		st.emit("response.output_text.done", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "content_index": 0, "text": full,
		})
		st.emit("response.content_part.done", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "content_index": 0, "part": part,
		})
		item := map[string]any{
			"id": st.curItemID, "type": "message", "status": "completed",
			"role": "assistant", "content": []any{part},
		}
		st.emit("response.output_item.done", map[string]any{"output_index": st.outIndex, "item": item})
		st.items = append(st.items, item)
	case "function_call":
		full := st.argsBuf.String()
		st.emit("response.function_call_arguments.done", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "arguments": full,
		})
		item := map[string]any{
			"id": st.curItemID, "type": "function_call", "call_id": st.fcCallID,
			"name": st.fcName, "arguments": full, "status": "completed",
		}
		st.emit("response.output_item.done", map[string]any{"output_index": st.outIndex, "item": item})
		st.items = append(st.items, item)
	}
	if st.curKind != "" {
		st.outIndex++
	}
	st.curKind = ""
}

func (st *respStreamState) openReasoning() {
	if st.curKind == "reasoning" {
		return
	}
	st.closeItem()
	st.curKind = "reasoning"
	st.curItemID = "rs_" + newUUIDShort()
	st.reasonBuf.Reset()
	st.emit("response.output_item.added", map[string]any{
		"output_index": st.outIndex,
		"item":         map[string]any{"id": st.curItemID, "type": "reasoning", "summary": []any{}},
	})
	st.emit("response.reasoning_summary_part.added", map[string]any{
		"item_id": st.curItemID, "output_index": st.outIndex, "summary_index": 0,
		"part": map[string]any{"type": "summary_text", "text": ""},
	})
}

func (st *respStreamState) openMessage() {
	if st.curKind == "message" {
		return
	}
	st.closeItem()
	st.curKind = "message"
	st.curItemID = "msg_" + newUUIDShort()
	st.textBuf.Reset()
	st.emit("response.output_item.added", map[string]any{
		"output_index": st.outIndex,
		"item": map[string]any{
			"id": st.curItemID, "type": "message", "status": "in_progress",
			"role": "assistant", "content": []any{},
		},
	})
	st.emit("response.content_part.added", map[string]any{
		"item_id": st.curItemID, "output_index": st.outIndex, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
	})
}

func (st *respStreamState) openFunctionCall(callID, name string) {
	st.closeItem()
	st.curKind = "function_call"
	st.curItemID = "fc_" + newUUIDShort()
	st.fcCallID, st.fcName = callID, name
	st.argsBuf.Reset()
	st.emit("response.output_item.added", map[string]any{
		"output_index": st.outIndex,
		"item": map[string]any{
			"id": st.curItemID, "type": "function_call", "call_id": callID,
			"name": name, "arguments": "", "status": "in_progress",
		},
	})
}

func (st *respStreamState) handleChunk(c *upChunk) {
	if len(c.Choices) == 0 {
		if c.Usage != nil {
			st.inTok = c.Usage.PromptTokens
			st.outTok = c.Usage.CompletionTokens
		}
		return
	}
	ch := c.Choices[0]
	d := ch.Delta
	if d.ReasoningContent != "" {
		st.openReasoning()
		st.reasonBuf.WriteString(d.ReasoningContent)
		st.emit("response.reasoning_summary_text.delta", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "summary_index": 0,
			"delta": d.ReasoningContent,
		})
	}
	if d.Content != "" {
		st.openMessage()
		st.textBuf.WriteString(d.Content)
		st.emit("response.output_text.delta", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "content_index": 0,
			"delta": d.Content,
		})
	}
	for _, tc := range d.ToolCalls {
		if tc.ID != "" || tc.Function.Name != "" {
			id, name := tc.ID, tc.Function.Name
			if id == "" {
				id = st.fcCallID
			}
			if name == "" {
				name = st.fcName
			}
			st.openFunctionCall(id, name)
		}
		if tc.Function.Arguments != "" {
			if st.curKind != "function_call" {
				st.openFunctionCall(st.fcCallID, st.fcName)
			}
			st.argsBuf.WriteString(tc.Function.Arguments)
			st.emit("response.function_call_arguments.delta", map[string]any{
				"item_id": st.curItemID, "output_index": st.outIndex,
				"delta": tc.Function.Arguments,
			})
		}
	}
	if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
		st.stopReason = *ch.FinishReason
		if c.Usage != nil {
			st.inTok = c.Usage.PromptTokens
			st.outTok = c.Usage.CompletionTokens
		}
	}
}

func (st *respStreamState) complete() {
	st.closeItem()
	status := "completed"
	var incomplete any
	if st.stopReason == "length" {
		status = "incomplete"
		incomplete = map[string]any{"reason": "max_output_tokens"}
	}
	resp := st.baseResponse(status)
	resp["output"] = st.items
	resp["incomplete_details"] = incomplete
	resp["usage"] = map[string]any{
		"input_tokens": st.inTok, "output_tokens": st.outTok,
		"total_tokens": st.inTok + st.outTok,
	}
	st.emit("response.completed", map[string]any{"response": resp})
}

func (st *respStreamState) fail(msg string) {
	resp := st.baseResponse("failed")
	resp["error"] = map[string]any{"code": "server_error", "message": msg}
	st.emit("response.failed", map[string]any{"response": resp})
}

func newUUIDShort() string {
	return strings.ReplaceAll(newUUID(), "-", "")[:24]
}

func (s *server) handleResponses(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		writeOAIError(w, http.StatusUnauthorized, "authentication_error", "invalid_api_key", "invalid or missing api key")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	var req respRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", "invalid JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		writeOAIError(w, 400, "invalid_request_error", "", "model is required")
		return
	}
	mc := s.models.resolve(req.Model)
	maxTok := req.MaxOutputTokens
	if maxTok == 0 {
		maxTok = 32000
	}
	params := map[string]any{"max_tokens": maxTok}
	if mc.MaxInputTokens > 0 {
		params["context_length"] = mc.MaxInputTokens
	}
	if req.Reasoning != nil {
		if e := normalizeEffort(req.Reasoning.Effort); e != "" {
			params["reasoning_effort"] = e
		}
	}
	if req.Temperature != nil {
		params["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		params["top_p"] = *req.TopP
	}
	if len(req.ToolChoice) > 0 {
		var tc any
		if json.Unmarshal(req.ToolChoice, &tc) == nil {
			params["tool_choice"] = tc
		}
	}
	system, upMsgs, err := respToUpstream(req.Instructions, req.Input)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	requestID := newUUID()
	body, err := remoteChatAskBody(system, upMsgs, respToolsToOAI(req.Tools), params, mc, s.sessionFor(req.Model), requestID)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	resp, err := s.doUpstream(r.Context(), body, mc)
	if err != nil {
		writeOAIError(w, 502, "api_error", "", "upstream request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		io.Copy(io.Discard, resp.Body)
		if rerr := s.auth.forceRefresh(r.Context()); rerr == nil {
			if resp2, err2 := s.doUpstream(r.Context(), body, mc); err2 == nil {
				defer resp2.Body.Close()
				resp = resp2
			}
		}
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		writeOAIError(w, resp.StatusCode, "api_error", "", fmt.Sprintf("upstream status %d: %s", resp.StatusCode, truncate(string(b), 300)))
		return
	}

	chunks, errc := upstreamChunks(r.Context(), resp.Body)
	if req.Stream {
		s.streamResponses(w, chunks, errc, &req, requestID)
	} else {
		s.collectResponses(w, chunks, errc, &req, requestID)
	}
}

func (s *server) streamResponses(w http.ResponseWriter, chunks <-chan *upChunk, errc <-chan error, req *respRequest, requestID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOAIError(w, 500, "api_error", "", "streaming unsupported")
		return
	}
	w.WriteHeader(200)
	st := &respStreamState{w: w, flusher: flusher, respID: "resp_" + newUUIDShort(), model: req.Model}
	created := st.baseResponse("in_progress")
	st.emit("response.created", map[string]any{"response": created})
	st.emit("response.in_progress", map[string]any{"response": created})
	failed := ""
	for c := range chunks {
		st.handleChunk(c)
	}
	select {
	case err := <-errc:
		if err != nil {
			failed = err.Error()
		}
	default:
	}
	if failed != "" {
		st.fail(failed)
		return
	}
	st.complete()
}

func (s *server) collectResponses(w http.ResponseWriter, chunks <-chan *upChunk, errc <-chan error, req *respRequest, requestID string) {
	var textBuf, reasonBuf strings.Builder
	type fc struct{ id, callID, name, args string }
	var fcs []fc
	cur := -1
	stopReason := "stop"
	inTok, outTok := 0, 0
	for c := range chunks {
		if c.Usage != nil {
			inTok, outTok = c.Usage.PromptTokens, c.Usage.CompletionTokens
		}
		if len(c.Choices) == 0 {
			continue
		}
		ch := c.Choices[0]
		d := ch.Delta
		reasonBuf.WriteString(d.ReasoningContent)
		textBuf.WriteString(d.Content)
		for _, tc := range d.ToolCalls {
			if tc.ID != "" || tc.Function.Name != "" {
				fcs = append(fcs, fc{})
				cur = len(fcs) - 1
				if tc.ID != "" {
					fcs[cur].callID = tc.ID
				}
				if tc.Function.Name != "" {
					fcs[cur].name = tc.Function.Name
				}
			}
			if tc.Function.Arguments != "" && cur >= 0 {
				fcs[cur].args += tc.Function.Arguments
			}
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
			stopReason = *ch.FinishReason
		}
	}
	failed := ""
	select {
	case err := <-errc:
		if err != nil {
			failed = err.Error()
		}
	default:
	}
	if failed != "" {
		writeOAIError(w, 502, "api_error", "", failed)
		return
	}
	var items []map[string]any
	if reasonBuf.Len() > 0 {
		items = append(items, map[string]any{
			"id": "rs_" + newUUIDShort(), "type": "reasoning",
			"summary": []any{map[string]any{"type": "summary_text", "text": reasonBuf.String()}},
		})
	}
	if textBuf.Len() > 0 {
		items = append(items, map[string]any{
			"id": "msg_" + newUUIDShort(), "type": "message", "status": "completed",
			"role": "assistant",
			"content": []any{map[string]any{
				"type": "output_text", "text": textBuf.String(), "annotations": []any{},
			}},
		})
	}
	for _, f := range fcs {
		items = append(items, map[string]any{
			"id": "fc_" + newUUIDShort(), "type": "function_call", "call_id": f.callID,
			"name": f.name, "arguments": f.args, "status": "completed",
		})
	}
	if items == nil {
		items = []map[string]any{}
	}
	status := "completed"
	var incomplete any
	if stopReason == "length" {
		status = "incomplete"
		incomplete = map[string]any{"reason": "max_output_tokens"}
	}
	out := map[string]any{
		"id": "resp_" + newUUIDShort(), "object": "response", "created_at": nowUnix(),
		"status": status, "model": req.Model, "output": items,
		"error": nil, "incomplete_details": incomplete,
		"metadata": map[string]any{}, "parallel_tool_calls": true,
		"usage": map[string]any{
			"input_tokens": inTok, "output_tokens": outTok, "total_tokens": inTok + outTok,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

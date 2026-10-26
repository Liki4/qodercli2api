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
	Model           string          `json:"model"`
	Instructions    string          `json:"instructions,omitempty"`
	Input           json.RawMessage `json:"input,omitempty"`
	Tools           []respTool      `json:"tools,omitempty"`
	ToolChoice      json.RawMessage `json:"tool_choice,omitempty"`
	MaxOutputTokens int             `json:"max_output_tokens,omitempty"`
	Stream          bool            `json:"stream,omitempty"`
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
	Format      *respToolFormat `json:"format,omitempty"`
}

type respInputItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments string          `json:"arguments,omitempty"`
	Input     *string         `json:"input,omitempty"`
	Output    *string         `json:"output,omitempty"`
	ID        string          `json:"id,omitempty"`
	Status    string          `json:"status,omitempty"`
}

type respContentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

func isCompactRespMessage(it respInputItem) bool {
	switch it.Role {
	case "user", "assistant", "system", "developer":
	default:
		return false
	}
	if raw := strings.TrimSpace(string(it.Content)); raw == "" || raw == "null" {
		return false
	}
	var text string
	if err := json.Unmarshal(it.Content, &text); err == nil {
		return true
	}
	var parts []struct {
		Type     string  `json:"type"`
		Text     *string `json:"text"`
		ImageURL *string `json:"image_url"`
	}
	if err := json.Unmarshal(it.Content, &parts); err != nil || len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		switch part.Type {
		case "input_text", "output_text", "text":
			if part.Text == nil {
				return false
			}
		case "input_image":
			if part.ImageURL == nil || strings.TrimSpace(*part.ImageURL) == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
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
		msgs = append(msgs, upMessage{Role: "user", Content: asString,
			Contents: []upPart{{Type: "text", Text: asString}}})
		ensureCacheMarker(msgs)
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
		case "":
			// Some Responses clients omit the optional message discriminator.
			// Only accept the documented compact role/content form.
			if !isCompactRespMessage(it) {
				flushAssistant()
				continue
			}
			fallthrough
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
			if it.Role == "user" {
				um.Contents = respPartsToUpstream(it.Content)
			} else if txt := respPartsText(it.Content); txt != "" {
				um.Contents = []upPart{{Type: "text", Text: txt}}
			}
			msgs = append(msgs, um)
		case "function_call", "custom_tool_call":
			arguments := it.Arguments
			if it.Type == "custom_tool_call" {
				if it.Input == nil {
					return "", nil, fmt.Errorf("custom_tool_call input must be a string")
				}
				arguments = encodeRespCustomInput(*it.Input)
			}
			if pendingAssistant == nil {
				pendingAssistant = &upMessage{Role: "assistant", Content: ""}
			}
			var tc upToolCall
			tc.ID = it.CallID
			tc.Type = "function"
			tc.Function.Name = it.Name
			tc.Function.Arguments = arguments
			pendingAssistant.ToolCalls = append(pendingAssistant.ToolCalls, tc)
		case "function_call_output", "custom_tool_call_output":
			output := ""
			if it.Output != nil {
				output = *it.Output
			} else if it.Type == "custom_tool_call_output" {
				return "", nil, fmt.Errorf("custom_tool_call_output output must be a string")
			}
			flushAssistant()
			msgs = append(msgs, upMessage{Role: "tool", ToolCallID: it.CallID, Content: output})
		case "reasoning", "item_reference":
			// not forwarded upstream
		default:
			flushAssistant()
		}
	}
	flushAssistant()
	ensureCacheMarker(msgs)
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

func respPartsToUpstream(raw json.RawMessage) []upPart {
	parts := parseRespParts(raw)
	out := make([]upPart, 0, len(parts))
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text":
			out = append(out, upPart{Type: "text", Text: p.Text})
		case "input_image":
			out = append(out, upPart{
				Type:     "image_url",
				ImageURL: &upImageURL{URL: p.ImageURL},
			})
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

// ---------- Responses API emission ----------

type respStreamState struct {
	w          http.ResponseWriter
	flusher    http.Flusher
	respID     string
	model      string
	seq        int
	outIndex   int
	curKind    string // "", "reasoning", "message", "pending_tool_call", "function_call", "custom_tool_call"
	curItemID  string
	toolKinds  respToolKinds
	call       *respToolCall
	failed     bool
	textBuf    strings.Builder
	reasonBuf  strings.Builder
	items      []map[string]any
	inTok      int
	outTok     int
	cacheRead  int
	cacheWrite int
	stopReason string
	bill       *upUsage
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
		"output":              []any{},
		"error":               nil,
		"incomplete_details":  nil,
		"instructions":        nil,
		"metadata":            map[string]any{},
		"parallel_tool_calls": true,
		"tools":               []any{},
		"tool_choice":         "auto",
		"store":               false,
	}
}

func (st *respStreamState) closeItem() bool {
	if st.failed {
		return false
	}
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
	case "pending_tool_call":
		st.fail(errRespToolCall.Error())
		return false
	case "function_call", "custom_tool_call":
		item, err := st.call.item(st.curItemID, st.toolKinds)
		if err != nil {
			st.fail(err.Error())
			return false
		}
		if st.curKind == "custom_tool_call" {
			// Buffer the transport JSON until validated. No escaped wrapper or
			// incomplete executable input is exposed through custom deltas.
			st.emit("response.custom_tool_call_input.delta", map[string]any{
				"item_id": st.curItemID, "output_index": st.outIndex, "delta": item["input"],
			})
			st.emit("response.custom_tool_call_input.done", map[string]any{
				"item_id": st.curItemID, "output_index": st.outIndex, "input": item["input"],
			})
		} else {
			st.emit("response.function_call_arguments.done", map[string]any{
				"item_id": st.curItemID, "output_index": st.outIndex, "arguments": item["arguments"],
			})
		}
		st.emit("response.output_item.done", map[string]any{"output_index": st.outIndex, "item": item})
		st.items = append(st.items, item)
		st.call = nil
	}
	if st.curKind != "" {
		st.outIndex++
	}
	st.curKind = ""
	return true
}

func (st *respStreamState) openReasoning() bool {
	if st.curKind == "reasoning" {
		return true
	}
	if !st.closeItem() {
		return false
	}
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
	return true
}

func (st *respStreamState) openMessage() bool {
	if st.curKind == "message" {
		return true
	}
	if !st.closeItem() {
		return false
	}
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
	return true
}

func (st *respStreamState) handleToolCall(callID, name, args string) {
	if st.call.startsNew(callID) && !st.closeItem() {
		return
	}
	if st.call == nil {
		if !st.closeItem() {
			return
		}
		st.curKind = "pending_tool_call"
		st.call = &respToolCall{}
	}
	if err := st.call.add(callID, name, args); err != nil {
		st.fail(err.Error())
		return
	}
	if st.curKind == "pending_tool_call" && st.call.ready() {
		st.curKind = "function_call"
		field := "arguments"
		if st.toolKinds[st.call.name] == "custom" {
			st.curKind, field = "custom_tool_call", "input"
		}
		st.curItemID = "fc_" + newUUIDShort()
		st.emit("response.output_item.added", map[string]any{
			"output_index": st.outIndex,
			"item": map[string]any{
				"id": st.curItemID, "type": st.curKind, "call_id": st.call.callID,
				"name": st.call.name, field: "", "status": "in_progress",
			},
		})
		// Include fragments that arrived before the ID/name, as well as any
		// arguments attached to the first complete header.
		args = st.call.args.String()
	}
	if st.curKind == "function_call" && args != "" {
		st.emit("response.function_call_arguments.delta", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "delta": args,
		})
	}
}

func (st *respStreamState) handleChunk(c *upChunk) {
	if st.failed {
		return
	}
	if c.Usage != nil {
		st.setUsage(c.Usage)
	}
	if len(c.Choices) == 0 {
		return
	}
	ch := c.Choices[0]
	d := ch.Delta
	if d.ReasoningContent != "" {
		if !st.openReasoning() {
			return
		}
		st.reasonBuf.WriteString(d.ReasoningContent)
		st.emit("response.reasoning_summary_text.delta", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "summary_index": 0,
			"delta": d.ReasoningContent,
		})
	}
	if d.Content != "" {
		if !st.openMessage() {
			return
		}
		st.textBuf.WriteString(d.Content)
		st.emit("response.output_text.delta", map[string]any{
			"item_id": st.curItemID, "output_index": st.outIndex, "content_index": 0,
			"delta": d.Content,
		})
	}
	for _, tc := range d.ToolCalls {
		st.handleToolCall(tc.ID, tc.Function.Name, tc.Function.Arguments)
		if st.failed {
			return
		}
	}
	if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
		st.stopReason = *ch.FinishReason
		if st.call != nil {
			st.closeItem()
		}
	}
}

func (st *respStreamState) setUsage(u *upUsage) {
	st.cacheRead = u.cachedTokens()
	st.cacheWrite = u.cacheWriteTokens()
	st.inTok = max(u.PromptTokens-st.cacheRead-st.cacheWrite, 0)
	st.outTok = u.CompletionTokens
	c := *u
	st.bill = &c
}

func (st *respStreamState) complete() {
	if !st.closeItem() {
		return
	}
	status := "completed"
	var incomplete any
	if st.stopReason == "length" {
		status = "incomplete"
		incomplete = map[string]any{"reason": "max_output_tokens"}
	}
	resp := st.baseResponse(status)
	resp["output"] = st.items
	resp["incomplete_details"] = incomplete
	usage := map[string]any{
		"input_tokens":         st.inTok,
		"input_tokens_details": map[string]int{"cached_tokens": st.cacheRead},
		"output_tokens":        st.outTok,
		"total_tokens":         st.inTok + st.cacheWrite + st.cacheRead + st.outTok,
	}
	for k, v := range st.bill.billingFields() {
		usage[k] = v
	}
	resp["usage"] = usage
	st.emit("response.completed", map[string]any{"response": resp})
}

func (st *respStreamState) fail(msg string) {
	if st.failed {
		return
	}
	st.failed = true
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
	tools, kinds, err := respToolsToOAI(req.Tools)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	choice, err := respToolChoiceToOAI(req.ToolChoice, kinds)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	if len(req.ToolChoice) > 0 {
		params["tool_choice"] = choice
	}
	system, upMsgs, err := respToUpstream(req.Instructions, req.Input)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	requestID := newUUID()
	body, err := remoteChatAskBody(system, upMsgs, tools, params, mc, s.sessionFor(req.Model), requestID)
	if err != nil {
		writeOAIError(w, 400, "invalid_request_error", "", err.Error())
		return
	}
	s.logf("req %s resp model=%s->%s stream=%v bytes=%d msgs=%d tools=%d", requestID[:8], req.Model, mc.Key, req.Stream, len(raw), len(upMsgs), len(req.Tools))
	resp, err := s.callUpstream(r.Context(), body, mc, requestID[:8])
	if err != nil {
		s.logUpstreamError(requestID[:8], err)
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
		s.streamResponses(w, chunks, errc, &req, requestID, kinds)
	} else {
		s.collectResponses(w, chunks, errc, &req, requestID, kinds)
	}
}

func (s *server) streamResponses(w http.ResponseWriter, chunks <-chan *upChunk, errc <-chan error, req *respRequest, requestID string, kinds respToolKinds) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeOAIError(w, 500, "api_error", "", "streaming unsupported")
		return
	}
	w.WriteHeader(200)
	st := &respStreamState{w: w, flusher: flusher, respID: "resp_" + newUUIDShort(), model: req.Model, toolKinds: kinds}
	created := st.baseResponse("in_progress")
	st.emit("response.created", map[string]any{"response": created})
	st.emit("response.in_progress", map[string]any{"response": created})
	failed := ""
	for c := range chunks {
		// A conversion failure stops emission, not consumption: upstreamChunks
		// must be drained so its producer cannot remain blocked on the channel.
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
	s.logf("req %s usage input=%d cache_write=%d cache_read=%d output=%d%s", requestID[:8], st.inTok, st.cacheWrite, st.cacheRead, st.outTok, st.bill.billingLog())
}

func (s *server) collectResponses(w http.ResponseWriter, chunks <-chan *upChunk, errc <-chan error, req *respRequest, requestID string, kinds respToolKinds) {
	var textBuf, reasonBuf strings.Builder
	var calls []map[string]any
	var call *respToolCall
	failed := ""
	closeCall := func() {
		if call == nil || failed != "" {
			return
		}
		item, err := call.item("fc_"+newUUIDShort(), kinds)
		if err != nil {
			failed = err.Error()
			return
		}
		calls = append(calls, item)
		call = nil
	}
	stopReason := "stop"
	inTok, outTok, cacheRead, cacheWrite := 0, 0, 0, 0
	var bill *upUsage
	for c := range chunks {
		if failed != "" {
			continue // Drain the existing producer even after conversion fails.
		}
		if c.Usage != nil {
			cacheRead = c.Usage.cachedTokens()
			cacheWrite = c.Usage.cacheWriteTokens()
			inTok = max(c.Usage.PromptTokens-cacheRead-cacheWrite, 0)
			outTok = c.Usage.CompletionTokens
			bill = c.Usage
		}
		if len(c.Choices) == 0 {
			continue
		}
		ch := c.Choices[0]
		d := ch.Delta
		if d.ReasoningContent != "" || d.Content != "" {
			closeCall()
			if failed != "" {
				continue
			}
		}
		reasonBuf.WriteString(d.ReasoningContent)
		textBuf.WriteString(d.Content)
		for _, tc := range d.ToolCalls {
			if call.startsNew(tc.ID) {
				closeCall()
				if failed != "" {
					break
				}
			}
			if call == nil {
				call = &respToolCall{}
			}
			if err := call.add(tc.ID, tc.Function.Name, tc.Function.Arguments); err != nil {
				failed = err.Error()
				break
			}
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" && *ch.FinishReason != "null" {
			stopReason = *ch.FinishReason
			closeCall()
		}
	}
	closeCall()
	select {
	case err := <-errc:
		if err != nil && failed == "" {
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
	items = append(items, calls...)
	if items == nil {
		items = []map[string]any{}
	}
	status := "completed"
	var incomplete any
	if stopReason == "length" {
		status = "incomplete"
		incomplete = map[string]any{"reason": "max_output_tokens"}
	}
	usage := map[string]any{
		"input_tokens":         inTok,
		"input_tokens_details": map[string]int{"cached_tokens": cacheRead},
		"output_tokens":        outTok,
		"total_tokens":         inTok + cacheWrite + cacheRead + outTok,
	}
	for k, v := range bill.billingFields() {
		usage[k] = v
	}
	out := map[string]any{
		"id": "resp_" + newUUIDShort(), "object": "response", "created_at": nowUnix(),
		"status": status, "model": req.Model, "output": items,
		"error": nil, "incomplete_details": incomplete,
		"metadata": map[string]any{}, "parallel_tool_calls": true,
		"usage": usage,
	}
	s.logf("req %s usage input=%d cache_write=%d cache_read=%d output=%d%s", requestID[:8], inTok, cacheWrite, cacheRead, outTok, bill.billingLog())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

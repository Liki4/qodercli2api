package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ---------- Anthropic request types ----------

type anthropicRequest struct {
	Model         string          `json:"model"`
	Messages      []anthropicMsg  `json:"messages"`
	System        json.RawMessage `json:"system,omitempty"`
	MaxTokens     int             `json:"max_tokens"`
	Stream        bool            `json:"stream,omitempty"`
	Tools         []anthropicTool `json:"tools,omitempty"`
	ToolChoice    json.RawMessage `json:"tool_choice,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	Thinking      *anthropicThink `json:"thinking,omitempty"`
}

type anthropicThink struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens,omitempty"`
}

type anthropicMsg struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthropicBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	Source    *struct {
		Type      string `json:"type"`
		MediaType string `json:"media_type"`
		Data      string `json:"data"`
		URL       string `json:"url,omitempty"`
	} `json:"source,omitempty"`
	Thinking     string        `json:"thinking,omitempty"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ---------- upstream (OpenAI-ish) types ----------

type upMessage struct {
	Role       string       `json:"role"`
	Content    any          `json:"content,omitempty"`
	Contents   []upPart     `json:"contents,omitempty"`
	ToolCalls  []upToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
	Name       string       `json:"name,omitempty"`
}

type cacheControl struct {
	Type string `json:"type"`
}

// upPart mirrors the structured `contents` entries the official client sends
// alongside `content`. Prompt-cache markers live here.
type upPart struct {
	Type         string        `json:"type"`
	Text         string        `json:"text,omitempty"`
	ImageURL     *upImageURL   `json:"image_url,omitempty"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type upImageURL struct {
	URL string `json:"url"`
}

type upToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type upContentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL *struct {
		URL string `json:"url"`
	} `json:"image_url,omitempty"`
}

type modelConfig struct {
	Key            string  `json:"key"`
	Format         string  `json:"format"`
	Source         string  `json:"source"`
	Enable         bool    `json:"enable"`
	DisplayName    string  `json:"display_name,omitempty"`
	IsVL           bool    `json:"is_vl"`
	IsReasoning    bool    `json:"is_reasoning"`
	IsDefault      bool    `json:"is_default,omitempty"`
	PriceFactor    float64 `json:"price_factor,omitempty"`
	MaxInputTokens int     `json:"max_input_tokens,omitempty"`
	URL            string  `json:"url,omitempty"`
}

// ---------- conversion ----------

func blocksFromRaw(raw json.RawMessage) ([]anthropicBlock, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []anthropicBlock{{Type: "text", Text: s}}, nil
	}
	var blocks []anthropicBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

func systemToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	blocks, err := blocksFromRaw(raw)
	if err != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

func messagesToUpstream(msgs []anthropicMsg) ([]upMessage, error) {
	var out []upMessage
	for _, m := range msgs {
		blocks, err := blocksFromRaw(m.Content)
		if err != nil {
			return nil, fmt.Errorf("parse %s message content: %w", m.Role, err)
		}
		if m.Role == "user" {
			var toolResults []anthropicBlock
			var normal []anthropicBlock
			for _, b := range blocks {
				if b.Type == "tool_result" {
					toolResults = append(toolResults, b)
				} else {
					normal = append(normal, b)
				}
			}
			if len(normal) > 0 || len(toolResults) == 0 {
				content, parts := userContentFromBlocks(normal)
				out = append(out, upMessage{Role: "user", Content: content, Contents: parts})
			}
			for _, tr := range toolResults {
				out = append(out, upMessage{
					Role:       "tool",
					ToolCallID: tr.ToolUseID,
					Content:    toolResultText(tr.Content),
				})
			}
			continue
		}
		// assistant
		var textParts []string
		var parts []upPart
		var calls []upToolCall
		for _, b := range blocks {
			switch b.Type {
			case "text":
				textParts = append(textParts, b.Text)
				parts = append(parts, upPart{Type: "text", Text: b.Text, CacheControl: b.CacheControl})
			case "tool_use":
				var tc upToolCall
				tc.ID = b.ID
				tc.Type = "function"
				tc.Function.Name = b.Name
				if len(b.Input) > 0 {
					tc.Function.Arguments = string(b.Input)
				} else {
					tc.Function.Arguments = "{}"
				}
				calls = append(calls, tc)
			}
		}
		um := upMessage{Role: "assistant", Contents: parts}
		joined := strings.Join(textParts, "")
		if joined != "" {
			um.Content = joined
		} else if len(calls) > 0 {
			um.Content = ""
		}
		if len(calls) > 0 {
			um.ToolCalls = calls
		}
		out = append(out, um)
	}
	return out, nil
}

// userContentFromBlocks returns the flat `content` value plus the structured
// `contents` parts. The official client sends both; cache markers ride on the
// structured parts.
func userContentFromBlocks(blocks []anthropicBlock) (any, []upPart) {
	var parts []upPart
	var texts []string
	hasImage := false
	for _, b := range blocks {
		switch b.Type {
		case "text":
			parts = append(parts, upPart{Type: "text", Text: b.Text, CacheControl: b.CacheControl})
			texts = append(texts, b.Text)
		case "image":
			if b.Source == nil {
				continue
			}
			url := b.Source.URL
			if b.Source.Type == "base64" {
				url = "data:" + b.Source.MediaType + ";base64," + b.Source.Data
			}
			parts = append(parts, upPart{Type: "image_url", ImageURL: &upImageURL{URL: url}, CacheControl: b.CacheControl})
			hasImage = true
		}
	}
	if hasImage {
		return parts, parts
	}
	return strings.Join(texts, "\n"), parts
}

// cacheableParts are the part types a prompt-cache marker may attach to,
// mirroring the official client's exclusion set.
func cacheablePart(t string) bool {
	return t == "text" || t == "image_url"
}

// ensureCacheMarker guarantees exactly one ephemeral marker at the end of the
// prompt when the client did not supply one (e.g. OpenAI/Codex clients), so the
// whole prefix becomes cacheable. Mirrors the official placement rule: last
// message, last cacheable part.
func ensureCacheMarker(msgs []upMessage) {
	for _, m := range msgs {
		for _, p := range m.Contents {
			if p.CacheControl != nil {
				return
			}
		}
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "tool" {
			continue
		}
		for j := len(msgs[i].Contents) - 1; j >= 0; j-- {
			if cacheablePart(msgs[i].Contents[j].Type) {
				msgs[i].Contents[j].CacheControl = &cacheControl{Type: "ephemeral"}
				return
			}
		}
	}
}

func toolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	blocks, err := blocksFromRaw(raw)
	if err != nil {
		return string(raw)
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			parts = append(parts, b.Text)
		} else if b.Type == "image" && b.Source != nil && b.Source.Type == "base64" {
			if _, err := base64.StdEncoding.DecodeString(b.Source.Data); err == nil {
				parts = append(parts, "[image omitted]")
			}
		}
	}
	return strings.Join(parts, "\n")
}

func toolsToUpstream(tools []anthropicTool) []map[string]any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		schema := json.RawMessage(`{"type":"object"}`)
		if len(t.InputSchema) > 0 {
			schema = t.InputSchema
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  schema,
			},
		})
	}
	return out
}

// budgetToEffort mirrors the CLI's CHL() mapping.
func budgetToEffort(budget int) string {
	switch {
	case budget <= 0:
		return "none"
	case budget <= 1024:
		return "low"
	case budget <= 8192:
		return "medium"
	case budget <= 24576:
		return "high"
	case budget <= 49152:
		return "xhigh"
	default:
		return "max"
	}
}

func toolChoiceToUpstream(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var tc struct {
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	}
	if json.Unmarshal(raw, &tc) != nil {
		return nil
	}
	switch tc.Type {
	case "auto":
		return "auto"
	case "any":
		return "required"
	case "none":
		return "none"
	case "tool":
		return map[string]any{"type": "function", "function": map[string]any{"name": tc.Name}}
	}
	return nil
}

// buildUpstreamBody constructs the RemoteChatAsk body.
func buildUpstreamBody(req *anthropicRequest, mc *modelConfig, sessionID, requestID string) ([]byte, error) {
	msgs, err := messagesToUpstream(req.Messages)
	if err != nil {
		return nil, err
	}
	ensureCacheMarker(msgs)
	params := map[string]any{"max_tokens": req.MaxTokens}
	if mc.MaxInputTokens > 0 {
		params["context_length"] = mc.MaxInputTokens
	}
	if req.Thinking != nil {
		switch req.Thinking.Type {
		case "enabled":
			params["reasoning_effort"] = budgetToEffort(req.Thinking.BudgetTokens)
		case "disabled":
			params["reasoning_effort"] = "none"
		default:
			// adaptive 等类型：不下发 reasoning_effort，由上游自行决定
		}
	}
	if tc := toolChoiceToUpstream(req.ToolChoice); tc != nil {
		params["tool_choice"] = tc
	}
	if req.Temperature != nil {
		params["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		params["top_p"] = *req.TopP
	}
	if len(req.StopSequences) > 0 {
		params["stop"] = req.StopSequences
	}
	return remoteChatAskBody(systemToString(req.System), msgs, toolsToUpstream(req.Tools), params, mc, sessionID, requestID)
}

// ---------- upstream SSE chunk types ----------

type sseEnvelope struct {
	Headers         map[string][]string `json:"headers"`
	Body            string              `json:"body"`
	StatusCodeValue int                 `json:"statusCodeValue"`
	StatusCode      string              `json:"statusCode"`
}

type upUsage struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	TotalTokens         int `json:"total_tokens"`
	PromptTokensDetails *struct {
		CachedTokens    int `json:"cached_tokens"`
		CacheableTokens int `json:"cacheable_tokens"`
	} `json:"prompt_tokens_details,omitempty"`
}

// cachedTokens reports how many prompt tokens the upstream served from cache.
func (u *upUsage) cachedTokens() int {
	if u == nil || u.PromptTokensDetails == nil {
		return 0
	}
	return u.PromptTokensDetails.CachedTokens
}

type upChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role             string `json:"role,omitempty"`
			Content          string `json:"content,omitempty"`
			ReasoningContent string `json:"reasoning_content,omitempty"`
			ToolCalls        []struct {
				ID       string `json:"id,omitempty"`
				Index    int    `json:"index"`
				Type     string `json:"type,omitempty"`
				Function struct {
					Name      string `json:"name,omitempty"`
					Arguments string `json:"arguments,omitempty"`
				} `json:"function"`
			} `json:"tool_calls,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *upUsage `json:"usage,omitempty"`
	Error *struct {
		Code    string `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	} `json:"error,omitempty"`
}

// ---------- Anthropic response (non-stream) types ----------

type anthropicResponse struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"`
	Role       string           `json:"role"`
	Content    []map[string]any `json:"content"`
	Model      string           `json:"model"`
	StopReason string           `json:"stop_reason"`
	Usage      map[string]int   `json:"usage"`
}

func mapStopReason(fr string) string {
	switch fr {
	case "stop":
		return "end_turn"
	case "tool_calls":
		return "tool_use"
	case "length":
		return "max_tokens"
	case "content_filter":
		return "refusal"
	}
	if fr == "" {
		return "end_turn"
	}
	return fr
}

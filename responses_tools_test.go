package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const respFreeformDescription = "The `apply_patch` tool can be used to edit files. This is a FREEFORM tool, so do not wrap the patch in JSON."
const respSyntheticGrammar = "start: \"BEGIN\" NEWLINE payload \"END\" NEWLINE\npayload: /[a-z\\n]+/\n%import common.NEWLINE"

func respTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func respTestChunk(t *testing.T, delta map[string]any, finish string, usage *upUsage) *upChunk {
	t.Helper()
	var c upChunk
	b := respTestJSON(t, map[string]any{
		"choices": []any{map[string]any{"delta": delta, "finish_reason": finish}}, "usage": usage,
	})
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func respTestCall(t *testing.T, id, name, args string) *upChunk {
	t.Helper()
	return respTestChunk(t, map[string]any{"tool_calls": []any{map[string]any{
		"index": 0, "id": id, "type": "function",
		"function": map[string]any{"name": name, "arguments": args},
	}}}, "", nil)
}

// The recorder sees the actual remoteChatAskBody before the fake protocol
// substitutes a synthetic transport body. Nothing authenticates or infers live.
func respTestServer(t *testing.T, turns ...[]*upChunk) (*server, *retryRecordingProtocolContext, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	payloads := make([]string, len(turns))
	for i, turn := range turns {
		var payload strings.Builder
		for _, chunk := range turn {
			envelope := sseEnvelope{StatusCodeValue: 200, Body: string(respTestJSON(t, chunk))}
			fmt.Fprintf(&payload, "event: message\ndata: %s\n\n", respTestJSON(t, envelope))
		}
		payloads[i] = payload.String()
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		if i >= len(payloads) {
			i = len(payloads) - 1
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if i >= 0 {
			fmt.Fprint(w, payloads[i])
		}
		fmt.Fprint(w, "event: finish\ndata: {}\n\n")
	}))
	t.Cleanup(upstream.Close)
	sequence := &sequenceProtocolContext{prepared: []*preparedRequest{{
		URL: upstream.URL, Header: http.Header{}, Body: []byte("synthetic transport body"),
	}}}
	recorder := &retryRecordingProtocolContext{inner: sequence}
	s := &server{
		auth: testAuthManager(recorder, upstream.URL), httpc: upstream.Client(),
		models: newModelResolver(resolverTestCatalog(), nil, "", ""), logf: func(string, ...any) {},
	}
	return s, recorder, &calls
}

func respTestRequest(t *testing.T, s *server, stream bool, tools any, input any, choice any) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"model": "auto", "stream": stream, "input": input, "tools": tools}
	if choice != nil {
		body["tool_choice"] = choice
	}
	rr := httptest.NewRecorder()
	s.handleResponses(rr, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(respTestJSON(t, body)))))
	return rr
}

func respTestEvents(t *testing.T, rr *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("stream status = %d, body = %s", rr.Code, rr.Body)
	}
	var events []map[string]any
	for _, frame := range strings.Split(rr.Body.String(), "\n\n") {
		if frame == "" {
			continue
		}
		lines := strings.Split(frame, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
			t.Fatalf("invalid SSE frame %q", frame)
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		if event["type"] != strings.TrimPrefix(lines[0], "event: ") || event["sequence_number"] != float64(len(events)+1) {
			t.Fatalf("event type/sequence mismatch: %#v", event)
		}
		events = append(events, event)
	}
	return events
}

func respTestResponse(t *testing.T, rr *httptest.ResponseRecorder, stream bool) map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body)
	}
	if stream {
		events := respTestEvents(t, rr)
		if len(events) == 0 || events[len(events)-1]["type"] != "response.completed" {
			t.Fatalf("missing completed response: %s", rr.Body)
		}
		for _, event := range events {
			if !protocolHarnessResponsesStreamFrameValid(event["type"].(string), respTestJSON(t, event)) {
				t.Fatalf("successful stream event rejected by protocol policy: %v", event["type"])
			}
		}
		return events[len(events)-1]["response"].(map[string]any)
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func respTestCapturedBody(t *testing.T, recorder *retryRecordingProtocolContext, index int) map[string]any {
	t.Helper()
	_, inputs := recorder.snapshot()
	if index >= len(inputs) {
		t.Fatalf("captured %d upstream requests, need index %d", len(inputs), index)
	}
	var body map[string]any
	if err := json.Unmarshal(inputs[index].Body, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func respTestCustomTools(name string) []map[string]any {
	return []map[string]any{{"type": "custom", "name": name}}
}

func TestHandleResponsesCustomToolDefinitionsAndChoice(t *testing.T) {
	tools := []map[string]any{
		{"type": "function", "name": "shell_command", "description": "Run a shell command", "parameters": map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}}},
		{"type": "function", "name": "read_file", "description": "Read a file"},
		{"type": "custom", "name": "apply_patch", "description": respFreeformDescription, "format": map[string]any{"type": "grammar", "syntax": "lark", "definition": respSyntheticGrammar}},
		{"type": "custom", "name": "send_raw_text", "description": "Send literal text", "format": map[string]any{"type": "text"}},
		{"type": "web_search"},
	}
	s, recorder, _ := respTestServer(t)
	rr := respTestRequest(t, s, false, tools, "hello", map[string]any{"type": "custom", "name": "apply_patch"})
	respTestResponse(t, rr, false)
	body := respTestCapturedBody(t, recorder, 0)
	converted := body["tools"].([]any)
	if len(converted) != 4 {
		t.Fatalf("converted %d tools, want both functions and both custom tools (4)", len(converted))
	}
	for i, raw := range converted {
		tool := raw.(map[string]any)
		fn := tool["function"].(map[string]any)
		if tool["type"] != "function" || fn["name"] != tools[i]["name"] {
			t.Fatalf("converted tool %d = %#v", i, tool)
		}
		params := fn["parameters"].(map[string]any)
		if i < 2 {
			want := tools[i]["parameters"]
			if want == nil {
				want = map[string]any{"type": "object"}
			}
			if !reflect.DeepEqual(params, want) || fn["description"] != tools[i]["description"] {
				t.Errorf("ordinary function changed: %#v", fn)
			}
			continue
		}
		props := params["properties"].(map[string]any)
		input := props["input"].(map[string]any)
		if params["type"] != "object" || params["additionalProperties"] != false || !reflect.DeepEqual(params["required"], []any{"input"}) || len(props) != 1 || input["type"] != "string" {
			t.Fatalf("custom input schema = %#v", params)
		}
		transport := fn["description"].(string)
		if !strings.Contains(transport, "JSON") || !strings.Contains(transport, "input") || !strings.Contains(transport, "decoded") {
			t.Errorf("description does not distinguish JSON transport and decoded raw input: %q", transport)
		}
		guidance := input["description"].(string)
		if !strings.Contains(guidance, tools[i]["description"].(string)) {
			t.Errorf("original custom description lost: %q", guidance)
		}
		if i == 2 && (!strings.Contains(guidance, respSyntheticGrammar) || !strings.Contains(guidance, "lark")) {
			t.Errorf("grammar guidance lost: %q", guidance)
		}
	}
	wantChoice := map[string]any{"type": "function", "function": map[string]any{"name": "apply_patch"}}
	if got := body["parameters"].(map[string]any)["tool_choice"]; !reflect.DeepEqual(got, wantChoice) {
		t.Errorf("tool_choice = %#v, want %#v", got, wantChoice)
	}
}

func TestRespToUpstreamCustomHistory(t *testing.T) {
	raw := " \tBEGIN\r\n+\"quoted\" \\ slash/ 中文 😀 literal\\n\nEND\n "
	input := []map[string]any{
		{"role": "user", "content": "edit"},
		{"type": "function_call", "call_id": "shell", "name": "shell_command", "arguments": `{"command":"pwd"}`},
		{"type": "reasoning"},
		{"type": "custom_tool_call", "call_id": "patch", "name": "apply_patch", "input": raw},
		{"type": "custom_tool_call", "call_id": "empty", "name": "send_raw_text", "input": ""},
		{"type": "function_call_output", "call_id": "shell", "output": "directory"},
		{"type": "custom_tool_call_output", "call_id": "patch", "output": "edited"},
		{"type": "custom_tool_call_output", "call_id": "empty", "output": ""},
		{"role": "assistant", "content": "done"},
	}
	_, msgs, err := respToUpstream("", respTestJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 6 {
		t.Fatalf("custom history missing: messages=%d, want 6", len(msgs))
	}
	if len(msgs[1].ToolCalls) != 3 {
		t.Fatalf("custom history grouping changed: calls=%d, want 3", len(msgs[1].ToolCalls))
	}
	calls := msgs[1].ToolCalls
	if msgs[1].Role != "assistant" || calls[0].Function.Arguments != `{"command":"pwd"}` {
		t.Fatalf("ordinary function history changed: %#v", msgs[1])
	}
	for i, want := range []string{raw, ""} {
		call := calls[i+1]
		var wrapper map[string]string
		if err := json.Unmarshal([]byte(call.Function.Arguments), &wrapper); err != nil || len(wrapper) != 1 || wrapper["input"] != want || call.ID != input[i+3]["call_id"] || call.Function.Name != input[i+3]["name"] || call.Type != "function" {
			t.Fatalf("custom history not losslessly wrapped: %#v (%v)", call, err)
		}
	}
	for i, want := range []string{"directory", "edited", ""} {
		if msgs[i+2].Role != "tool" || msgs[i+2].Content != want || msgs[i+2].ToolCallID != input[i+5]["call_id"] {
			t.Errorf("tool result %d = %#v", i, msgs[i+2])
		}
	}
	if msgs[0].Contents[0].CacheControl != nil || msgs[5].Content != "done" || msgs[5].Contents[0].CacheControl == nil || msgs[5].Contents[0].CacheControl.Type != "ephemeral" {
		t.Fatalf("cache marker/content order changed: %#v", msgs)
	}
}

func TestHandleResponsesRejectsInvalidCustomRequestsBeforeUpstream(t *testing.T) {
	cases := []struct {
		name   string
		tools  any
		input  any
		choice any
	}{
		{name: "empty name", tools: respTestCustomTools("")},
		{name: "blank name", tools: respTestCustomTools(" \t")},
		{name: "duplicate custom", tools: []map[string]any{{"type": "custom", "name": "raw"}, {"type": "custom", "name": "raw"}}},
		{name: "custom function collision", tools: []map[string]any{{"type": "custom", "name": "raw"}, {"type": "function", "name": "raw"}}},
		{name: "function custom collision", tools: []map[string]any{{"type": "function", "name": "raw"}, {"type": "custom", "name": "raw"}}},
		{name: "unsupported format", tools: []map[string]any{{"type": "custom", "name": "raw", "format": map[string]any{"type": "json"}}}},
		{name: "empty format", tools: []map[string]any{{"type": "custom", "name": "raw", "format": map[string]any{}}}},
		{name: "grammar missing definition", tools: []map[string]any{{"type": "custom", "name": "raw", "format": map[string]any{"type": "grammar", "syntax": "lark"}}}},
		{name: "grammar blank definition", tools: []map[string]any{{"type": "custom", "name": "raw", "format": map[string]any{"type": "grammar", "syntax": "regex", "definition": " \n"}}}},
		{name: "grammar unsupported syntax", tools: []map[string]any{{"type": "custom", "name": "raw", "format": map[string]any{"type": "grammar", "syntax": "other", "definition": "abc"}}}},
		{name: "missing custom input", input: []map[string]any{{"type": "custom_tool_call", "call_id": "raw", "name": "raw"}}},
		{name: "null custom input", input: []map[string]any{{"type": "custom_tool_call", "call_id": "raw", "name": "raw", "input": nil}}},
		{name: "nonstring custom input", input: []map[string]any{{"type": "custom_tool_call", "call_id": "raw", "name": "raw", "input": 1}}},
		{name: "array custom output", input: []map[string]any{{"type": "custom_tool_call_output", "call_id": "raw", "output": []any{map[string]any{"type": "input_text", "text": "no"}}}}},
		{name: "unknown custom choice", tools: respTestCustomTools("raw"), choice: map[string]any{"type": "custom", "name": "other"}},
		{name: "missing custom choice name", tools: respTestCustomTools("raw"), choice: map[string]any{"type": "custom"}},
		{name: "custom choice targets function", tools: []map[string]any{{"type": "function", "name": "raw"}}, choice: map[string]any{"type": "custom", "name": "raw"}},
	}
	for _, tc := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				s, recorder, calls := respTestServer(t)
				input := tc.input
				if input == nil {
					input = "hello"
				}
				rr := respTestRequest(t, s, stream, tc.tools, input, tc.choice)
				if rr.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", rr.Code)
				}
				prepared, _ := recorder.snapshot()
				if prepared != 0 || calls.Load() != 0 {
					t.Errorf("invalid request reached upstream: preparations=%d calls=%d", prepared, calls.Load())
				}
			})
		}
	}
}

func TestHandleResponsesCustomOutputRequiresString(t *testing.T) {
	cases := []struct {
		name    string
		present bool
		output  any
	}{
		{name: "missing"},
		{name: "null", present: true},
		{name: "number", present: true, output: 1},
		{name: "boolean", present: true, output: false},
		{name: "array", present: true, output: []any{"synthetic"}},
		{name: "object", present: true, output: map[string]any{"text": "synthetic"}},
	}
	for _, tc := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				item := map[string]any{"type": "custom_tool_call_output", "call_id": "call"}
				if tc.present {
					item["output"] = tc.output
				}
				s, recorder, calls := respTestServer(t)
				rr := respTestRequest(t, s, stream, nil, []any{item}, nil)
				if rr.Code != http.StatusBadRequest {
					t.Errorf("nonstring custom output status = %d, want 400", rr.Code)
				}
				prepared, _ := recorder.snapshot()
				if prepared != 0 || calls.Load() != 0 {
					t.Errorf("invalid custom output reached upstream: preparations=%d calls=%d", prepared, calls.Load())
				}
			})
		}
	}
}

func TestHandleResponsesToolOutputStringCompatibility(t *testing.T) {
	cases := []struct {
		name, kind string
		present    bool
		output     any
		want       string
	}{
		{name: "custom empty", kind: "custom_tool_call_output", present: true, output: ""},
		{name: "custom text", kind: "custom_tool_call_output", present: true, output: "synthetic result", want: "synthetic result"},
		{name: "function missing", kind: "function_call_output"},
		{name: "function null", kind: "function_call_output", present: true},
		{name: "function empty", kind: "function_call_output", present: true, output: ""},
		{name: "function text", kind: "function_call_output", present: true, output: "synthetic result", want: "synthetic result"},
	}
	for _, tc := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				item := map[string]any{"type": tc.kind, "call_id": "call"}
				if tc.present {
					item["output"] = tc.output
				}
				s, recorder, _ := respTestServer(t)
				rr := respTestRequest(t, s, stream, nil, []any{item}, nil)
				respTestResponse(t, rr, stream)
				body := respTestCapturedBody(t, recorder, 0)
				messages := body["messages"].([]any)
				if len(messages) != 1 {
					t.Fatalf("tool output history has %d messages, want 1", len(messages))
				}
				message := messages[0].(map[string]any)
				if message["role"] != "tool" || message["tool_call_id"] != "call" || message["content"] != tc.want {
					t.Fatalf("tool output compatibility changed: %#v", message)
				}
			})
		}
	}
}

func TestHandleResponsesCustomFormatsAndToolChoiceCompatibility(t *testing.T) {
	for _, format := range []any{nil, map[string]any{"type": "text"}, map[string]any{"type": "grammar", "syntax": "regex", "definition": "^synthetic$"}} {
		for _, choice := range []any{nil, "auto", "none", "required", map[string]any{"type": "function", "name": "raw"}, map[string]any{"type": "function", "function": map[string]any{"name": "raw"}}, map[string]any{"type": "custom", "name": "raw"}} {
			t.Run(fmt.Sprintf("format=%v/choice=%v", format, choice), func(t *testing.T) {
				tool := map[string]any{"type": "custom", "name": "raw"}
				if format != nil {
					tool["format"] = format
				}
				s, recorder, _ := respTestServer(t)
				rr := respTestRequest(t, s, false, []any{tool}, "hello", choice)
				respTestResponse(t, rr, false)
				body := respTestCapturedBody(t, recorder, 0)
				if len(body["tools"].([]any)) != 1 {
					t.Fatal("custom tool was dropped")
				}
				want := choice
				if _, ok := choice.(map[string]any); ok {
					want = map[string]any{"type": "function", "function": map[string]any{"name": "raw"}}
				}
				if got := body["parameters"].(map[string]any)["tool_choice"]; !reflect.DeepEqual(got, want) {
					t.Errorf("tool choice = %#v, want %#v", got, want)
				}
			})
		}
	}
}

func respTestAssertCustomEvents(t *testing.T, events []map[string]any, item map[string]any, index int) {
	t.Helper()
	id, raw := item["id"], item["input"]
	added, done, itemDone, deltas := 0, 0, 0, 0
	var combined strings.Builder
	for _, event := range events {
		kind := event["type"].(string)
		if event["item_id"] == id {
			if event["output_index"] != float64(index) {
				t.Errorf("unstable output index: %#v", event)
			}
			switch kind {
			case "response.custom_tool_call_input.delta":
				deltas++
				combined.WriteString(event["delta"].(string))
			case "response.custom_tool_call_input.done":
				done++
				if event["input"] != raw {
					t.Errorf("done input differs: %#v", event)
				}
			case "response.function_call_arguments.delta", "response.function_call_arguments.done":
				t.Error("custom call leaked function argument events")
			}
		}
		if got, ok := event["item"].(map[string]any); ok && got["id"] == id {
			if event["output_index"] != float64(index) || got["call_id"] != item["call_id"] || got["name"] != item["name"] || got["type"] != "custom_tool_call" {
				t.Errorf("unstable item metadata: %#v", event)
			}
			if kind == "response.output_item.added" {
				added++
				if got["input"] != "" {
					t.Error("custom added item must have empty input")
				}
			}
			if kind == "response.output_item.done" {
				itemDone++
				if !reflect.DeepEqual(got, item) {
					t.Errorf("done item differs from completed output: %#v / %#v", got, item)
				}
			}
		}
	}
	if added != 1 || done != 1 || itemDone != 1 || deltas != 1 || combined.String() != raw {
		t.Fatalf("custom events mismatch: added=%d delta=%d done=%d itemDone=%d inputEqual=%t", added, deltas, done, itemDone, combined.String() == raw)
	}
}

func TestHandleResponsesMixedCustomCalls(t *testing.T) {
	raw := " \tBEGIN\r\n+\"quote\"/\\ 中文 😀 literal\\n\nEND\n "
	wrapped := string(respTestJSON(t, map[string]string{"input": raw}))
	credits, original, billable := 1.25, 2.5, true
	usage := &upUsage{PromptTokens: 20, CompletionTokens: 7, Credits: &credits, OriginalCredits: &original, Billable: &billable}
	if err := json.Unmarshal([]byte(`{"cached_tokens":4,"cacheable_tokens":3}`), &usage.PromptTokensDetails); err != nil {
		t.Fatal(err)
	}
	chunks := []*upChunk{
		respTestChunk(t, map[string]any{"reasoning_content": "thinking"}, "", nil),
		respTestChunk(t, map[string]any{"content": "working"}, "", nil),
		respTestCall(t, "shell", "shell_command", `{"command":`),
		respTestCall(t, "shell", "shell_command", `"pwd"}`),
		respTestCall(t, "patch", "", ""),
		respTestCall(t, "patch", "apply_patch", wrapped),
		respTestCall(t, "raw", "send_raw_text", ""),
	}
	// Split every byte, including JSON escapes and a UTF-16 surrogate pair.
	for _, c := range []byte(`{"input":"  {\"x\":\"\\n\"}\r\n\t\uD83D\uDE00  "}`) {
		chunks = append(chunks, respTestCall(t, "", "", string(c)))
	}
	chunks = append(chunks, respTestChunk(t, nil, "tool_calls", usage))
	tools := []map[string]any{{"type": "function", "name": "shell_command"}, {"type": "custom", "name": "apply_patch"}, {"type": "custom", "name": "send_raw_text"}}
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			s, _, _ := respTestServer(t, chunks)
			rr := respTestRequest(t, s, stream, tools, "hello", nil)
			response := respTestResponse(t, rr, stream)
			items := response["output"].([]any)
			if len(items) != 5 {
				t.Fatalf("output count = %d, want reasoning/text/function/two custom calls: %#v", len(items), items)
			}
			if items[0].(map[string]any)["type"] != "reasoning" || items[1].(map[string]any)["type"] != "message" {
				t.Fatalf("reasoning/text lost: %#v", items[:2])
			}
			function := items[2].(map[string]any)
			if function["type"] != "function_call" || function["call_id"] != "shell" || function["arguments"] != `{"command":"pwd"}` {
				t.Errorf("ordinary call metadata/args changed: %#v", function)
			}
			for i, want := range []string{raw, "  {\"x\":\"\\n\"}\r\n\t😀  "} {
				item := items[i+3].(map[string]any)
				if item["type"] != "custom_tool_call" || item["input"] != want || item["name"] != tools[i+1]["name"] || item["call_id"] != []string{"patch", "raw"}[i] || item["status"] != "completed" {
					t.Fatalf("custom call %d not lossless: %#v", i, item)
				}
				if _, ok := item["arguments"]; ok {
					t.Error("custom call contains arguments envelope")
				}
				if stream {
					respTestAssertCustomEvents(t, respTestEvents(t, rr), item, i+3)
				}
			}
			gotUsage := response["usage"].(map[string]any)
			if gotUsage["input_tokens"] != float64(13) || gotUsage["output_tokens"] != float64(7) || gotUsage["total_tokens"] != float64(27) || gotUsage["credits"] != credits || gotUsage["original_credits"] != original || gotUsage["billable"] != billable {
				t.Errorf("usage/billing changed: %#v", gotUsage)
			}
		})
	}
}

func TestHandleResponsesCustomDelayedHeaders(t *testing.T) {
	cases := map[string][]*upChunk{
		"id then name":       {respTestCall(t, "call", "", `{"input":`), respTestCall(t, "", "raw", `"value"}`)},
		"name then id":       {respTestCall(t, "", "raw", `{"input":`), respTestCall(t, "call", "", `"value"}`)},
		"args before header": {respTestCall(t, "", "", `{"input":`), respTestCall(t, "call", "", `"value"}`), respTestCall(t, "", "raw", "")},
		"repeated metadata":  {respTestCall(t, "call", "raw", `{"input":`), respTestCall(t, "call", "raw", `"value"}`), respTestCall(t, "call", "raw", "")},
	}
	for name, chunks := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", name, stream), func(t *testing.T) {
				s, _, _ := respTestServer(t, chunks)
				rr := respTestRequest(t, s, stream, respTestCustomTools("raw"), "hello", nil)
				response := respTestResponse(t, rr, stream)
				items := response["output"].([]any)
				if len(items) != 1 {
					t.Fatalf("got %d calls, want one", len(items))
				}
				item := items[0].(map[string]any)
				if item["type"] != "custom_tool_call" || item["call_id"] != "call" || item["name"] != "raw" || item["input"] != "value" {
					t.Fatalf("pending header/arguments not preserved: %#v", item)
				}
				if stream {
					respTestAssertCustomEvents(t, respTestEvents(t, rr), item, 0)
				}
			})
		}
	}
}

func TestHandleResponsesCustomWrapperFailures(t *testing.T) {
	bad := []string{
		``, `SYNTHETIC_SECRET`, `{}`, `null`, `[]`, `"SYNTHETIC_SECRET"`,
		`{"input":null}`, `{"input":1}`, `{"input":false}`, `{"input":[]}`, `{"input":{}}`,
		`{"input":"SYNTHETIC_SECRET","extra":1}`, `{"input":"SYNTHETIC_SECRET","input":"other"}`,
		`{"input":"SYNTHETIC_SECRET"} {}`, `{"input":"SYNTHETIC_SECRET"} trailing`,
		`{"input":"SYNTHETIC_SECRET`, "```json\n{\"input\":\"SYNTHETIC_SECRET\"}\n```",
	}
	for i, args := range bad {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("case=%d/stream=%t", i, stream), func(t *testing.T) {
				chunks := []*upChunk{
					respTestCall(t, "bad", "raw", args),
					respTestChunk(t, nil, "length", nil),
					respTestChunk(t, map[string]any{"content": "must not follow failure"}, "", nil),
				}
				s, _, _ := respTestServer(t, chunks)
				rr := respTestRequest(t, s, stream, respTestCustomTools("raw"), "hello", nil)
				respTestAssertFailure(t, rr, stream)
			})
		}
	}
}

func respTestAssertFailure(t *testing.T, rr *httptest.ResponseRecorder, stream bool) {
	t.Helper()
	if strings.Contains(rr.Body.String(), "SYNTHETIC_SECRET") {
		t.Error("error response leaked custom arguments")
	}
	if !stream {
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("invalid upstream call status = %d, want 502", rr.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["error"] == nil || body["output"] != nil {
			t.Fatalf("invalid error response: %s", rr.Body)
		}
		return
	}
	events := respTestEvents(t, rr)
	failures := 0
	for i, event := range events {
		switch event["type"] {
		case "response.failed":
			failures++
			if i != len(events)-1 || event["response"].(map[string]any)["status"] != "failed" {
				t.Error("stream output continued after failure")
			}
		case "response.completed", "response.custom_tool_call_input.delta", "response.custom_tool_call_input.done", "response.output_item.done":
			t.Errorf("invalid call emitted success event %v", event["type"])
		}
	}
	if failures != 1 {
		t.Fatalf("response.failed count = %d, want one", failures)
	}
}

func TestHandleResponsesRejectsUnresolvedToolCall(t *testing.T) {
	cases := map[string][]*upChunk{
		"missing name":   {respTestCall(t, "bad", "", `{"input":"SYNTHETIC_SECRET"}`)},
		"missing id":     {respTestCall(t, "", "raw", `{"input":"SYNTHETIC_SECRET"}`)},
		"only arguments": {respTestCall(t, "", "", `{"input":"SYNTHETIC_SECRET"}`)},
	}
	for name, chunks := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", name, stream), func(t *testing.T) {
				s, _, _ := respTestServer(t, chunks)
				rr := respTestRequest(t, s, stream, respTestCustomTools("raw"), "hello", nil)
				respTestAssertFailure(t, rr, stream)
			})
		}
	}
}

func TestHandleResponsesCustomKindsAreRequestLocal(t *testing.T) {
	chunks := []*upChunk{respTestCall(t, "call", "apply_patch", `{"input":"raw"}`)}
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			s, _, _ := respTestServer(t, chunks)
			for _, kind := range []string{"custom", "function", "custom", "function"} {
				rr := respTestRequest(t, s, stream, []map[string]any{{"type": kind, "name": "apply_patch"}}, "hello", nil)
				response := respTestResponse(t, rr, stream)
				item := response["output"].([]any)[0].(map[string]any)
				want := "function_call"
				if kind == "custom" {
					want = "custom_tool_call"
				}
				if item["type"] != want {
					t.Fatalf("request tool kind %s generated %v", kind, item["type"])
				}
				if kind == "function" && item["arguments"] != `{"input":"raw"}` {
					t.Fatalf("plain function apply_patch was unwrapped: %#v", item)
				}
			}
		})
	}
}

func TestRespCustomInputCodec(t *testing.T) {
	for _, raw := range []string{"", " \t\r\n", "中文 😀 <>& / \\", "literal\\n and \"quotes\"", `{"input":"do not recursively decode"}`, "\n```raw\nvalue\n```\n"} {
		wrapped := encodeRespCustomInput(raw)
		for _, arguments := range []string{wrapped, " \r\n\t" + wrapped + "\r\n "} {
			got, err := decodeRespCustomInput(arguments)
			if err != nil || got != raw {
				t.Errorf("codec round trip = %q, %v; want %q", got, err, raw)
			}
		}
	}
	bad := []string{
		``, `null`, `[]`, `{}`, `{"other":"SYNTHETIC_SECRET"}`, `{"input":null}`,
		`{"input":1}`, `{"input":true}`, `{"input":[]}`, `{"input":{}}`,
		`{"input":"SYNTHETIC_SECRET","input":"duplicate"}`,
		`{"input":"SYNTHETIC_SECRET","extra":null}`,
		`{"input":"SYNTHETIC_SECRET",}`, `{"input":"SYNTHETIC_SECRET"`,
		`{"input":"SYNTHETIC_SECRET"} null`, `{"input":"SYNTHETIC_SECRET"} trailing`,
		`"{\"input\":\"SYNTHETIC_SECRET\"}"`, "```json\n{\"input\":\"SYNTHETIC_SECRET\"}\n```",
	}
	for _, arguments := range bad {
		got, err := decodeRespCustomInput(arguments)
		if err == nil || got != "" {
			t.Errorf("invalid wrapper accepted: %q", arguments)
		} else if strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Error("codec error exposes arguments")
		}
	}
}

func respTestInvalidSurrogateWrappers() map[string]string {
	escape := "\\" + "u"
	return map[string]string{
		"lone high":         `{"input":"before` + escape + `d800after"}`,
		"lone low":          `{"input":"before` + escape + `dc00after"}`,
		"high then nonlow":  `{"input":"before` + escape + `d800` + escape + `0041after"}`,
		"high then high":    `{"input":"before` + escape + `d800` + escape + `dbffafter"}`,
		"high then literal": `{"input":"before` + escape + `d800xafter"}`,
		"high then escaped": `{"input":"before` + escape + `d800\` + escape + `dc00after"}`,
		"low then high":     `{"input":"before` + escape + `dc00` + escape + `d800after"}`,
	}
}

func TestRespCustomInputRejectsInvalidUnicode(t *testing.T) {
	cases := respTestInvalidSurrogateWrappers()
	cases["invalid UTF8"] = `{"input":"before` + string([]byte{0xff}) + `after"}`
	cases["truncated UTF8"] = `{"input":"before` + string([]byte{0xe2, 0x82}) + `after"}`
	cases["UTF8 surrogate"] = `{"input":"before` + string([]byte{0xed, 0xa0, 0x80}) + `after"}`
	for name, wrapper := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeRespCustomInput(wrapper)
			if err == nil || got != "" {
				t.Fatalf("invalid Unicode was silently accepted: input=%q error=%v", got, err)
			}
			if strings.Contains(err.Error(), "before") || strings.Contains(err.Error(), "after") {
				t.Error("Unicode validation error exposed raw input")
			}
		})
	}
}

func TestRespCustomInputPreservesValidUnicode(t *testing.T) {
	escape := "\\" + "u"
	cases := []struct{ name, wrapper, want string }{
		{"surrogate pair", `{"input":"before` + escape + `D83d` + escape + `De00after"}`, "before😀after"},
		{"surrogate bounds", `{"input":"` + escape + `d800` + escape + `dc00` + escape + `dbff` + escape + `dfff"}`, "\U00010000\U0010ffff"},
		{"literal replacement", `{"input":"before�after"}`, "before�after"},
		{"escaped replacement", `{"input":"before` + escape + `FFFDafter"}`, "before�after"},
		{"literal backslash-u", `{"input":"before\` + escape + `d800after"}`, "before" + escape + "d800after"},
		{"literal surrogate escapes", `{"input":"before\` + escape + `d800\` + escape + `dc00after"}`, "before" + escape + "d800" + escape + "dc00after"},
		{"escaped slash", `{"input":"before\/after"}`, "before/after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeRespCustomInput(tc.wrapper)
			if err != nil || got != tc.want {
				t.Errorf("valid Unicode/escape changed: got=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
}

func TestHandleResponsesRejectsInvalidCustomUnicode(t *testing.T) {
	for name, wrapper := range respTestInvalidSurrogateWrappers() {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", name, stream), func(t *testing.T) {
				s, _, _ := respTestServer(t, []*upChunk{respTestCall(t, "bad", "raw", wrapper)})
				rr := respTestRequest(t, s, stream, respTestCustomTools("raw"), "hello", nil)
				respTestAssertFailure(t, rr, stream)
				if strings.Contains(rr.Body.String(), "before") || strings.Contains(rr.Body.String(), "after") {
					t.Error("invalid Unicode input escaped through an error response")
				}
			})
		}
	}
}

func TestHandleResponsesCustomCompleteInputAtTokenLimit(t *testing.T) {
	for _, raw := range []string{"", "  raw outside the synthetic grammar\r\n", `{"input":"not recursive"}`} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("raw=%q/stream=%t", raw, stream), func(t *testing.T) {
				tools := []map[string]any{{"type": "custom", "name": "raw", "format": map[string]any{"type": "grammar", "syntax": "regex", "definition": "^SYNTHETIC_ONLY$"}}}
				chunks := []*upChunk{respTestCall(t, "call", "raw", encodeRespCustomInput(raw)), respTestChunk(t, nil, "length", nil)}
				s, _, _ := respTestServer(t, chunks)
				rr := respTestRequest(t, s, stream, tools, "hello", nil)
				response := respTestResponse(t, rr, stream)
				item := response["output"].([]any)[0].(map[string]any)
				if item["type"] != "custom_tool_call" || item["input"] != raw || response["status"] != "incomplete" || response["incomplete_details"].(map[string]any)["reason"] != "max_output_tokens" {
					t.Fatalf("complete custom input/length status changed: %#v", response)
				}
				if stream {
					respTestAssertCustomEvents(t, respTestEvents(t, rr), item, 0)
				}
			})
		}
	}
}

func TestRespStreamCustomInputWaitsForValidation(t *testing.T) {
	rr := httptest.NewRecorder()
	st := &respStreamState{w: rr, flusher: rr, respID: "resp_test", toolKinds: respToolKinds{"raw": "custom"}}
	st.handleChunk(respTestCall(t, "call", "", ""))
	st.handleChunk(respTestCall(t, "", "", `{"input":"raw`))
	if rr.Body.Len() != 0 {
		t.Fatal("output item emitted before the name resolved its kind")
	}
	st.handleChunk(respTestCall(t, "call", "raw", `\n"}`))
	events := respTestEvents(t, rr)
	if len(events) != 1 || events[0]["type"] != "response.output_item.added" {
		t.Fatalf("custom input emitted before call boundary: %#v", events)
	}
	st.handleChunk(respTestCall(t, "call", "raw", ""))
	if len(respTestEvents(t, rr)) != 1 {
		t.Fatal("repeated metadata reopened or closed the custom call")
	}
	st.handleChunk(respTestCall(t, "function", "shell_command", `{"command":`))
	st.handleChunk(respTestCall(t, "", "", `"pwd"}`))
	st.complete()
	response := respTestResponse(t, rr, true)
	items := response["output"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["input"] != "raw\n" {
		t.Fatalf("call boundary/output changed: %#v", items)
	}
	respTestAssertCustomEvents(t, respTestEvents(t, rr), items[0].(map[string]any), 0)
	var args []string
	for _, event := range respTestEvents(t, rr) {
		if event["type"] == "response.function_call_arguments.delta" {
			args = append(args, event["delta"].(string))
		}
	}
	if !reflect.DeepEqual(args, []string{`{"command":`, `"pwd"}`}) {
		t.Fatalf("ordinary function arguments are no longer incremental: %#v", args)
	}
}

func TestHandleResponsesCustomFailureAfterValidCall(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			chunks := []*upChunk{
				respTestCall(t, "valid", "raw", `{"input":"valid"}`),
				// A fresh unnamed ID must not inherit the previous call's name.
				respTestCall(t, "bad", "", `{"input":"SYNTHETIC_SECRET"}`),
			}
			s, _, _ := respTestServer(t, chunks)
			rr := respTestRequest(t, s, stream, respTestCustomTools("raw"), "hello", nil)
			if !stream {
				respTestAssertFailure(t, rr, false)
				return
			}
			if strings.Contains(rr.Body.String(), "SYNTHETIC_SECRET") {
				t.Fatal("unresolved call leaked arguments")
			}
			failures, done := 0, 0
			events := respTestEvents(t, rr)
			for i, event := range events {
				if event["type"] == "response.completed" {
					t.Error("bad second call completed successfully")
				}
				if event["type"] == "response.failed" {
					failures++
					if i != len(events)-1 {
						t.Error("events emitted after failure")
					}
				}
				if event["type"] == "response.output_item.done" {
					done++
					if event["item"].(map[string]any)["call_id"] != "valid" {
						t.Error("bad second call emitted a done item")
					}
				}
			}
			if failures != 1 || done != 1 {
				t.Fatalf("failures/done = %d/%d, want 1/1", failures, done)
			}
		})
	}
}

func TestRespConversionFailureDrainsProducer(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			bad := respTestCall(t, "bad", "raw", `{"input":"SYNTHETIC_SECRET"`)
			finish := respTestChunk(t, nil, "length", nil)
			later := respTestChunk(t, map[string]any{"content": "must not follow failure"}, "", nil)
			chunks := make(chan *upChunk)
			errCh := make(chan error, 1)
			errCh <- errors.New("later upstream error must not replace conversion error")
			produced := make(chan struct{})
			go func() {
				defer close(produced)
				defer close(chunks)
				for i := 0; i < 130; i++ {
					chunk := later
					if i == 0 {
						chunk = bad
					} else if i == 1 {
						chunk = finish
					}
					select {
					case chunks <- chunk:
					case <-ctx.Done():
						return
					}
				}
			}()
			rr := httptest.NewRecorder()
			s := &server{logf: func(string, ...any) {}}
			consumed := make(chan struct{})
			go func() {
				defer close(consumed)
				if stream {
					s.streamResponses(rr, chunks, errCh, &respRequest{Model: "auto"}, "synthetic", respToolKinds{"raw": "custom"})
				} else {
					s.collectResponses(rr, chunks, errCh, &respRequest{Model: "auto"}, "synthetic", respToolKinds{"raw": "custom"})
				}
			}()
			for _, done := range []<-chan struct{}{consumed, produced} {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("conversion failure left chunk production/consumption blocked")
				}
			}
			respTestAssertFailure(t, rr, stream)
			if strings.Contains(rr.Body.String(), "later upstream error") || strings.Contains(rr.Body.String(), "must not follow failure") {
				t.Fatal("output continued or a later error replaced the conversion failure")
			}
		})
	}
}

func TestRespToolChoicePreservesUnrelatedCompatibility(t *testing.T) {
	for _, raw := range []string{`null`, `"auto"`, `"none"`, `"required"`, `{"type":"function","function":{"name":"shell","extra":true}}`, `{"type":"unsupported","name":"raw"}`} {
		got, err := respToolChoiceToOAI(json.RawMessage(raw), nil)
		var want any
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatal(err)
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("existing choice changed: got=%#v err=%v want=%#v", got, err, want)
		}
	}
}

func TestHandleResponsesCustomTwoTurnFlow(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			raw := "\nBEGIN\n+synthetic\nEND\n"
			first := []*upChunk{respTestCall(t, "call_patch", "apply_patch", string(respTestJSON(t, map[string]string{"input": raw})))}
			second := []*upChunk{respTestChunk(t, map[string]any{"content": "finished"}, "stop", nil)}
			s, recorder, calls := respTestServer(t, first, second)
			choice := map[string]any{"type": "custom", "name": "apply_patch"}
			rr := respTestRequest(t, s, stream, respTestCustomTools("apply_patch"), "edit", choice)
			response := respTestResponse(t, rr, stream)
			item := response["output"].([]any)[0].(map[string]any)
			if item["type"] != "custom_tool_call" || item["input"] != raw {
				t.Fatalf("first turn missing raw custom call: %#v", item)
			}
			input := []any{map[string]any{"role": "user", "content": "edit"}, item, map[string]any{"type": "custom_tool_call_output", "call_id": "call_patch", "output": "synthetic success"}}
			// History is classified by item type even when no tools are advertised.
			rr = respTestRequest(t, s, stream, nil, input, nil)
			respTestResponse(t, rr, stream)
			if calls.Load() != 2 {
				t.Fatalf("upstream calls = %d, want 2", calls.Load())
			}
			body := respTestCapturedBody(t, recorder, 1)
			messages := body["messages"].([]any)
			if len(messages) != 3 {
				t.Fatalf("second turn lost call/result history: %#v", messages)
			}
			call := messages[1].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
			fn := call["function"].(map[string]any)
			var wrapper map[string]string
			if err := json.Unmarshal([]byte(fn["arguments"].(string)), &wrapper); err != nil || wrapper["input"] != raw || call["id"] != "call_patch" || fn["name"] != "apply_patch" {
				t.Fatalf("second turn wrapper/correlation changed: %#v", call)
			}
			result := messages[2].(map[string]any)
			if result["role"] != "tool" || result["tool_call_id"] != "call_patch" || result["content"] != "synthetic success" {
				t.Fatalf("second turn custom output not forwarded: %#v", result)
			}
			firstBody := respTestCapturedBody(t, recorder, 0)
			want := map[string]any{"type": "function", "function": map[string]any{"name": "apply_patch"}}
			if !reflect.DeepEqual(firstBody["parameters"].(map[string]any)["tool_choice"], want) || len(firstBody["tools"].([]any)) != 1 {
				t.Fatal("first turn tools/choice were not converted before protocol preparation")
			}
		})
	}
}

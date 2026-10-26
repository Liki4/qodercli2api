package main

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

type respToolFormat struct {
	Type       string `json:"type"`
	Syntax     string `json:"syntax,omitempty"`
	Definition string `json:"definition,omitempty"`
}

// Original tool kinds belong to one request, never to a model or session.
type respToolKinds map[string]string

func respToolsToOAI(tools []respTool) ([]map[string]any, respToolKinds, error) {
	out := make([]map[string]any, 0, len(tools))
	kinds := make(respToolKinds)
	for _, t := range tools {
		if t.Type != "function" && t.Type != "custom" {
			continue
		}
		if previous, exists := kinds[t.Name]; exists && (previous == "custom" || t.Type == "custom") {
			return nil, nil, errors.New("duplicate tool name involving a custom tool")
		}
		kinds[t.Name] = t.Type
		params := any(t.Parameters)
		description := t.Description
		if t.Type == "custom" {
			if strings.TrimSpace(t.Name) == "" {
				return nil, nil, errors.New("custom tool name is required")
			}
			guidance := "Instructions for the decoded raw input string only (not the outer JSON transport envelope):\n" + t.Description
			if t.Format != nil {
				switch t.Format.Type {
				case "text":
				case "grammar":
					if t.Format.Syntax != "lark" && t.Format.Syntax != "regex" {
						return nil, nil, errors.New("unsupported custom tool grammar syntax")
					}
					if strings.TrimSpace(t.Format.Definition) == "" {
						return nil, nil, errors.New("custom tool grammar definition is required")
					}
					guidance += "\nGrammar guidance for that raw string (" + t.Format.Syntax + "):\n" + t.Format.Definition
				default:
					return nil, nil, errors.New("unsupported custom tool format type")
				}
			}
			description = `Custom tool transported as a function. The outer function arguments MUST be a JSON object {"input": string}, with exactly one string input member. Put the tool's raw input in that string. The input property's instructions and grammar apply only to the decoded raw input string; any FREEFORM or "do not wrap in JSON" instruction describes that raw string, not this required JSON transport envelope.`
			params = map[string]any{
				"type": "object",
				"properties": map[string]any{"input": map[string]any{
					"type": "string", "description": guidance,
				}},
				"required": []string{"input"}, "additionalProperties": false,
			}
		} else if len(t.Parameters) == 0 {
			params = json.RawMessage(`{"type":"object"}`)
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name": t.Name, "description": description, "parameters": params,
			},
		})
	}
	return out, kinds, nil
}

func respToolChoiceToOAI(raw json.RawMessage, kinds respToolKinds) (any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var choice any
	if err := json.Unmarshal(raw, &choice); err != nil {
		return nil, errors.New("invalid tool_choice")
	}
	obj, ok := choice.(map[string]any)
	if !ok {
		return choice, nil
	}
	kind, _ := obj["type"].(string)
	name, _ := obj["name"].(string)
	if kind == "custom" {
		if name == "" || kinds[name] != "custom" {
			return nil, errors.New("custom tool_choice must name an advertised custom tool")
		}
	} else if kind != "function" || obj["function"] != nil || name == "" {
		// Keep existing nested function choices and unrelated choices unchanged.
		return choice, nil
	}
	return map[string]any{"type": "function", "function": map[string]any{"name": name}}, nil
}

func encodeRespCustomInput(input string) string {
	b, _ := json.Marshal(struct {
		Input string `json:"input"`
	}{Input: input})
	return string(b)
}

var errRespCustomInput = errors.New("invalid upstream custom tool input wrapper")
var errRespToolCall = errors.New("unresolved upstream tool call")

// Do not use map/struct unmarshalling here: it accepts duplicate members. A
// custom call is executable client input, so accept only one complete wrapper,
// never raw text, extra members, or a partially generated JSON string.
func decodeRespCustomInput(arguments string) (string, error) {
	d := json.NewDecoder(strings.NewReader(arguments))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return "", errRespCustomInput
	}
	if token, err := d.Token(); err != nil || token != "input" {
		return "", errRespCustomInput
	}
	var literal json.RawMessage
	if err := d.Decode(&literal); err != nil || !validRespCustomString(literal) {
		return "", errRespCustomInput
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return "", errRespCustomInput
	}
	if _, err := d.Token(); err != io.EOF {
		return "", errRespCustomInput
	}
	var input string
	if err := json.Unmarshal(literal, &input); err != nil {
		return "", errRespCustomInput
	}
	return input, nil
}

// The decoder has already checked JSON syntax. Preserve the literal long enough
// to reject Unicode that encoding/json would silently replace with U+FFFD; an
// actual U+FFFD character (literal or escaped) remains valid tool input.
func validRespCustomString(literal []byte) bool {
	if len(literal) < 2 || literal[0] != '"' || literal[len(literal)-1] != '"' || !utf8.Valid(literal) {
		return false
	}
	for i := 1; i < len(literal)-1; i++ {
		if literal[i] != '\\' {
			continue
		}
		i++
		if literal[i] != 'u' {
			continue // Includes escaped backslashes, not Unicode escapes.
		}
		if i+4 >= len(literal)-1 {
			return false
		}
		value, err := strconv.ParseUint(string(literal[i+1:i+5]), 16, 16)
		if err != nil || value >= 0xdc00 && value <= 0xdfff {
			return false // A low surrogate is only valid after a high surrogate.
		}
		i += 4
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(literal)-1 || literal[i+1] != '\\' || literal[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(literal[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// Upstream calls are sequential and can all use index zero. Only a fresh ID
// delimits another call; repeated metadata and delayed headers extend this one.
// This is deliberately not an interleaved-index tool-call multiplexer.
type respToolCall struct {
	callID string
	name   string
	args   strings.Builder
}

func (c *respToolCall) startsNew(id string) bool {
	return c != nil && c.callID != "" && id != "" && id != c.callID
}

func (c *respToolCall) add(id, name, args string) error {
	if name != "" {
		if c.name != "" && c.name != name {
			return errRespToolCall
		}
		c.name = name
	}
	if id != "" {
		c.callID = id
	}
	c.args.WriteString(args)
	return nil
}

func (c *respToolCall) ready() bool {
	return c.callID != "" && c.name != ""
}

func (c *respToolCall) item(id string, kinds respToolKinds) (map[string]any, error) {
	if !c.ready() {
		return nil, errRespToolCall
	}
	item := map[string]any{
		"id": id, "type": "function_call", "call_id": c.callID,
		"name": c.name, "status": "completed",
	}
	if kinds[c.name] == "custom" {
		input, err := decodeRespCustomInput(c.args.String())
		if err != nil {
			return nil, err
		}
		item["type"], item["input"] = "custom_tool_call", input
	} else {
		item["arguments"] = c.args.String()
	}
	return item, nil
}

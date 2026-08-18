package main

import (
	"encoding/json"
	"testing"
)

func TestRespToUpstreamPreservesInputImage(t *testing.T) {
	input := json.RawMessage(`[
		{
			"type": "message",
			"role": "user",
			"content": [
				{"type": "input_text", "text": "describe this"},
				{"type": "input_image", "image_url": "data:image/png;base64,abc"}
			]
		}
	]`)

	_, msgs, err := respToUpstream("", input)
	if err != nil {
		t.Fatalf("respToUpstream returned error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if len(msgs[0].Contents) != 2 {
		t.Fatalf("got %d upstream content parts, want 2", len(msgs[0].Contents))
	}
	if got := msgs[0].Contents[0].Text; got != "describe this" {
		t.Fatalf("text content = %q, want %q", got, "describe this")
	}
	if got := msgs[0].Contents[1].ImageURL.URL; got != "data:image/png;base64,abc" {
		t.Fatalf("image URL = %q, want data URL", got)
	}
}

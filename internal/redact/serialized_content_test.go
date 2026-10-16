package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestSerializedToolContentRedaction(t *testing.T) {
	cases := []string{
		`{"cookie":"PRIVATE_CANARY","keep":"VISIBLE"}`,
		`{"auth":"PRIVATE_CANARY","keep":"VISIBLE"}`,
		`{"credentials":{"value":"PRIVATE_CANARY"},"keep":"VISIBLE"}`,
		`{"pass\u0077ord":"PRIVATE_CANARY","keep":"VISIBLE"}`,
		`{"password":"prefix\"PRIVATE_CANARY","keep":"VISIBLE"}`,
		`{"password":["PRIVATE_CANARY"],"keep":"VISIBLE"}`,
		`{"password":"PRIVATE_CANARY","keep":"VISIBLE"}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			var ev model.Event
			ev.SetToolInput(body)
			ev.SetToolResult(body)
			preview, _ := ToolInputPreview(body)
			if strings.Contains(preview, "PRIVATE_CANARY") {
				t.Fatal("preview exposed recognized credential")
			}
			full := EventWithContent(ev)
			if strings.Contains(full.ToolInput+full.ToolResult, "PRIVATE_CANARY") {
				t.Error("full content exposed recognized credential")
			}
			for _, payload := range []string{full.ToolInput, full.ToolResult} {
				var decoded string
				if err := json.Unmarshal([]byte(payload), &decoded); err != nil || !json.Valid([]byte(decoded)) || !strings.Contains(decoded, "VISIBLE") {
					t.Error("serialized representation or unrelated field lost")
				}
			}
			raw := EventWithRawContent(ev)
			for _, payload := range []string{raw.ToolInput, raw.ToolResult, ev.ToolInputForAnalysis(), ev.ToolResultForAnalysis()} {
				var decoded string
				if json.Unmarshal([]byte(payload), &decoded) != nil || decoded != body {
					t.Fatal("raw or local analysis changed")
				}
			}
		})
	}
}

func TestNestedSerializedContentBoundAndPrecision(t *testing.T) {
	body := `{"cookie":"PRIVATE_CANARY","n":9007199254740993,"keep":"VISIBLE <tag>"}`
	for depth := 1; depth <= maxSerializedJSONDepth+1; depth++ {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		body = string(encoded)
		var ev model.Event
		ev.SetToolInput(json.RawMessage(body))
		full := EventWithContent(ev)
		if strings.Contains(full.ToolInput, "PRIVATE_CANARY") {
			t.Fatalf("depth %d exposed credential", depth)
		}
		if depth > maxSerializedJSONDepth {
			if !full.ToolInputTruncated {
				t.Fatal("decoding bound not reported")
			}
		} else {
			if full.ToolInputTruncated || !strings.Contains(full.ToolInput, "9007199254740993") || !strings.Contains(full.ToolInput, "VISIBLE") {
				t.Fatal("bounded redaction lost unrelated values")
			}
		}
		if EventWithRawContent(ev).ToolInput != body || ev.ToolInputForAnalysis() != body {
			t.Fatal("decoding bound changed raw or analysis content")
		}
	}
}

func TestNestedObjectSerializedContent(t *testing.T) {
	var ev model.Event
	ev.SetToolResult(map[string]any{"content": []any{map[string]string{"text": `{"cookie":"PRIVATE_CANARY","keep":"VISIBLE"}`}}, "plain": "ordinary text", "input_tokens": 123})
	full := EventWithContent(ev)
	if !json.Valid([]byte(full.ToolResult)) || strings.Contains(full.ToolResult, "PRIVATE_CANARY") || !strings.Contains(full.ToolResult, "VISIBLE") || !strings.Contains(full.ToolResult, "ordinary text") || !strings.Contains(full.ToolResult, "123") {
		t.Fatal("nested content or benign sibling redacted incorrectly")
	}
}

func TestMalformedSerializedToolContent(t *testing.T) {
	for _, body := range []string{
		`{"cookie":"PRIVATE_CANARY"`,
		`{"auth":"PRIVATE_CANARY"} trailing`,
		`{"pass\u0077ord":"PRIVATE_CANARY"`,
		`{"password":"prefix\"PRIVATE_CANARY"`,
		` [{"credentials":"PRIVATE_CANARY"}`,
		`"PRIVATE_CANARY`,
	} {
		t.Run(body, func(t *testing.T) {
			if preview, truncated := ToolInputPreview(body); preview != "" || !truncated {
				t.Fatal("damaged JSON preview must be omitted")
			}
			for _, value := range []any{body, map[string]any{"content": []any{map[string]string{"text": body}}}} {
				var ev model.Event
				ev.SetToolInput(value)
				ev.SetToolResult(value)
				original := ev.ToolInputForAnalysis()
				full := EventWithContent(ev)
				if strings.Contains(full.ToolInput+full.ToolResult, "PRIVATE_CANARY") ||
					!strings.Contains(full.ToolInput, "payload omitted") || !strings.Contains(full.ToolResult, "payload omitted") ||
					!full.ToolInputTruncated || !full.ToolResultTruncated {
					t.Error("unsafe serialized content must be explicitly omitted")
				}
				if full.ToolInputBytes != len(original) || full.ToolResultBytes != len(original) {
					t.Fatal("omission changed original byte counts")
				}
				raw := EventWithRawContent(ev)
				if raw.ToolInput != original || raw.ToolResult != original || raw.ToolInputTruncated || raw.ToolResultTruncated ||
					ev.ToolInputForAnalysis() != original || ev.ToolResultForAnalysis() != original {
					t.Fatal("output omission changed raw content or analysis originals")
				}
			}
		})
	}
}

func TestSerializedToolContentOrdinaryText(t *testing.T) {
	for _, body := range []string{"", "ordinary text", "echo hello", "text with { braces }", "123", "true", "null"} {
		var ev model.Event
		ev.SetToolResult(body)
		full := EventWithContent(ev)
		var decoded string
		if full.ToolResultTruncated || json.Unmarshal([]byte(full.ToolResult), &decoded) != nil || decoded != body {
			t.Fatalf("ordinary text changed: %q", body)
		}
	}
}

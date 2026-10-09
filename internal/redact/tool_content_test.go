package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestToolContentProjection(t *testing.T) {
	for _, raw := range []string{`null`, `""`, `false`, `0`, `[]`, `{}`, `{"n":9007199254740993,"unknown":[null,false,""],"password":"PRIVATE_CANARY"}`} {
		t.Run(raw, func(t *testing.T) {
			var ev model.Event
			ev.SetToolInput(json.RawMessage(raw))
			ev.SetToolResult(json.RawMessage(raw))
			b, err := json.Marshal(ev)
			if err != nil || strings.Contains(string(b), "tool_input") || strings.Contains(string(b), "PRIVATE_CANARY") {
				t.Fatalf("default marshal exposed payload: %s (%v)", b, err)
			}
			preview := Event(ev)
			if preview.ToolInput != "" || preview.ToolResult != "" || preview.ToolInputBytes != len(raw) {
				t.Fatal("preview must omit bodies but retain their original sizes")
			}
			full, original := EventWithContent(ev), EventWithRawContent(ev)
			if !json.Valid([]byte(full.ToolInput)) || strings.Contains(full.ToolInput+full.ToolResult, "PRIVATE_CANARY") {
				t.Fatalf("invalid redacted payload: %q", full.ToolInput)
			}
			if original.ToolInput != raw || original.ToolResult != raw || original.ToolInputBytes != len(raw) {
				t.Fatal("raw projection changed the source payload")
			}
			if ev.ToolInputForAnalysis() != raw || ev.ToolResultForAnalysis() != raw {
				t.Fatal("output projection mutated analysis data")
			}
		})
	}
}

func TestToolContentBeyondMessageLimit(t *testing.T) {
	text := strings.Repeat("x", model.ContentMaxBytes+1) + "TAIL_CANARY"
	var ev model.Event
	ev.SetToolResult(text)
	for _, projected := range []model.Event{EventWithContent(ev), EventWithRawContent(ev)} {
		var got string
		if err := json.Unmarshal([]byte(projected.ToolResult), &got); err != nil || got != text || projected.ToolResultTruncated {
			t.Fatalf("tool result did not survive: length=%d truncated=%t err=%v", len(got), projected.ToolResultTruncated, err)
		}
	}
}

func TestToolContentBoundIsVisible(t *testing.T) {
	var ev model.Event
	ev.SetToolResult(strings.Repeat("x", model.ToolPayloadMaxBytes+1))
	if !ev.ToolResultTruncatedForAnalysis() || ev.ToolResultBytesForAnalysis() != model.ToolPayloadMaxBytes+3 {
		t.Fatal("source size or truncation missing")
	}
	if full := EventWithContent(ev); !full.ToolResultTruncated || strings.Contains(full.ToolResult, strings.Repeat("x", 30)) {
		t.Fatal("incomplete JSON must not pass redaction")
	}
	if preview := Event(ev); !preview.ToolResultTruncated || preview.ToolResult != "" {
		t.Fatal("preview hid a capture gap")
	}
}

func TestToolContentSerializedArgumentsRedaction(t *testing.T) {
	var ev model.Event
	ev.SetToolInput(`{"password":"PRIVATE_CANARY","query":"keep this"}`)
	full := EventWithContent(ev)
	if strings.Contains(full.ToolInput, "PRIVATE_CANARY") || !strings.Contains(full.ToolInput, "keep this") {
		t.Fatalf("serialized arguments = %s", full.ToolInput)
	}
}

func TestMessageContentKeepsToolMetadata(t *testing.T) {
	for _, value := range []string{"", `null`, `""`, `{}`, `{"cookie":"PRIVATE_CANARY"`, `{"data":"complete"}`} {
		for _, truncated := range []bool{false, true} {
			ev := model.Event{
				ToolInput: value, ToolInputBytes: len(value), ToolInputTruncated: truncated,
				ToolResult: value, ToolResultBytes: len(value), ToolResultTruncated: truncated,
			}
			for _, raw := range []bool{false, true} {
				got := EventWithMessageContent(ev, raw)
				if got.ToolInput != "" || got.ToolResult != "" ||
					got.ToolInputBytes != len(value) || got.ToolResultBytes != len(value) ||
					got.ToolInputTruncated != truncated || got.ToolResultTruncated != truncated {
					t.Fatalf("value=%q truncated=%t raw=%t: body omission changed source metadata", value, truncated, raw)
				}
				if got.ToolInputForAnalysis() != "" || got.ToolResultForAnalysis() != "" {
					t.Fatal("export retained private tool bodies")
				}
			}
		}
	}
}

package extract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestMuseRelocatedSessionPath(t *testing.T) {
	path := "/sessions/cache/2026/storage/muse/sessions/2026/09/18/sess-1/session.jsonl"
	got := museExtractFixture(t, path, museSessionFixture, false)
	want := museExtractFixture(t, "/muse/sessions/2026/09/18/sess-1/session.jsonl", museSessionFixture, false)
	if len(got.Events) != len(want.Events) || len(got.Events) == 0 {
		t.Fatalf("relocated path lost events: got %d want %d", len(got.Events), len(want.Events))
	}
	for _, ev := range got.Events {
		if ev.SessionID != "sess-1" {
			t.Fatalf("wrong session: %q", ev.SessionID)
		}
	}
	for _, path := range []string{
		"/sessions/2026/09/18/sess-1/not-session.jsonl",
		"/sessions/2026/09/18/sess-1/other/session.jsonl",
		"/sessions/not/a/date/sess-1/session.jsonl",
		"/sessions/2026/02/31/sess-1/session.jsonl",
	} {
		if root, sub, stream := museFileContext(path); root != "" || sub != "" || stream != "" {
			t.Fatalf("malformed layout acquired identity: %s", path)
		}
	}
}

func museContentRecord(t *testing.T, kind, field string, item map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"payload_type": "runtime.session",
		"payload": map[string]any{"kind": "run", "event": map[string]any{
			"kind": kind, field: []any{item},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw) + "\n"
}

func TestMuseToolContentPresenceAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, args, want string
		present          bool
	}{
		{"missing", "", "", false},
		{"empty", "", `""`, true},
		{"null", "null", "null", true},
		{"array", "[1,false]", "[1,false]", true},
		{"malformed", "{bad", `"{bad"`, true},
		{"object", `{"text":"input-marker","token":"synthetic-secret","large":9007199254740993}`, `{"text":"input-marker","token":"synthetic-secret","large":9007199254740993}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := map[string]any{"name": "mcp__notes__save", "call_id": "c"}
			if tc.present {
				call["args"] = tc.args
			}
			body := museContentRecord(t, museEventAssistantToolCallsCommitted, "tool_calls", call)
			result := map[string]any{"tool_call_id": "c"}
			if tc.present {
				result["text"] = tc.args
			}
			body += museContentRecord(t, museEventToolResultBatchCommitted, "results", result)
			res := museExtractFixture(t, "/session.jsonl", body, false)
			if len(res.Events) != 2 || len(res.Diagnostics) != 0 {
				t.Fatalf("unexpected extraction: %+v", res)
			}
			ev := res.Events[0]
			if ev.ToolInputForAnalysis() != tc.want {
				t.Fatalf("input=%q want=%q", ev.ToolInputForAnalysis(), tc.want)
			}
			if res.Events[1].ToolResultForAnalysis() == "" && tc.present {
				t.Fatal("explicit result lost")
			}
			if res.Events[1].ToolResultForAnalysis() != "" && !tc.present {
				t.Fatal("absent result fabricated")
			}
			if ev.ToolInput != "" || redact.Event(ev).ToolInput != "" {
				t.Fatal("default output exposes retained input")
			}
			if tc.name == "object" {
				if strings.Contains(ev.ContentPreview, "synthetic-secret") || !strings.Contains(ev.ContentPreview, "input-marker") {
					t.Fatalf("unsafe or missing preview: %s", ev.ContentPreview)
				}
				full, raw := redact.EventWithContent(ev), redact.EventWithRawContent(ev)
				if strings.Contains(full.ToolInput, "synthetic-secret") || raw.ToolInput != tc.args {
					t.Fatalf("content modes changed: full=%q raw=%q", full.ToolInput, raw.ToolInput)
				}
				if scoped := redact.EventWithMessageContent(ev, false); scoped.ToolInput != "" {
					t.Fatal("message-only scope exposes tool input")
				}
			}
		})
	}
}

func FuzzMuseExtract(f *testing.F) {
	f.Add(museSessionFixture)
	fuzzExtractor(f, MuseCodeExtractor{})
}

func TestMuseTypedToolContentRemainsOptIn(t *testing.T) {
	res := museExtractFixture(t, "/muse/sessions/2026/09/18/sess-1/session.jsonl", museSessionFixture, false)
	for _, ev := range res.Events {
		switch ev.EventType {
		case model.EventCommandExec, model.EventFileRead, model.EventFileWrite,
			model.EventCommandResult, model.EventToolResult:
			if ev.ContentPreview != "" {
				t.Fatalf("typed tool or result gained a body preview: %s", ev.EventType)
			}
			if ev.ToolInputForAnalysis() == "" && ev.ToolResultForAnalysis() == "" {
				t.Fatalf("typed tool content not retained for opt-in output: %s", ev.EventType)
			}
		}
	}
}

package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestHookToolContentAcrossActions(t *testing.T) {
	for _, name := range []string{"Bash", "Read", "Write", "mcp__fetch__fetch", "mcp__notes__save"} {
		input := map[string]any{"command": "echo safe", "file_path": "/repo/file", "url": "https://example.test/", "content": strings.Repeat("x", 70000) + "INPUT_TAIL", "integer": json.Number("9007199254740993")}
		p := map[string]any{"tool_name": name, "tool_use_id": "c1", "tool_input": input}
		ev := Map(LifecyclePreTool, AgentClaude, model.AgentClaudeCode, "test", p)
		if !strings.Contains(ev.ToolInputForAnalysis(), "INPUT_TAIL") || !strings.Contains(ev.ToolInputForAnalysis(), "9007199254740993") {
			t.Fatalf("%s lost full input", name)
		}
		p["tool_response"] = []any{map[string]any{"type": "text", "text": "RESULT_TAIL"}, map[string]any{"type": "image", "data": "SYNTHETIC_IMAGE"}}
		ev = Map(LifecyclePostTool, AgentClaude, model.AgentClaudeCode, "test", p)
		out := redact.EventWithContent(ev)
		if !strings.Contains(out.ToolResult, "RESULT_TAIL") || !strings.Contains(out.ToolResult, "SYNTHETIC_IMAGE") {
			t.Fatalf("%s lost result blocks", name)
		}
		if err := ev.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHookResultPresence(t *testing.T) {
	for _, value := range []any{nil, "", false, []any{}} {
		p := map[string]any{"tool_name": "mcp__notes__save", "tool_response": value}
		ev := Map(LifecyclePostTool, AgentClaude, model.AgentClaudeCode, "test", p)
		if ev.ToolResultForAnalysis() == "" {
			t.Fatalf("dropped explicit value %#v", value)
		}
		delete(p, "tool_response")
		ev = Map(LifecyclePostTool, AgentClaude, model.AgentClaudeCode, "test", p)
		if ev.ToolResultForAnalysis() != "" {
			t.Fatal("fabricated missing result")
		}
	}
}

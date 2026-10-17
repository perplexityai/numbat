package hook

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestMuseHookRetainsEncodedToolContent(t *testing.T) {
	payload := map[string]any{
		"tool_name":     "mcp__notes__save",
		"tool_input":    `{"text":"input-marker","password":"synthetic-secret","n":9007199254740993}`,
		"tool_response": `{"text":"result-marker","token":"synthetic-secret"}`,
	}
	event := Map(LifecyclePostTool, AgentMuse, model.AgentMuseCode, "synthetic", payload)
	if !strings.Contains(event.ToolInputForAnalysis(), "input-marker") || !strings.Contains(event.ToolResultForAnalysis(), "result-marker") {
		t.Fatal("encoded hook content lost")
	}
	full := redact.EventWithContent(event)
	if strings.Contains(full.ToolInput, "synthetic-secret") || strings.Contains(full.ToolResult, "synthetic-secret") {
		t.Fatal("encoded hook content not redacted")
	}
	if !strings.Contains(full.ToolInput, "9007199254740993") {
		t.Fatal("encoded integer changed")
	}
	if preview := redact.Event(event); preview.ToolInput != "" || preview.ToolResult != "" {
		t.Fatal("preview exposed tool bodies")
	}
}

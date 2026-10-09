package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestHermesRetainsNestedResult(t *testing.T) {
	ev := Map(LifecycleHermesPostTool, AgentHermes, model.AgentHermesCLI, "e", map[string]any{"tool_name": "custom", "extra": map[string]any{"result": "RESULT_CANARY", "tool_call_id": "c"}})
	if ev.EventType != model.EventToolResult || !strings.Contains(ev.ToolResultForAnalysis(), "RESULT_CANARY") {
		t.Fatal("nested result lost")
	}
}

func TestHermesResultPresenceAndScope(t *testing.T) {
	for _, value := range []any{nil, "", false, []any{}, map[string]any{"n": json.Number("9007199254740993")}} {
		payload := map[string]any{"tool_name": "custom", "extra": map[string]any{"result": value}, "result": "WRONG_LEVEL"}
		ev := Map(LifecycleHermesPostTool, AgentHermes, model.AgentHermesCLI, "e", payload)
		want, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if ev.ToolResultForAnalysis() != string(want) {
			t.Fatal("nested result presence or value changed")
		}
		ev = Map(LifecycleHermesPreTool, AgentHermes, model.AgentHermesCLI, "e", payload)
		if ev.ToolResultForAnalysis() != "" {
			t.Fatal("pre-tool hook fabricated a result")
		}
		delete(payload, "extra")
		ev = Map(LifecycleHermesPostTool, AgentHermes, model.AgentHermesCLI, "e", payload)
		if ev.ToolResultForAnalysis() != "" {
			t.Fatal("unrelated top-level field became a result")
		}
	}
}

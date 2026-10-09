package hook

import (
	"encoding/json"

	"github.com/perplexityai/numbat/internal/model"
)

// retainToolContent preserves values without using status decoders, which
// intentionally accept only objects and would drop text, arrays, null or false.
func retainToolContent(ev *model.Event, r resolver) {
	switch ev.EventType {
	case model.EventToolCall, model.EventToolResult, model.EventCommandExec, model.EventCommandResult,
		model.EventFileRead, model.EventFileWrite, model.EventFileDelete, model.EventNetworkIndicator,
		model.EventPermissionRequested, model.EventPermissionApproved, model.EventPermissionDenied:
	default:
		return
	}
	ev.SetToolInput(r.toolInputValue())
	if ev.EventType != model.EventToolResult && ev.EventType != model.EventCommandResult {
		return
	}
	keys := []string{"tool_response", "toolResponse", "tool_result", "toolResult", "result", "response", "output", "error"}
	switch r.agent {
	case AgentGemini:
		keys = []string{"tool_response"}
	case AgentCursor:
		keys = []string{"tool_output", "error_message"}
	case AgentOpenCode, AgentKilo:
		keys = []string{"output"}
	case AgentClaude:
		keys = []string{"tool_response", "error"}
	}
	for _, key := range keys {
		if value, ok := r.fieldMap()[key]; ok {
			if value == nil {
				value = json.RawMessage("null")
			}
			ev.SetToolResult(value)
			return
		}
	}
}

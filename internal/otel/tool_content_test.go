package otel

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestOTLPResultContentAndRecordScope(t *testing.T) {
	for _, body := range [][]byte{anyStr(""), anyStr(strings.Repeat("x", 70000) + "RESULT_TAIL"), anyKVList(kv("unknown", "RESULT_TAIL"))} {
		result := mapOne(t, nil, recBuilder{attrs: [][]byte{kv(attrGenAIToolName, "mcp__notes__save"), kvAny(attrGenAIToolCallResult, body)}}.build())
		if !result.Mapped || result.Event.EventType != model.EventToolResult || result.Event.ToolResultForAnalysis() == "" {
			t.Fatal("result was lost or classified as a call")
		}
	}
	result := mapOne(t, [][]byte{kv(attrGenAIToolCallResult, "RESOURCE_CANARY")}, recBuilder{attrs: [][]byte{kv(attrGenAIToolName, "mcp__notes__save")}}.build())
	if result.Event.ToolResultForAnalysis() != "" || result.Event.EventType != model.EventToolCall {
		t.Fatal("process metadata fabricated a tool result")
	}
}

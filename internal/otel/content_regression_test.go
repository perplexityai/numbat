package otel

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestCompletionRetainsNormalizedCommand(t *testing.T) {
	ev := mustMap(t, nil, recBuilder{attrs: [][]byte{kv(attrGenAIToolName, "bash"), kv(attrGenAIToolCallArgs, `{"command":"echo COMMAND_CANARY"}`), kvAny("process.exit.code", anyInt(0)), kv(attrGenAIToolCallResult, "result")}}.build())
	if ev.EventType != model.EventCommandResult || ev.Command != "echo COMMAND_CANARY" {
		t.Fatalf("type=%s command=%q", ev.EventType, ev.Command)
	}
}

func TestNativeOTLPToolArgumentsRetained(t *testing.T) {
	for _, tc := range []struct{ service, event, name, key string }{
		{"codex", codexToolResult, "exec_command", attrArguments},
		{"gemini-cli", geminiToolCall, "run_shell_command", attrFunctionArgs},
		{"qwen-code", qwenToolCall, "run_shell_command", attrFunctionArgs},
	} {
		t.Run(tc.service, func(t *testing.T) {
			for _, service := range []string{tc.service, "collector", "claude-code"} {
				nameKey := attrAliasToolName
				if tc.key == attrFunctionArgs {
					nameKey = attrFunctionName
				}
				ev := mustMap(t, [][]byte{kv(attrServiceName, service)}, recBuilder{attrs: [][]byte{eventNameAttr(tc.event), kv(nameKey, tc.name), kv(tc.key, `{"command":"echo COMMAND_CANARY","unknown":"UNKNOWN_CANARY"}`)}}.build())
				if !strings.Contains(ev.ToolInputForAnalysis(), "UNKNOWN_CANARY") {
					t.Fatal("native arguments lost")
				}
			}
		})
	}
}

func TestNativeArgumentsRequireRecordEvidence(t *testing.T) {
	ev := mustMap(t, [][]byte{kv(attrServiceName, "codex"), kv(attrArguments, `{"unknown":"RESOURCE_CANARY"}`)}, recBuilder{attrs: [][]byte{eventNameAttr(codexToolResult), kv(attrAliasToolName, "custom")}}.build())
	if ev.ToolInputForAnalysis() != "" {
		t.Fatal("resource attributes fabricated a tool payload")
	}
	ev = mustMap(t, nil, recBuilder{attrs: [][]byte{kv(attrGenAIToolName, "custom"), kv(attrArguments, "FOREIGN_ALIAS")}}.build())
	if ev.ToolInputForAnalysis() != "" {
		t.Fatal("unidentified agent used a native alias")
	}
}

package hook

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestNewAgentLifecycleAndResponses(t *testing.T) {
	cases := []struct {
		agent string
		raw   string
		want  Lifecycle
	}{
		{AgentPi, "tool_call", LifecyclePreTool},
		{AgentPi, "message_end", LifecycleAssistant},
		{AgentPi, "session_shutdown", LifecycleSessionEnd},
		{AgentKimi, "PreToolUse", LifecyclePreTool},
		{AgentKimi, "PermissionResult", LifecyclePermission},
		{AgentQwen, "PostToolUseFailure", LifecyclePostTool},
		{AgentQwen, "PermissionDenied", LifecyclePermissionDenied},
		{AgentCline, "TaskResume", LifecycleSessionStart},
		{AgentCline, "tool_call", LifecyclePreTool},
		{AgentCline, "agent_error", LifecycleSessionEnd},
		{AgentCline, "TaskError", LifecycleSessionEnd},
		{AgentCline, "SessionShutdown", LifecycleSessionEnd},
		{AgentAmp, "tool.result", LifecyclePostTool},
		{AgentAmp, "agent.end", LifecycleAssistant},
		{AgentAuggie, "SessionEnd", LifecycleSessionEnd},
		{AgentKiro, "PreToolUse", LifecyclePreTool},
		{AgentKiro, "agentSpawn", LifecycleSessionStart},
		{AgentGoose, "PreToolUse", LifecyclePreTool},
		{AgentKilo, "tool.execute.before", LifecyclePreTool},
		{AgentKilo, "session.deleted", LifecycleSessionEnd},
		{AgentOpenHands, "PreToolUse", LifecyclePreTool},
		{AgentCrush, "pre_tool_use", LifecyclePreTool},
		{AgentJunie, "PreToolUse", LifecyclePreTool},
	}
	for _, tc := range cases {
		got, err := ResolveLifecycle(tc.agent, tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("ResolveLifecycle(%s, %s) = %s, %v; want %s", tc.agent, tc.raw, got, err, tc.want)
		}
	}
	if got := PassthroughResponse(AgentCline, LifecyclePreTool); got["cancel"] != false {
		t.Fatalf("Cline passthrough = %#v", got)
	}
	if got := PassthroughResponse(AgentAmp, LifecyclePreTool); got["action"] != "allow" {
		t.Fatalf("Amp passthrough = %#v", got)
	}
	if got, ok := DenyResponse(AgentPi, "blocked"); !ok || got["block"] != true {
		t.Fatalf("Pi deny = %#v, %t", got, ok)
	}
	if got, ok := DenyResponse(AgentKilo, "blocked"); !ok || got["block"] != true {
		t.Fatalf("Kilo deny = %#v, %t", got, ok)
	}
	for _, agent := range []string{AgentKimi, AgentQwen, AgentAuggie, AgentKiro, AgentGoose, AgentOpenHands, AgentCrush, AgentJunie} {
		if !DenyUsesExitCode(agent) {
			t.Errorf("%s should deny with exit 2", agent)
		}
	}
}

func TestQwenPermissionDeniedMapsFinalDecision(t *testing.T) {
	ev := Map(LifecyclePermissionDenied, AgentQwen, model.AgentQwenCode, "qwen-denied", map[string]any{
		"tool_name":   "run_shell_command",
		"tool_use_id": "toolu-qwen-1",
		"reason":      "classifier_blocked",
	})
	if ev.EventType != model.EventPermissionDenied || ev.Decision != model.DecisionDenied ||
		ev.ApprovalDecision != model.DecisionDenied || ev.ToolCallID != "toolu-qwen-1" ||
		ev.ApprovalReason != "classifier_blocked" {
		t.Fatalf("permission denial = %+v", ev)
	}
}

func TestKimiPermissionResultMapsDecisionAndJoin(t *testing.T) {
	cases := []struct {
		decision string
		wantType model.EventType
		want     string
	}{
		{"approved", model.EventPermissionApproved, model.DecisionAllowed},
		{"rejected", model.EventPermissionDenied, model.DecisionDenied},
		{"cancelled", model.EventPermissionRequested, model.DecisionAsked},
	}
	for _, tc := range cases {
		ev := Map(LifecyclePermission, AgentKimi, model.AgentKimiCode, "kimi-result", map[string]any{
			"tool_name":    "Shell",
			"tool_call_id": "toolu-kimi-1",
			"decision":     tc.decision,
		})
		if ev.EventType != tc.wantType || ev.Decision != tc.want ||
			ev.ApprovalDecision != tc.want || ev.ToolCallID != "toolu-kimi-1" {
			t.Errorf("%s permission result = %+v", tc.decision, ev)
		}
	}
}

func TestNewAgentToolMapping(t *testing.T) {
	cases := []struct {
		agent   string
		payload map[string]any
		want    model.EventType
		value   string
	}{
		{AgentPi, map[string]any{"toolName": "bash", "input": map[string]any{"command": "go test ./..."}}, model.EventCommandExec, "go test ./..."},
		{AgentKimi, map[string]any{"tool_name": "ReadFile", "tool_input": map[string]any{"path": "/tmp/a"}}, model.EventFileRead, "/tmp/a"},
		{AgentKimi, map[string]any{"tool_name": "FetchURL", "tool_input": map[string]any{"url": "https://example.com/kimi"}}, model.EventNetworkIndicator, "https://example.com/kimi"},
		{AgentQwen, map[string]any{"tool_name": "WriteFile", "tool_input": map[string]any{"file_path": "/tmp/b"}}, model.EventFileWrite, "/tmp/b"},
		{AgentCline, map[string]any{"hookName": "tool_call", "taskId": "t1", "workspaceRoots": []any{"/work"}, "preToolUse": map[string]any{"toolName": "execute_command", "parameters": map[string]any{"command": "pwd"}}}, model.EventCommandExec, "pwd"},
		{AgentAmp, map[string]any{"tool_name": "read_web_page", "tool_input": map[string]any{"url": "https://example.com"}}, model.EventNetworkIndicator, "https://example.com"},
		{AgentAuggie, map[string]any{"tool_name": "remove-files", "tool_input": map[string]any{"path": "/tmp/c"}}, model.EventFileDelete, "/tmp/c"},
		{AgentKiro, map[string]any{"tool_name": "fs_read", "tool_input": map[string]any{"operations": []any{map[string]any{"path": "/tmp/d"}}}}, model.EventFileRead, "/tmp/d"},
		{AgentGoose, map[string]any{"tool_name": "developer__shell", "tool_input": map[string]any{"command": "go test ./..."}}, model.EventCommandExec, "go test ./..."},
		{AgentGoose, map[string]any{"tool_name": "developer__write", "tool_input": map[string]any{"path": "/tmp/goose"}}, model.EventFileWrite, "/tmp/goose"},
		{AgentKilo, map[string]any{"tool_name": "bash", "tool_input": map[string]any{"command": "git status"}}, model.EventCommandExec, "git status"},
		{AgentKilo, map[string]any{"tool_name": "write", "tool_input": map[string]any{"filePath": "/tmp/kilo"}}, model.EventFileWrite, "/tmp/kilo"},
		{AgentOpenHands, map[string]any{"tool_name": "terminal", "tool_input": map[string]any{"command": "make test"}}, model.EventCommandExec, "make test"},
		{AgentCrush, map[string]any{"event": "PreToolUse", "session_id": "s1", "cwd": "/work", "tool_name": "bash", "tool_input": map[string]any{"command": "go test ./..."}}, model.EventCommandExec, "go test ./..."},
		{AgentJunie, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "go test ./..."}}, model.EventCommandExec, "go test ./..."},
	}
	for _, tc := range cases {
		source, err := ParseAgent(tc.agent)
		if err != nil {
			t.Fatal(err)
		}
		ev := Map(LifecyclePreTool, tc.agent, source, "evt", tc.payload)
		if ev.EventType != tc.want {
			t.Errorf("%s event = %s, want %s", tc.agent, ev.EventType, tc.want)
		}
		got := ev.Command
		if got == "" {
			got = ev.FilePath
		}
		if got == "" {
			got = ev.URL
		}
		if got != tc.value {
			t.Errorf("%s mapped value = %q, want %q", tc.agent, got, tc.value)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s mapped invalid event: %v", tc.agent, err)
		}
	}
}

func TestPiAssistantMessageCarriesFinalText(t *testing.T) {
	source, err := ParseAgent(AgentPi)
	if err != nil {
		t.Fatal(err)
	}
	ev := Map(LifecycleAssistant, AgentPi, source, "evt", map[string]any{"assistant_text": "Pi completed the work."})
	if ev.EventType != model.EventMessageAssistant || ev.ContentPreview != "Pi completed the work." {
		t.Fatalf("Pi assistant mapping = %+v", ev)
	}
}

func TestPiPostToolMapsResultDetails(t *testing.T) {
	source, err := ParseAgent(AgentPi)
	if err != nil {
		t.Fatal(err)
	}
	exitCode := 7
	ev := Map(LifecyclePostTool, AgentPi, source, "evt", map[string]any{
		"tool_name":   "bash",
		"tool_input":  map[string]any{"command": "false"},
		"tool_result": map[string]any{"exitCode": exitCode},
		"is_error":    true,
	})
	if ev.EventType != model.EventCommandResult || ev.Command != "false" || ev.ExitCode == nil || *ev.ExitCode != exitCode {
		t.Fatalf("Pi post-tool mapping = %+v", ev)
	}
	if len(ev.Tags) != 1 || ev.Tags[0] != model.TagToolError {
		t.Fatalf("Pi post-tool error tag = %+v", ev.Tags)
	}
}

func TestAmpFinalTextAndResultDetails(t *testing.T) {
	assistant := Map(LifecycleAssistant, AgentAmp, model.AgentAmp, "assistant", map[string]any{
		"assistant_text": "Amp completed the work.",
	})
	if assistant.EventType != model.EventMessageAssistant || assistant.ContentPreview != "Amp completed the work." {
		t.Fatalf("Amp assistant mapping = %+v", assistant)
	}

	exitCode := 7
	result := Map(LifecyclePostTool, AgentAmp, model.AgentAmp, "result", map[string]any{
		"tool_name":   "Bash",
		"tool_input":  map[string]any{"command": "false"},
		"tool_result": map[string]any{"exitCode": exitCode},
		"status":      "error",
	})
	if result.EventType != model.EventCommandResult || result.Command != "false" ||
		result.ExitCode == nil || *result.ExitCode != exitCode ||
		!containsString(result.Tags, model.TagToolError) {
		t.Fatalf("Amp result mapping = %+v", result)
	}
}

func TestJunieRejectsCallbacksNumbatDoesNotWire(t *testing.T) {
	for _, event := range []string{"PermissionRequest", "StopFailure"} {
		if _, err := ResolveLifecycle(AgentJunie, event); err == nil {
			t.Errorf("ResolveLifecycle(junie, %q) should reject an unwired callback", event)
		}
	}
}

func TestPortablePostToolFailureEventAliases(t *testing.T) {
	cases := []struct {
		agent  string
		marker map[string]any
	}{
		{AgentGoose, map[string]any{"event": "PostToolUseFailure"}},
		{AgentOpenHands, map[string]any{"event_type": "PostToolUseFailure"}},
	}
	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			payload := map[string]any{
				"tool_name":  "unknown_tool",
				"tool_input": map[string]any{},
			}
			for key, value := range tc.marker {
				payload[key] = value
			}
			ev := Map(LifecyclePostTool, tc.agent, agentModelByCLI[tc.agent], "evt", payload)
			if !containsString(ev.Tags, model.TagToolError) {
				t.Fatalf("tags = %v, want %q", ev.Tags, model.TagToolError)
			}
		})
	}
}

func TestClineCurrentToolResultPayload(t *testing.T) {
	payload := map[string]any{
		"hookName":       "tool_result",
		"taskId":         "conversation-1",
		"workspaceRoots": []any{"/work"},
		"tool_result": map[string]any{
			"id": "call-1",
		},
		"postToolUse": map[string]any{
			"toolName":        "execute_command",
			"parameters":      map[string]any{"command": "go test ./..."},
			"success":         false,
			"executionTimeMs": 125,
		},
	}
	ev := Map(LifecyclePostTool, AgentCline, model.AgentCline, "evt", payload)
	if ev.EventType != model.EventCommandResult || ev.Command != "go test ./..." {
		t.Fatalf("mapped Cline result = %#v", ev)
	}
	if ev.ToolCallID != "call-1" || ev.DurationMs == nil || *ev.DurationMs != 125 {
		t.Fatalf("Cline result identity/duration = %#v", ev)
	}
	if !containsString(ev.Tags, model.TagToolError) {
		t.Fatalf("tags = %v, want %q", ev.Tags, model.TagToolError)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

package hook

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// Field shapes below are sanitized from real `muse exec` hook captures
// (Muse Code 1.3.0), verified against docs/notes/muse-contract.md. Muse's
// hook_event_name/session_id/tool_name/tool_input/tool_use_id/cwd naming is
// byte-for-byte Claude Code's, so lifecycle resolution and most field
// resolution are free; tool_response/error being JSON-encoded strings
// (Cursor's shape class, not a nested object) is the one real decode delta.

func TestMuseLifecycleResolution(t *testing.T) {
	cases := []struct {
		raw  string
		want Lifecycle
	}{
		{"SessionStart", LifecycleSessionStart},
		{"UserPromptSubmit", LifecyclePromptSubmit},
		{"PreToolUse", LifecyclePreTool},
		{"PostToolUse", LifecyclePostTool},
		{"PostToolUseFailure", LifecyclePostTool},
		{"PermissionRequest", LifecyclePermission},
		{"SubagentStart", LifecycleSessionStart},
		{"SubagentStop", LifecycleSessionEnd},
		{"Stop", LifecycleStop},
		{"SessionEnd", LifecycleSessionEnd},
	}
	for _, tc := range cases {
		got, err := ResolveLifecycle(AgentMuse, tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("ResolveLifecycle(muse, %s) = %s, %v; want %s", tc.raw, got, err, tc.want)
		}
	}
}

func TestMuseParseAgent(t *testing.T) {
	source, err := ParseAgent(AgentMuse)
	if err != nil || source != model.AgentMuseCode {
		t.Fatalf("ParseAgent(muse) = %q, %v; want %q", source, err, model.AgentMuseCode)
	}
	if !model.IsValidSourceAgent(model.AgentMuseCode) {
		t.Fatal("model.AgentMuseCode is not in the closed source-agent set")
	}
}

func TestMuseDenyAndEnforceContract(t *testing.T) {
	// Phase 0 proved empirically (side-effect checks, not just message text)
	// that only exit 2 and Claude's exact hookSpecificOutput JSON block a
	// Muse PreToolUse call; Gemini/Cursor/Pi/OpenClaw/Cline-shaped deny
	// bodies, malformed JSON, a non-2 nonzero exit, and a killed hook all
	// fail open. Muse therefore reuses Claude's structured deny transport,
	// not the exit-code transport.
	got, ok := DenyResponse(AgentMuse, "blocked")
	if !ok {
		t.Fatal("DenyResponse(muse) reported no deny transport")
	}
	out, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok || out["permissionDecision"] != "deny" || out["permissionDecisionReason"] != "blocked" {
		t.Fatalf("muse deny response = %#v", got)
	}
	if DenyUsesExitCode(AgentMuse) {
		t.Fatal("muse should not be classified as an exit-code deny agent")
	}
	if !EnforceEligible(AgentMuse, "PreToolUse", LifecyclePreTool) {
		t.Fatal("muse PreToolUse should be enforce-eligible")
	}
	if EnforceEligible(AgentMuse, "PostToolUse", LifecyclePostTool) {
		t.Fatal("muse PostToolUse must never be enforce-eligible (post-action hooks never block)")
	}
	if got := PassthroughResponse(AgentMuse, LifecyclePreTool); len(got) != 0 {
		t.Fatalf("muse passthrough = %#v, want empty (no native allow spelling observed)", got)
	}
}

func TestMuseToolMapping(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    model.EventType
		value   string
	}{
		{
			name: "bash pre-tool becomes command.exec",
			payload: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "bash",
				"tool_input": map[string]any{
					"command":     "echo hook-test-1",
					"description": "Echo hook test string",
					"workdir":     "/work",
				},
				"tool_use_id": "call_1",
				"session_id":  "sess-1",
				"cwd":         "/work",
			},
			want:  model.EventCommandExec,
			value: "echo hook-test-1",
		},
		{
			name: "read_file uses the path field",
			payload: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "read_file",
				"tool_input":      map[string]any{"path": "sample.txt"},
				"tool_use_id":     "call_2",
				"session_id":      "sess-1",
			},
			want:  model.EventFileRead,
			value: "sample.txt",
		},
		{
			name: "write_file uses the path field, content is not copied",
			payload: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "write_file",
				"tool_input":      map[string]any{"path": "output.txt", "content": "edited content"},
				"tool_use_id":     "call_3",
				"session_id":      "sess-1",
			},
			want:  model.EventFileWrite,
			value: "output.txt",
		},
		{
			name: "unconfirmed/bookkeeping tools stay generic, never fabricated as shell or file",
			payload: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "submit_reminder_decision",
				"tool_input":      map[string]any{"decision": "none", "reason": "no skill trigger matched"},
				"tool_use_id":     "call_4",
				"session_id":      "sess-2",
			},
			want:  model.EventToolCall,
			value: "",
		},
		{
			name: "subagent_spawn stays generic; lineage join is a separate, stateful concern",
			payload: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "subagent_spawn",
				"tool_input":      map[string]any{"command_id": "spawn-1", "objective": "run a command", "role": "worker"},
				"tool_use_id":     "call_5",
				"session_id":      "sess-1",
			},
			want:  model.EventToolCall,
			value: "",
		},
	}
	for _, tc := range cases {
		ev := Map(LifecyclePreTool, AgentMuse, model.AgentMuseCode, "evt", tc.payload)
		if ev.EventType != tc.want {
			t.Errorf("%s: event = %s, want %s", tc.name, ev.EventType, tc.want)
		}
		got := ev.Command
		if got == "" {
			got = ev.FilePath
		}
		if got != tc.value {
			t.Errorf("%s: mapped value = %q, want %q", tc.name, got, tc.value)
		}
		if ev.SourceAgent != model.AgentMuseCode || ev.SourceType != model.SourceHook {
			t.Errorf("%s: source_agent/source_type = %q/%q", tc.name, ev.SourceAgent, ev.SourceType)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: mapped invalid event: %v", tc.name, err)
		}
	}
}

// TestMusePostToolExitCodeFromJSONStringResponse proves the decode delta from
// every other Claude-shaped portable agent: tool_response is a JSON-encoded
// string, not a nested object (Cursor's tool_output shape class), and
// resolver.museToolResponse must decode it for exitCode()/durationMs() to see
// the exit_code Muse actually reports.
func TestMusePostToolExitCodeFromJSONStringResponse(t *testing.T) {
	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "bash",
		"tool_input":      map[string]any{"command": "echo hook-test-1", "workdir": "/work"},
		"tool_response":   `{"chunk_id":"exec-1-1","command":"echo hook-test-1","exit_code":0,"terminal_status":"completed","output":"hook-test-1\n"}`,
		"tool_use_id":     "call_1",
		"session_id":      "sess-1",
	}
	ev := Map(LifecyclePostTool, AgentMuse, model.AgentMuseCode, "evt", payload)
	if ev.EventType != model.EventCommandResult {
		t.Fatalf("event = %s, want %s", ev.EventType, model.EventCommandResult)
	}
	if ev.ExitCode == nil || *ev.ExitCode != 0 {
		t.Fatalf("exit code = %v, want 0", ev.ExitCode)
	}
	for _, tag := range ev.Tags {
		if tag == model.TagToolError {
			t.Fatal("clean exit 0 must not carry tool_error")
		}
	}
}

// TestMusePostToolUseFailureIsToolError proves the empirical finding that
// PostToolUseFailure fires for a plain nonzero shell exit code (not only a
// tool-invocation crash), and that the failing command's exit_code is still
// recoverable from the JSON-encoded `error` string.
func TestMusePostToolUseFailureIsToolError(t *testing.T) {
	payload := map[string]any{
		"hook_event_name": "PostToolUseFailure",
		"tool_name":       "bash",
		"tool_input":      map[string]any{"command": "false", "workdir": "/work"},
		"error":           `{"chunk_id":"exec-1-1","command":"false","exit_code":1,"terminal_status":"failed","terminal_reason":"process exited with status 1"}`,
		"is_interrupt":    false,
		"duration_ms":     21,
		"tool_use_id":     "call_6",
		"session_id":      "sess-1",
	}
	ev := Map(LifecyclePostTool, AgentMuse, model.AgentMuseCode, "evt", payload)
	if ev.EventType != model.EventCommandResult {
		t.Fatalf("event = %s, want %s", ev.EventType, model.EventCommandResult)
	}
	if ev.ExitCode == nil || *ev.ExitCode != 1 {
		t.Fatalf("exit code = %v, want 1", ev.ExitCode)
	}
	if ev.DurationMs == nil || *ev.DurationMs != 21 {
		t.Fatalf("duration_ms = %v, want 21", ev.DurationMs)
	}
	found := false
	for _, tag := range ev.Tags {
		if tag == model.TagToolError {
			found = true
		}
	}
	if !found {
		t.Fatal("PostToolUseFailure must carry tool_error")
	}
}

// TestMuseSubagentStartUsesChildSessionAndSubAgentID matches the same
// modeling numbat already uses for Kimi/Qwen: a subagent lifecycle boundary
// is a session.start/session.end for the child's OWN session id, with
// SubAgent naming which subagent it is. Full parent/child lineage
// reconstruction is a separate, stateful concern (see
// docs/notes/muse-contract.md) and is intentionally not attempted here.
func TestMuseSubagentStartUsesChildSessionAndSubAgentID(t *testing.T) {
	payload := map[string]any{
		"hook_event_name":  "SubagentStart",
		"subagent_id":      "skill-reminder",
		"child_session_id": "child-sess-1",
		"session_id":       "child-sess-1",
		"turn_id":          "child-sess-1",
		"cwd":              "/work",
	}
	ev := Map(LifecycleSessionStart, AgentMuse, model.AgentMuseCode, "evt", payload)
	if ev.EventType != model.EventSessionStart {
		t.Fatalf("event = %s, want %s", ev.EventType, model.EventSessionStart)
	}
	if ev.SessionID != "child-sess-1" {
		t.Fatalf("session_id = %q, want child-sess-1", ev.SessionID)
	}
	if ev.SubAgent != "skill-reminder" {
		t.Fatalf("sub_agent = %q, want skill-reminder", ev.SubAgent)
	}
}

// TestMuseStopCapturesAssistantText matches the same last_assistant_message
// field name and semantics numbat already maps for Claude Code and Codex.
func TestMuseStopCapturesAssistantText(t *testing.T) {
	payload := map[string]any{
		"hook_event_name":        "Stop",
		"stop_hook_active":       false,
		"last_assistant_message": "Done. Output: `hook-test-1`.",
		"session_id":             "sess-1",
		"turn_id":                "turn-1",
	}
	ev := Map(LifecycleStop, AgentMuse, model.AgentMuseCode, "evt", payload)
	if ev.EventType != model.EventMessageAssistant {
		t.Fatalf("event = %s, want %s", ev.EventType, model.EventMessageAssistant)
	}
	if ev.ContentPreview == "" {
		t.Fatal("expected a non-empty content preview from last_assistant_message")
	}
}

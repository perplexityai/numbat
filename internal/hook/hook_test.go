package hook

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

const testDiffSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPreviewDoesNotCutToken(t *testing.T) {
	input := "prefix " + strings.Repeat("x", previewMax+1)
	if got := preview(input); got != "prefix" {
		t.Fatalf("preview = %q, want complete prefix token", got)
	}
}

// every hook-sourced event must be stamped source_type=hook and confidence
// medium, with a thin hook evidence record that never fabricates a file/line —
// the honesty constraint for live signals.
func assertHookProvenance(t *testing.T, ev model.Event) {
	t.Helper()
	if ev.SourceType != model.SourceHook {
		t.Errorf("source_type = %q, want %q", ev.SourceType, model.SourceHook)
	}
	if ev.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", ev.SchemaVersion, model.SchemaVersion)
	}
	if ev.Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", ev.Confidence)
	}
	if ev.Evidence.ArtifactType != "hook" {
		t.Errorf("evidence.artifact_type = %q, want hook", ev.Evidence.ArtifactType)
	}
	if ev.Evidence.LocalPath != "" {
		t.Errorf("hook evidence must not fabricate a local artifact path: %+v", ev.Evidence)
	}
	if ev.Evidence.Line != 0 || ev.Evidence.SHA256 != "" {
		t.Errorf("hook evidence must not fabricate line/hash: %+v", ev.Evidence)
	}
}

func TestParseLifecycle(t *testing.T) {
	for _, s := range []string{"session-start", "prompt-submit", "pre-tool", "post-tool", "permission-request", "permission-denied", "stop", "session-end"} {
		if _, err := ParseLifecycle(s); err != nil {
			t.Errorf("ParseLifecycle(%q) errored: %v", s, err)
		}
	}
	if _, err := ParseLifecycle("nope"); err == nil {
		t.Error("ParseLifecycle(nope) should error")
	}
}

func TestResolveClaudeEvents(t *testing.T) {
	cases := map[string]Lifecycle{
		"SessionStart":       LifecycleSessionStart,
		"UserPromptSubmit":   LifecyclePromptSubmit,
		"PreToolUse":         LifecyclePreTool,
		"PostToolUse":        LifecyclePostTool,
		"PostToolUseFailure": LifecyclePostTool,
		"PermissionRequest":  LifecyclePermission,
		"PermissionDenied":   LifecyclePermissionDenied,
		"SubagentStart":      LifecycleSessionStart,
		"SubagentStop":       LifecycleSessionEnd,
		"Stop":               LifecycleStop,
		"SessionEnd":         LifecycleSessionEnd,
		"permission-denied":  LifecyclePermissionDenied,
		"session-start":      LifecycleSessionStart,
	}
	for raw, want := range cases {
		got, err := ResolveLifecycle(AgentClaude, raw)
		if err != nil || got != want {
			t.Errorf("ResolveLifecycle(claude, %q) = %q,%v want %q", raw, got, err, want)
		}
	}
	if _, err := ResolveLifecycle(AgentClaude, "PermissionDeniedV2"); err == nil {
		t.Fatal("near-miss Claude hook event should fail")
	}
}

func TestParseAgent(t *testing.T) {
	cases := map[string]string{
		AgentClaude: model.AgentClaudeCode,
		AgentCodex:  model.AgentCodex,
		AgentGemini: model.AgentGeminiCLI,
	}
	for in, want := range cases {
		got, err := ParseAgent(in)
		if err != nil || got != want {
			t.Errorf("ParseAgent(%q) = %q,%v want %q", in, got, err, want)
		}
	}
	if _, err := ParseAgent("vim"); err == nil {
		t.Error("ParseAgent(vim) should error")
	}
}

func TestPassthroughResponseIsInert(t *testing.T) {
	for _, a := range []string{AgentClaude, AgentCodex, AgentGemini, "unknown"} {
		resp := PassthroughResponse(a, LifecyclePreTool)
		if len(resp) != 0 {
			t.Errorf("PassthroughResponse(%q) = %v, want empty object", a, resp)
		}
	}
	// A fresh map each call: mutating one must not affect the next.
	r := PassthroughResponse(AgentClaude, LifecyclePreTool)
	r["x"] = 1
	if len(PassthroughResponse(AgentClaude, LifecyclePreTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}

func TestEnforceEligibleOnlyBlockingPreToolEvents(t *testing.T) {
	tests := []struct {
		agent string
		event string
		lc    Lifecycle
		want  bool
	}{
		{AgentClaude, "PreToolUse", LifecyclePreTool, true},
		{AgentCodex, "PreToolUse", LifecycleCodexPreTool, true},
		{AgentCopilot, "PreToolUse", LifecycleCopilotPreTool, true},
		{AgentGemini, "BeforeTool", LifecycleGeminiPreTool, true},
		{AgentFactory, "PreToolUse", LifecycleFactoryPreTool, true},
		{AgentGrok, "PreToolUse", LifecycleGrokPreTool, true},
		{AgentDevin, "PreToolUse", LifecycleDevinPreTool, true},
		{AgentHermes, "pre_tool_call", LifecycleHermesPreTool, true},
		{AgentWindsurf, "pre_read_code", LifecycleFileRead, true},
		{AgentWindsurf, "pre_write_code", LifecycleFileWrite, true},
		{AgentWindsurf, "pre_run_command", LifecycleCommandExec, true},
		{AgentWindsurf, "pre_mcp_tool_use", LifecycleMCPCall, true},
		{AgentWindsurf, "post_read_code", LifecycleFileRead, false},
		{AgentWindsurf, "post_write_code", LifecycleFileWrite, false},
		{AgentWindsurf, "post_mcp_tool_use", LifecycleMCPCall, false},
		// Specialized Cursor events remain eligible for manual configs. Current
		// installs also use beforeReadFile as the canonical file-read gate.
		{AgentCursor, "beforeShellExecution", LifecycleCommandExec, true},
		{AgentCursor, "beforeMCPExecution", LifecycleMCPCall, true},
		{AgentCursor, "beforeReadFile", LifecycleFileRead, true},
		{AgentCursor, "preToolUse", LifecycleCursorPreTool, true},
		{AgentCursor, "postToolUse", LifecycleCursorPostTool, false},
		{AgentCursor, "postToolUseFailure", LifecycleCursorPostToolFailure, false},
		// Cursor currently ignores deny responses from subagentStart. Keep the
		// event for monitoring, but never advertise it as a control point.
		{AgentCursor, "subagentStart", LifecycleSessionStart, false},
		{AgentCursor, "afterShellExecution", LifecycleCommandResult, false},
		{AgentOpenCode, "opencode-pre-tool", LifecycleOpenCodePreTool, false},
		{AgentAntigravity, "PreToolUse", LifecycleAntigravityPreTool, true},
	}
	for _, tc := range tests {
		if got := EnforceEligible(tc.agent, tc.event, tc.lc); got != tc.want {
			t.Errorf("EnforceEligible(%q, %q, %q) = %v, want %v", tc.agent, tc.event, tc.lc, got, tc.want)
		}
	}
}

func TestDenyResponseContracts(t *testing.T) {
	for _, agent := range []string{
		AgentClaude, AgentCodex, AgentCursor, AgentCopilot, AgentVSCode, AgentGemini,
		AgentFactory, AgentGrok, AgentDevin, AgentHermes,
	} {
		response, ok := DenyResponse(agent, "reason")
		if !ok || len(response) == 0 {
			t.Errorf("DenyResponse(%q) = %v, %v", agent, response, ok)
		}
	}
	if response, ok := DenyResponse(AgentWindsurf, "reason"); ok || response != nil {
		t.Fatalf("Windsurf structured response = %v, %v; want nil, false", response, ok)
	}
	if !DenyUsesExitCode(AgentWindsurf) || DenyUsesExitCode(AgentClaude) {
		t.Fatal("exit-code deny classification is incorrect")
	}
	copilot, _ := DenyResponse(AgentCopilot, "reason")
	if _, ok := copilot["hookSpecificOutput"]; ok {
		t.Fatal("Copilot deny contains VS Code response fields")
	}
	vscode, _ := DenyResponse(AgentVSCode, "reason")
	if _, ok := vscode["permissionDecision"]; ok {
		t.Fatal("VS Code deny contains Copilot CLI response fields")
	}
}

func TestEnforcementCapabilityHasExactlyOneDenyTransport(t *testing.T) {
	for _, agent := range AgentNames() {
		_, structured := DenyResponse(agent, "reason")
		exitCode := DenyUsesExitCode(agent)
		if AgentSupportsEnforcement(agent) {
			if structured == exitCode {
				t.Errorf("%s: enforce-capable agent has structured=%v exit-code=%v; want exactly one transport", agent, structured, exitCode)
			}
			continue
		}
		if structured || exitCode {
			t.Errorf("%s: observe-only agent unexpectedly has a deny transport", agent)
		}
	}
}

// Map covers each lifecycle moment: the right event_type, the right resolved
// fields, and hook provenance throughout. The payloads mix per-agent key
// spellings to exercise the resolver fallbacks.
func TestMapLifecycles(t *testing.T) {
	const eventID = "hook-run-1"

	tests := []struct {
		name    string
		lc      Lifecycle
		agent   string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name:    "session start",
			lc:      LifecycleSessionStart,
			agent:   AgentClaude,
			payload: map[string]any{"session_id": "s1", "cwd": "/proj", "model": "claude-x"},
			want:    model.EventSessionStart,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorSystem {
					t.Errorf("actor = %q, want system", ev.Actor)
				}
				if ev.SessionID != "s1" || ev.ProjectPath != "/proj" {
					t.Errorf("session/cwd not resolved: %+v", ev)
				}
				if ev.Model != "claude-x" {
					t.Errorf("model = %q, want claude-x", ev.Model)
				}
			},
		},
		{
			name:    "prompt submit",
			lc:      LifecyclePromptSubmit,
			agent:   AgentGemini,
			payload: map[string]any{"sessionId": "s2", "userPrompt": "  read   the env  "},
			want:    model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorUser {
					t.Errorf("actor = %q, want user", ev.Actor)
				}
				if ev.ContentPreview != "read the env" {
					t.Errorf("preview = %q, want collapsed whitespace", ev.ContentPreview)
				}
			},
		},
		{
			name:    "pre-tool bash",
			lc:      LifecyclePreTool,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "cat .env"}, "model": "claude-x", "model_provider": "anthropic", "agent_name": "security-reviewer"},
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" {
					t.Errorf("command = %q", ev.Command)
				}
				if ev.Model != "claude-x" || ev.ModelProvider != "anthropic" {
					t.Errorf("model context = %q/%q, want claude-x/anthropic", ev.Model, ev.ModelProvider)
				}
				if ev.SubAgent != "security-reviewer" {
					t.Errorf("sub_agent = %q, want security-reviewer", ev.SubAgent)
				}
			},
		},
		{
			name:    "pre-tool read with json-string input",
			lc:      LifecyclePreTool,
			agent:   AgentCodex,
			payload: map[string]any{"toolName": "Read", "toolInput": `{"file_path":"/p/.env"}`},
			want:    model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/p/.env" {
					t.Errorf("file_path = %q, want /p/.env (json-string input)", ev.FilePath)
				}
			},
		},
		{
			name:    "pre-tool webfetch tags network",
			lc:      LifecyclePreTool,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "WebFetch", "tool_input": map[string]any{"url": "https://evil.example/x"}},
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "https://evil.example/x" {
					t.Errorf("url = %q", ev.URL)
				}
				if len(ev.Tags) == 0 || ev.Tags[0] != model.TagNetwork {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		{
			// Regression: a non-http(s) WebFetch url must NOT be promoted
			// into Event.URL; it stays visible in ContentPreview, the event stays a
			// network.indicator tagged network.
			name:    "pre-tool webfetch rejects non-http url",
			lc:      LifecyclePreTool,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "WebFetch", "tool_input": map[string]any{"url": "file:///etc/passwd"}},
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "" {
					t.Errorf("url = %q, want empty (non-http(s) must not be promoted)", ev.URL)
				}
				if ev.ContentPreview != "file:///etc/passwd" {
					t.Errorf("content_preview = %q, want the raw value preserved", ev.ContentPreview)
				}
				if len(ev.Tags) == 0 || ev.Tags[0] != model.TagNetwork {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		{
			// Regression: a fractional exit_code must NOT be truncated
			// into a fabricated integer; ExitCode stays nil (absent).
			name:  "post-tool fractional exit code is not fabricated",
			lc:    LifecyclePostTool,
			agent: AgentClaude,
			payload: map[string]any{
				"tool_name":     "Bash",
				"tool_input":    map[string]any{"command": "ls"},
				"tool_response": map[string]any{"exit_code": float64(1.7)},
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ExitCode != nil {
					t.Errorf("exit_code = %v, want nil (fractional must not be truncated)", *ev.ExitCode)
				}
			},
		},
		{
			name:    "pre-tool mcp tool splits server/tool",
			lc:      LifecyclePreTool,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "mcp__github__create_issue", "tool_input": map[string]any{}},
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
			},
		},
		{
			name:  "post-tool bash carries exit code and duration",
			lc:    LifecyclePostTool,
			agent: AgentClaude,
			payload: map[string]any{
				"tool_name":     "Bash",
				"tool_use_id":   "tool-result-1",
				"tool_input":    map[string]any{"command": "ls"},
				"tool_response": map[string]any{"exit_code": float64(2), "duration_ms": float64(125)},
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ExitCode == nil || *ev.ExitCode != 2 {
					t.Errorf("exit_code = %v, want 2", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 125 {
					t.Errorf("duration_ms = %v, want 125", ev.DurationMs)
				}
				if ev.ToolCallID != "tool-result-1" {
					t.Errorf("tool_call_id = %q", ev.ToolCallID)
				}
			},
		},
		{
			name:  "post-tool file edit becomes tool.result with tool_error",
			lc:    LifecyclePostTool,
			agent: AgentClaude,
			payload: map[string]any{
				"tool_name":     "Edit",
				"tool_input":    map[string]any{"file_path": "/p/x.go"},
				"tool_response": map[string]any{"diff_sha256": testDiffSHA256, "diff_bytes": float64(42), "is_error": true},
			},
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" || ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result repeated action fields: %+v", ev)
				}
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error", ev.Tags)
				}
			},
		},
		{
			name:    "permission denied",
			lc:      LifecyclePermission,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "Bash", "tool_use_id": "tool-permission-1", "decision": "deny", "reason": "blocked by policy"},
			want:    model.EventPermissionDenied,
			check: func(t *testing.T, ev model.Event) {
				if ev.ApprovalRequired == nil || !*ev.ApprovalRequired {
					t.Errorf("approval_required = %v, want true", ev.ApprovalRequired)
				}
				if ev.ApprovalDecision != model.DecisionDenied {
					t.Errorf("approval_decision = %q, want denied", ev.ApprovalDecision)
				}
				if ev.ApprovalReason != "blocked by policy" {
					t.Errorf("approval_reason = %q", ev.ApprovalReason)
				}
				if ev.ToolCallID != "tool-permission-1" {
					t.Errorf("tool_call_id = %q", ev.ToolCallID)
				}
			},
		},
		{
			name:    "permission open request when no decision",
			lc:      LifecyclePermission,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "Write"},
			want:    model.EventPermissionRequested,
			check: func(t *testing.T, ev model.Event) {
				if ev.ApprovalDecision != model.DecisionAsked {
					t.Errorf("approval_decision = %q, want asked", ev.ApprovalDecision)
				}
			},
		},
		{
			name:    "permission denied lifecycle",
			lc:      LifecyclePermissionDenied,
			agent:   AgentClaude,
			payload: map[string]any{"tool_name": "Bash", "reason": "auto mode denied"},
			want:    model.EventPermissionDenied,
			check: func(t *testing.T, ev model.Event) {
				if ev.ApprovalRequired == nil || !*ev.ApprovalRequired {
					t.Errorf("approval_required = %v, want true", ev.ApprovalRequired)
				}
				if ev.Decision != model.DecisionDenied || ev.ApprovalDecision != model.DecisionDenied {
					t.Errorf("decision = %q/%q, want denied", ev.Decision, ev.ApprovalDecision)
				}
				if ev.ApprovalReason != "auto mode denied" {
					t.Errorf("approval_reason = %q", ev.ApprovalReason)
				}
			},
		},
		{
			name:    "stop ends assistant turn",
			lc:      LifecycleStop,
			agent:   AgentClaude,
			payload: map[string]any{"session_id": "s3"},
			want:    model.EventMessageAssistant,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorAssistant {
					t.Errorf("actor = %q, want assistant", ev.Actor)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sourceAgent, _ := ParseAgent(tc.agent)
			ev := Map(tc.lc, tc.agent, sourceAgent, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Errorf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.EventID != eventID {
				t.Errorf("event_id = %q, want %q", ev.EventID, eventID)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped hook event failed Validate: %v", err)
			}
			assertHookProvenance(t, ev)
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

// The events the real post-tool mapper produces must satisfy the model
// contract. The event_contract tests assert hand-built command.result and
// tool.result events pass Validate(); this closes the seam by running the
// actual mapper (Map → mapPostTool) on representative post-tool payloads and
// asserting the resulting event validates — proving the fields the mapper
// stamps (command+tool_name on a Bash result, tool_name+mcp_server+mcp_tool on
// an MCP result) are exactly the ones the allow-list admits.
func TestMapPostToolEventsSatisfyContract(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name: "bash command.result",
			payload: map[string]any{
				"tool_name":     "Bash",
				"tool_input":    map[string]any{"command": "go test ./..."},
				"tool_response": map[string]any{"exit_code": float64(0), "duration_ms": float64(1500)},
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "go test ./..." || ev.ToolName != "Bash" {
					t.Errorf("command/tool_name = %q/%q, want \"go test ./...\"/Bash", ev.Command, ev.ToolName)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 0 {
					t.Errorf("exit_code = %v, want 0", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 1500 {
					t.Errorf("duration_ms = %v, want 1500", ev.DurationMs)
				}
			},
		},
		{
			name: "mcp tool.result",
			payload: map[string]any{
				"tool_name":     "mcp__github__create_issue",
				"tool_input":    map[string]any{},
				"tool_response": map[string]any{},
			},
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "mcp__github__create_issue" {
					t.Errorf("tool_name = %q, want mcp__github__create_issue", ev.ToolName)
				}
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(LifecyclePostTool, AgentClaude, model.AgentClaudeCode, "hook-pt", tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			tc.check(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapper-produced %q event failed Validate: %v", ev.EventType, err)
			}
		})
	}
}

// An empty payload must still yield a well-formed event so the hook command
// never fails the agent on a malformed body.
func TestMapEmptyPayloadIsWellFormed(t *testing.T) {
	ev := Map(LifecyclePreTool, AgentClaude, model.AgentClaudeCode, "hook-x", map[string]any{})
	assertHookProvenance(t, ev)
	if ev.EventType != model.EventToolCall {
		t.Errorf("empty pre-tool event_type = %q, want tool.call", ev.EventType)
	}
}

func TestHookNetworkTargetURLRequiresHostname(t *testing.T) {
	if got := hookNetworkTargetURL("https://:443/path"); got != "" {
		t.Fatalf("hostless URL accepted as %q", got)
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

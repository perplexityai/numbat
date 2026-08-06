package hook

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// ResolveLifecycle maps Cursor's current generic hook names and the specialized
// names retained for existing manual configurations. Matching is exact apart
// from case and explicitly listed historical aliases.
func TestResolveCursorLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		// Current generic names and supported specialized compatibility names.
		{"beforeSubmitPrompt", LifecyclePromptSubmit},
		{"preToolUse", LifecycleCursorPreTool},
		{"postToolUse", LifecycleCursorPostTool},
		{"postToolUseFailure", LifecycleCursorPostToolFailure},
		{"beforeShellExecution", LifecycleCommandExec},
		{"beforeMCPExecution", LifecycleMCPCall},
		{"beforeReadFile", LifecycleFileRead},
		{"afterFileEdit", LifecycleFileWrite},
		{"stop", LifecycleStop},
		// Observed variant spellings must resolve to the same moments.
		{"beforeShellCommand", LifecycleCommandExec},
		{"afterShellCommand", LifecycleCommandResult},
		{"beforeFileWrite", LifecycleFileWrite},
		{"afterFileWrite", LifecycleFileWrite},
		{"pre_user_prompt", LifecyclePromptSubmit},
		// Case-insensitivity.
		{"BEFOREreadFILE", LifecycleFileRead},
		{"AfterMcpExecution", LifecycleMCPCall},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentCursor, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(cursor, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(cursor, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	if _, err := ResolveLifecycle(AgentCursor, "workspaceOpen"); err == nil {
		t.Error("ResolveLifecycle(cursor, workspaceOpen) should error: no activity moment matches")
	}
	// A non-cursor agent still routes through the exact ParseLifecycle path.
	if _, err := ResolveLifecycle(AgentClaude, "beforeShellExecution"); err == nil {
		t.Error("ResolveLifecycle(claude, beforeShellExecution) should error: claude takes exact lifecycle names")
	}
	if lc, err := ResolveLifecycle(AgentClaude, "pre-tool"); err != nil || lc != LifecyclePreTool {
		t.Errorf("ResolveLifecycle(claude, pre-tool) = %q,%v want pre-tool", lc, err)
	}
}

// Map must turn each Cursor event's stdin payload into the right model.Event
// type with its key fields resolved, exercising the real resolve→map path with
// realistic payloads. Both spelling variants are covered for the shell and file
// moments. Every mapped event must also satisfy the model field co-occurrence
// contract (Validate), proving the mapper only sets fields the event_type admits.
func TestMapCursorEvents(t *testing.T) {
	const eventID = "hook-cursor-1"

	tests := []struct {
		name    string
		event   string // raw Cursor event name
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name:  "preToolUse write maps before action",
			event: "preToolUse",
			payload: map[string]any{
				"tool_name":  "Write",
				"tool_input": map[string]any{"file_path": `C:Usersdev.sshauthorized_keys`},
			},
			want: model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != `C:Usersdev.sshauthorized_keys` {
					t.Errorf("file_path = %q", ev.FilePath)
				}
			},
		},
		{
			name:  "preToolUse ReadFile maps before action",
			event: "preToolUse",
			payload: map[string]any{
				"tool_name":  "ReadFile",
				"tool_input": map[string]any{"path": "/proj/.env"},
			},
			want: model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/.env" || ev.ToolName != "ReadFile" {
					t.Errorf("mapped ReadFile = path %q, tool %q", ev.FilePath, ev.ToolName)
				}
			},
		},
		{
			name:  "preToolUse StrReplace maps before action",
			event: "preToolUse",
			payload: map[string]any{
				"tool_name": "StrReplace",
				"tool_input": map[string]any{
					"path":       "/proj/main.go",
					"old_string": "before",
					"new_string": "after",
				},
			},
			want: model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/main.go" || ev.ToolName != "StrReplace" {
					t.Errorf("mapped StrReplace = path %q, tool %q", ev.FilePath, ev.ToolName)
				}
			},
		},
		{
			name:  "preToolUse shell maps command and correlation",
			event: "preToolUse",
			payload: map[string]any{
				"tool_name":   "Shell",
				"tool_input":  map[string]any{"command": "cat .env"},
				"tool_use_id": "tool-shell-1",
				"cwd":         "/proj",
			},
			want: model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" || ev.ToolCallID != "tool-shell-1" {
					t.Errorf("command/call id = %q/%q", ev.Command, ev.ToolCallID)
				}
			},
		},
		{
			name:  "preToolUse MCP maps documented tool spelling",
			event: "preToolUse",
			payload: map[string]any{
				"tool_name":   "MCP:create_issue",
				"tool_input":  map[string]any{"title": "x"},
				"tool_use_id": "tool-mcp-1",
			},
			want: model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "MCP:create_issue" || ev.MCPServer != "" || ev.MCPTool != "create_issue" {
					t.Errorf("tool/MCP fields = %q/%q/%q", ev.ToolName, ev.MCPServer, ev.MCPTool)
				}
			},
		},
		{
			name:  "postToolUse shell maps structured result",
			event: "postToolUse",
			payload: map[string]any{
				"tool_name":   "Shell",
				"tool_input":  map[string]any{"command": "npm test"},
				"tool_output": `{"exitCode":1,"stdout":"failed"}`,
				"tool_use_id": "tool-shell-2",
				"duration":    float64(5432),
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "npm test" || ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("command/exit = %q/%v", ev.Command, ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 5432 || ev.ToolCallID != "tool-shell-2" {
					t.Errorf("duration/call id = %v/%q", ev.DurationMs, ev.ToolCallID)
				}
				if ev.ContentPreview != "" {
					t.Errorf("tool output leaked into content_preview: %q", ev.ContentPreview)
				}
			},
		},
		{
			name:  "postToolUse MCP maps generic tool result",
			event: "postToolUse",
			payload: map[string]any{
				"tool_name":   "MCP:create_issue",
				"tool_input":  map[string]any{"title": "x"},
				"tool_output": `{"content":[{"type":"text","text":"created"}]}`,
				"tool_use_id": "tool-mcp-2",
			},
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "" || ev.MCPTool != "create_issue" || ev.ToolCallID != "tool-mcp-2" {
					t.Errorf("MCP result fields = %q/%q/%q", ev.MCPServer, ev.MCPTool, ev.ToolCallID)
				}
			},
		},
		{
			name:  "postToolUseFailure retains explicit failure",
			event: "postToolUseFailure",
			payload: map[string]any{
				"tool_name":     "Read",
				"tool_input":    map[string]any{"file_path": "/proj/.env"},
				"tool_use_id":   "tool-read-1",
				"error_message": "not allowed",
				"failure_type":  "permission_denied",
				"duration":      float64(12),
				"is_interrupt":  false,
			},
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) || ev.Decision != model.DecisionDenied {
					t.Errorf("failure tags/decision = %v/%q", ev.Tags, ev.Decision)
				}
				if ev.ToolName != "Read" || ev.ToolCallID != "tool-read-1" || ev.ContentPreview != "" {
					t.Errorf("failure identity/content = %q/%q/%q", ev.ToolName, ev.ToolCallID, ev.ContentPreview)
				}
			},
		},
		{
			name:  "beforeSubmitPrompt → prompt.user with attachments folded in",
			event: "beforeSubmitPrompt",
			payload: map[string]any{
				"conversation_id": "c1",
				"generation_id":   "g1",
				"prompt":          "read the   env file",
				"attachments": []any{
					map[string]any{"type": "file", "file_path": "/proj/.env"},
					map[string]any{"type": "file", "file_path": "/proj/main.go"},
				},
				"workspace_roots": []any{"/proj"},
			},
			want: model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorUser {
					t.Errorf("actor = %q, want user", ev.Actor)
				}
				if ev.SessionID != "c1" {
					t.Errorf("session_id = %q, want c1 (conversation_id)", ev.SessionID)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want first workspace_roots entry", ev.ProjectPath)
				}
				// The prompt is collapsed and the attachment paths are appended so
				// the references are visible without a dedicated field.
				want := "read the env file [attachments: /proj/.env /proj/main.go]"
				if ev.ContentPreview != want {
					t.Errorf("content_preview = %q, want %q", ev.ContentPreview, want)
				}
			},
		},
		{
			name:  "subagentStart maps child context",
			event: "subagentStart",
			payload: map[string]any{
				"conversation_id": "parent-session",
				"model":           "parent-model",
				"subagent_id":     "opaque-child-id",
				"subagent_type":   "reviewer",
				"subagent_model":  "child-model",
				"workspace_roots": []any{"/proj", "/other"},
				"git_branch":      "feature/hooks",
			},
			want: model.EventSessionStart,
			check: func(t *testing.T, ev model.Event) {
				if ev.SubAgent != "reviewer" || ev.Model != "child-model" {
					t.Errorf("subagent/model = %q/%q, want reviewer/child-model", ev.SubAgent, ev.Model)
				}
				if ev.ProjectPath != "/proj" || ev.GitBranch != "feature/hooks" {
					t.Errorf("project/branch = %q/%q", ev.ProjectPath, ev.GitBranch)
				}
			},
		},
		{
			name:  "subagentStop retains documented type",
			event: "subagentStop",
			payload: map[string]any{
				"conversation_id": "parent-session",
				"subagent_type":   "reviewer",
				"workspace_roots": []any{"/proj"},
			},
			want: model.EventSessionEnd,
			check: func(t *testing.T, ev model.Event) {
				if ev.SubAgent != "reviewer" || ev.ProjectPath != "/proj" {
					t.Errorf("subagent/project = %q/%q", ev.SubAgent, ev.ProjectPath)
				}
			},
		},
		{
			name:  "beforeShellExecution → command.exec",
			event: "beforeShellExecution",
			payload: map[string]any{
				"conversation_id": "c1",
				"command":         "cat .env",
				"cwd":             "/proj",
			},
			want: model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" {
					t.Errorf("command = %q, want cat .env", ev.Command)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want /proj (cwd)", ev.ProjectPath)
				}
			},
		},
		{
			name:  "afterShellCommand (variant) → command.result with exit/duration",
			event: "afterShellCommand",
			payload: map[string]any{
				"commandLine": "ls -la",
				"exit_code":   float64(1),
				"duration_ms": float64(42),
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "ls -la" {
					t.Errorf("command = %q, want ls -la (commandLine fallback)", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 42 {
					t.Errorf("duration_ms = %v, want 42", ev.DurationMs)
				}
			},
		},
		{
			name:  "afterShellCommand with explicit error → tool_error tag",
			event: "afterShellCommand",
			payload: map[string]any{
				"command": "false",
				"error":   "command failed",
			},
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error (explicit error field)", ev.Tags)
				}
			},
		},
		{
			name:  "beforeMCPExecution → tool.call splits server/tool",
			event: "beforeMCPExecution",
			payload: map[string]any{
				"server":     "github",
				"tool_name":  "create_issue",
				"tool_input": `{"title":"x"}`,
				"command":    "github-mcp",
			},
			want: model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
				if ev.ToolName != "create_issue" {
					t.Errorf("tool_name = %q, want create_issue", ev.ToolName)
				}
				// tool.call does not admit a command field; the MCP command text must
				// not be stored on it.
				if ev.Command != "" {
					t.Errorf("command = %q, want empty (tool.call admits no command)", ev.Command)
				}
			},
		},
		{
			name:  "beforeMCPExecution with url → network.indicator",
			event: "beforeMCPExecution",
			payload: map[string]any{
				"server":    "fetch",
				"tool_name": "fetch",
				"url":       "https://evil.example/x",
			},
			want: model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "https://evil.example/x" {
					t.Errorf("url = %q", ev.URL)
				}
				if ev.MCPServer != "fetch" || ev.MCPTool != "fetch" {
					t.Errorf("mcp split = %q/%q, want fetch/fetch", ev.MCPServer, ev.MCPTool)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		{
			name:  "beforeReadFile → file.read, content never stored",
			event: "beforeReadFile",
			payload: map[string]any{
				"file_path": "/proj/.env",
				"content":   "SECRET=abc123",
			},
			want: model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/.env" {
					t.Errorf("file_path = %q, want /proj/.env", ev.FilePath)
				}
				if ev.ContentPreview != "" {
					t.Errorf("content_preview = %q, want empty (read content is never stored)", ev.ContentPreview)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("file.read must carry no diff: %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:  "afterFileEdit → file.write with diff from edits",
			event: "afterFileEdit",
			payload: map[string]any{
				"file_path": "/proj/x.go",
				"edits": []any{
					map[string]any{"old_string": "foo", "new_string": "bar"},
					map[string]any{"old_string": "baz", "new_string": "qux"},
				},
			},
			want: model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/x.go" {
					t.Errorf("file_path = %q, want /proj/x.go", ev.FilePath)
				}
				if len(ev.DiffSHA256) != 64 {
					t.Errorf("diff_sha256 = %q, want a 64-char hex digest computed from edits", ev.DiffSHA256)
				}
				if ev.DiffBytes <= 0 {
					t.Errorf("diff_bytes = %d, want > 0", ev.DiffBytes)
				}
			},
		},
		{
			name:  "beforeFileWrite (variant) → file.write",
			event: "beforeFileWrite",
			payload: map[string]any{
				"path": "/proj/y.go",
			},
			want: model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/y.go" {
					t.Errorf("file_path = %q, want /proj/y.go (path fallback)", ev.FilePath)
				}
				// No edits present → no fabricated diff.
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("no edits → no diff, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "stop maps assistant turn",
			event:   "stop",
			payload: map[string]any{"conversation_id": "c9", "status": "completed"},
			want:    model.EventMessageAssistant,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorAssistant {
					t.Errorf("actor = %q, want assistant", ev.Actor)
				}
				if ev.SessionID != "c9" {
					t.Errorf("session_id = %q, want c9", ev.SessionID)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := ResolveLifecycle(AgentCursor, tc.event)
			if err != nil {
				t.Fatalf("ResolveLifecycle(%q): %v", tc.event, err)
			}
			ev := Map(lc, AgentCursor, model.AgentCursor, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SourceAgent != model.AgentCursor {
				t.Errorf("source_agent = %q, want cursor", ev.SourceAgent)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped cursor %q event failed Validate: %v", tc.event, err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestMapCursorGenericPreToolFamilies(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		wantType model.EventType
		wantPath string
	}{
		{"Read", map[string]any{"file_path": "/p/a"}, model.EventFileRead, "/p/a"},
		{"Grep", map[string]any{"path": "/p"}, model.EventFileRead, "/p"},
		{"Delete", map[string]any{"file_path": "/p/old"}, model.EventFileDelete, "/p/old"},
		{"Task", map[string]any{"prompt": "inspect", "subagent_type": "reviewer"}, model.EventToolCall, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(LifecycleCursorPreTool, AgentCursor, model.AgentCursor, "cursor-family", map[string]any{
				"tool_name":  tc.name,
				"tool_input": tc.input,
			})
			if ev.EventType != tc.wantType || ev.FilePath != tc.wantPath {
				t.Fatalf("event/path = %q/%q, want %q/%q", ev.EventType, ev.FilePath, tc.wantType, tc.wantPath)
			}
			if tc.name == "Task" && ev.SubAgent != "reviewer" {
				t.Errorf("sub_agent = %q, want reviewer", ev.SubAgent)
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// Two afterFileEdit payloads with identical edits must produce the same diff
// digest, and different edits a different one — the invariant a reviewer relies
// on to confirm two writes are byte-identical without the content leaving the box.
func TestCursorEditsDiffIsStable(t *testing.T) {
	mk := func(oldS, newS string) map[string]any {
		return map[string]any{
			"file_path": "/p/f",
			"edits":     []any{map[string]any{"old_string": oldS, "new_string": newS}},
		}
	}
	a := Map(LifecycleFileWrite, AgentCursor, model.AgentCursor, "e1", mk("foo", "bar"))
	b := Map(LifecycleFileWrite, AgentCursor, model.AgentCursor, "e2", mk("foo", "bar"))
	c := Map(LifecycleFileWrite, AgentCursor, model.AgentCursor, "e3", mk("foo", "DIFFERENT"))
	if a.DiffSHA256 == "" || a.DiffSHA256 != b.DiffSHA256 {
		t.Errorf("identical edits must share a digest: %q vs %q", a.DiffSHA256, b.DiffSHA256)
	}
	if a.DiffSHA256 == c.DiffSHA256 {
		t.Error("different edits must produce a different digest")
	}
}

// A file.write whose edits carry no real text must NOT get a fabricated diff.
// An empty edit map or empty old+new strings contributes only separator bytes;
// synthesizing a digest over those would forge edit evidence into a detection
// tool, contradicting the "no edits → no fabricated diff" contract. A delete-only
// edit (old present, new empty) IS real content and must still produce a digest.
func TestCursorEditsDiffNoFabricationOnEmpty(t *testing.T) {
	mk := func(edits []any) map[string]any {
		return map[string]any{"file_path": "/p/f", "edits": edits}
	}
	cases := []struct {
		name     string
		edits    []any
		wantDiff bool
	}{
		{"empty edit map", []any{map[string]any{}}, false},
		{"empty old and new", []any{map[string]any{"old_string": "", "new_string": ""}}, false},
		{"all no-op entries", []any{map[string]any{}, map[string]any{"old_string": "", "new_string": ""}}, false},
		{"delete-only edit", []any{map[string]any{"old_string": "gone", "new_string": ""}}, true},
		{"insert-only edit", []any{map[string]any{"old_string": "", "new_string": "added"}}, true},
		{"mixed real and no-op", []any{map[string]any{}, map[string]any{"old_string": "a", "new_string": "b"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Map(LifecycleFileWrite, AgentCursor, model.AgentCursor, "e", mk(c.edits))
			gotDiff := ev.DiffSHA256 != "" || ev.DiffBytes != 0
			if gotDiff != c.wantDiff {
				t.Errorf("diff present = %v (sha=%q bytes=%d), want %v", gotDiff, ev.DiffSHA256, ev.DiffBytes, c.wantDiff)
			}
			if c.wantDiff && len(ev.DiffSHA256) != 64 {
				t.Errorf("diff_sha256 = %q, want a 64-char digest", ev.DiffSHA256)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event failed Validate: %v", err)
			}
		})
	}
	// A no-op edit list and an absent edit list must yield the same (empty) diff,
	// so a payload that happens to carry empty edits is indistinguishable from one
	// with none — neither fabricates evidence.
	noop := Map(LifecycleFileWrite, AgentCursor, model.AgentCursor, "e", mk([]any{map[string]any{}}))
	none := Map(LifecycleFileWrite, AgentCursor, model.AgentCursor, "e", map[string]any{"file_path": "/p/f"})
	if noop.DiffSHA256 != none.DiffSHA256 || noop.DiffBytes != none.DiffBytes {
		t.Errorf("no-op edits (%q/%d) must match absent edits (%q/%d)", noop.DiffSHA256, noop.DiffBytes, none.DiffSHA256, none.DiffBytes)
	}
}

// A Cursor event with an empty/malformed payload must still yield a well-formed,
// hook-stamped event so the live handler never fails the agent on a bad body.
func TestMapCursorEmptyPayloadIsWellFormed(t *testing.T) {
	for _, ev := range []string{"preToolUse", "postToolUse", "postToolUseFailure", "beforeShellExecution", "afterFileEdit", "beforeReadFile", "beforeMCPExecution", "stop"} {
		lc, err := ResolveLifecycle(AgentCursor, ev)
		if err != nil {
			t.Fatalf("ResolveLifecycle(%q): %v", ev, err)
		}
		got := Map(lc, AgentCursor, model.AgentCursor, "hook-x", map[string]any{})
		assertHookProvenance(t, got)
		if err := got.Validate(); err != nil {
			t.Errorf("empty %q event failed Validate: %v", ev, err)
		}
	}
}

// Monitor mode emits no permission decision, preserving Cursor's own approval
// flow. The map must be fresh for each call.
func TestCursorPassthroughIsInert(t *testing.T) {
	resp := PassthroughResponse(AgentCursor, LifecyclePreTool)
	if len(resp) != 0 {
		t.Errorf("passthrough = %v, want empty object", resp)
	}
	resp["x"] = 1
	if len(PassthroughResponse(AgentCursor, LifecyclePreTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}

package hook

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// ResolveLifecycle must map every Windsurf agent_action_name onto the right
// numbat lifecycle by case-insensitive substring match on the action verb. This
// is the one place fuzzy matching is allowed — it recognizes the agent's own
// event label, not activity — so each of the ten in-prod events is exercised
// here, plus case-insensitivity and an unknown label.
func TestResolveWindsurfLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"pre_user_prompt", LifecyclePromptSubmit},
		{"pre_read_code", LifecycleFileRead},
		{"post_read_code", LifecycleFileRead},
		{"pre_write_code", LifecycleFileWrite},
		{"post_write_code", LifecycleFileWrite},
		{"pre_run_command", LifecycleCommandExec},
		{"post_run_command", LifecycleCommandResult},
		{"pre_mcp_tool_use", LifecycleMCPCall},
		{"post_mcp_tool_use", LifecycleMCPCall},
		{"post_cascade_response", LifecycleAssistant},
		// Case-insensitivity on the label.
		{"PRE_RUN_COMMAND", LifecycleCommandExec},
		{"Post_Write_Code", LifecycleFileWrite},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentWindsurf, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(windsurf, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(windsurf, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	if _, err := ResolveLifecycle(AgentWindsurf, "workspace_open"); err == nil {
		t.Error("ResolveLifecycle(windsurf, workspace_open) should error: no activity moment matches")
	}
}

// Map must turn each Windsurf event's stdin payload into the right model.Event
// type with its key fields resolved, exercising the real resolve→map path with
// realistic payloads whose action fields are NESTED under tool_info (unlike
// Cursor's flat payload). Every mapped event must also satisfy the model field
// co-occurrence contract (Validate).
func TestMapWindsurfEvents(t *testing.T) {
	const eventID = "hook-windsurf-1"

	// ws builds a realistic Windsurf payload: trajectory_id identifies the
	// conversation, execution_id identifies one turn, and action fields are under
	// tool_info.
	ws := func(action string, toolInfo map[string]any) map[string]any {
		return map[string]any{
			"agent_action_name": action,
			"trajectory_id":     "trajectory-1",
			"execution_id":      "exec-1",
			"timestamp":         "2026-06-04T00:00:00Z",
			"tool_info":         toolInfo,
		}
	}

	tests := []struct {
		name    string
		event   string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name:    "pre_user_prompt → prompt.user, prompt read from tool_info",
			event:   "pre_user_prompt",
			payload: ws("pre_user_prompt", map[string]any{"prompt": "read the   env file"}),
			want:    model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorUser {
					t.Errorf("actor = %q, want user", ev.Actor)
				}
				if ev.SessionID != "trajectory-1" {
					t.Errorf("session_id = %q, want trajectory-1", ev.SessionID)
				}
				if ev.ContentPreview != "read the env file" {
					t.Errorf("content_preview = %q, want collapsed prompt", ev.ContentPreview)
				}
			},
		},
		{
			name:    "pre_run_command → command.exec with cwd",
			event:   "pre_run_command",
			payload: ws("pre_run_command", map[string]any{"command_line": "cat .env", "cwd": "/proj"}),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" {
					t.Errorf("command = %q, want cat .env", ev.Command)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want nested tool_info cwd", ev.ProjectPath)
				}
			},
		},
		{
			name:  "post_run_command → command.result with exit/duration",
			event: "post_run_command",
			payload: ws("post_run_command", map[string]any{
				"command":     "ls -la",
				"exit_code":   float64(1),
				"duration_ms": float64(42),
				"stderr":      "some warning noise",
			}),
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "ls -la" {
					t.Errorf("command = %q, want ls -la", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 42 {
					t.Errorf("duration_ms = %v, want 42", ev.DurationMs)
				}
				// stderr alone is NOT an explicit error — a clean command may write to
				// stderr — so no tool_error tag is fabricated from its presence.
				if hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want no tool_error (stderr alone is not an error)", ev.Tags)
				}
			},
		},
		{
			name:  "post_run_command with explicit error → tool_error tag",
			event: "post_run_command",
			payload: ws("post_run_command", map[string]any{
				"command": "false",
				"error":   "command failed",
			}),
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error (explicit error field)", ev.Tags)
				}
				// No exit code is fabricated when the payload carries none.
				if ev.ExitCode != nil {
					t.Errorf("exit_code = %v, want nil (none reported, none fabricated)", ev.ExitCode)
				}
			},
		},
		{
			// Windsurf reports action fields FLAT under tool_info, so an explicit
			// failure arrives as tool_info.status:"error" — not nested in a response
			// map. toolErrored() must treat that flat status as an explicit error and
			// set the tool_error tag.
			name:  "post_run_command with flat tool_info.status:error → tool_error tag",
			event: "post_run_command",
			payload: ws("post_run_command", map[string]any{
				"command": "false",
				"status":  "error",
			}),
			want: model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error (flat tool_info.status:error)", ev.Tags)
				}
			},
		},
		{
			name:    "pre_read_code → file.read, content never stored",
			event:   "pre_read_code",
			payload: ws("pre_read_code", map[string]any{"file_path": "/proj/.env", "content": "SECRET=abc123"}),
			want:    model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/.env" {
					t.Errorf("file_path = %q, want /proj/.env", ev.FilePath)
				}
				if ev.ContentPreview != "" {
					t.Errorf("content_preview = %q, want empty (read content never stored)", ev.ContentPreview)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("file.read must carry no diff: %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "post_read_code → file.read",
			event:   "post_read_code",
			payload: ws("post_read_code", map[string]any{"file_path": "/proj/main.go"}),
			want:    model.EventFileRead,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/main.go" {
					t.Errorf("file_path = %q, want /proj/main.go", ev.FilePath)
				}
			},
		},
		{
			name:  "pre_write_code → file.write with diff from edits",
			event: "pre_write_code",
			payload: ws("pre_write_code", map[string]any{
				"file_path": "/proj/x.go",
				"edits": []any{
					map[string]any{"old_string": "foo", "new_string": "bar"},
				},
			}),
			want: model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/x.go" {
					t.Errorf("file_path = %q, want /proj/x.go", ev.FilePath)
				}
				if len(ev.DiffSHA256) != 64 || ev.DiffBytes <= 0 {
					t.Errorf("want a 64-char digest and positive bytes from edits, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "post_write_code with no edits → no fabricated diff",
			event:   "post_write_code",
			payload: ws("post_write_code", map[string]any{"file_path": "/proj/y.go"}),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/y.go" {
					t.Errorf("file_path = %q, want /proj/y.go", ev.FilePath)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("no edits → no diff, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:  "post_write_code delete-only edit → diff present",
			event: "post_write_code",
			payload: ws("post_write_code", map[string]any{
				"file_path": "/proj/z.go",
				"edits":     []any{map[string]any{"old_string": "gone", "new_string": ""}},
			}),
			want: model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if len(ev.DiffSHA256) != 64 {
					t.Errorf("delete-only edit is real content; want a digest, got %q", ev.DiffSHA256)
				}
			},
		},
		{
			name:  "pre_mcp_tool_use → tool.call splits server/tool",
			event: "pre_mcp_tool_use",
			payload: ws("pre_mcp_tool_use", map[string]any{
				"mcp_server_name":    "github",
				"mcp_tool_name":      "create_issue",
				"mcp_tool_arguments": map[string]any{"title": "x"},
			}),
			want: model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
				if ev.ToolName != "create_issue" {
					t.Errorf("tool_name = %q, want create_issue", ev.ToolName)
				}
				if ev.Command != "" {
					t.Errorf("command = %q, want empty (tool.call admits no command)", ev.Command)
				}
			},
		},
		{
			name:  "post_mcp_tool_use → tool.result with official names",
			event: "post_mcp_tool_use",
			payload: ws("post_mcp_tool_use", map[string]any{
				"mcp_server_name": "github",
				"mcp_tool_name":   "list_commits",
			}),
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "list_commits" {
					t.Errorf("mcp split = %q/%q", ev.MCPServer, ev.MCPTool)
				}
			},
		},
		{
			name:  "post_mcp_tool_use with url → tool.result",
			event: "post_mcp_tool_use",
			payload: ws("post_mcp_tool_use", map[string]any{
				"server_name": "fetch",
				"name":        "fetch",
				"url":         "https://evil.example/x",
			}),
			want: model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "" {
					t.Errorf("url = %q", ev.URL)
				}
				if ev.MCPServer != "fetch" || ev.MCPTool != "fetch" {
					t.Errorf("mcp split = %q/%q, want fetch/fetch (server_name/name fallbacks)", ev.MCPServer, ev.MCPTool)
				}
				if hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want no network tag", ev.Tags)
				}
			},
		},
		{
			name:    "post_cascade_response → message.assistant",
			event:   "post_cascade_response",
			payload: ws("post_cascade_response", map[string]any{}),
			want:    model.EventMessageAssistant,
			check: func(t *testing.T, ev model.Event) {
				if ev.SessionID != "trajectory-1" {
					t.Errorf("session_id = %q, want trajectory-1", ev.SessionID)
				}
				// The cascade response text is the agent's output, not stored.
				if ev.ContentPreview != "" {
					t.Errorf("content_preview = %q, want empty", ev.ContentPreview)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := ResolveLifecycle(AgentWindsurf, tc.event)
			if err != nil {
				t.Fatalf("ResolveLifecycle(%q): %v", tc.event, err)
			}
			ev := Map(lc, AgentWindsurf, model.AgentWindsurf, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SourceAgent != model.AgentWindsurf {
				t.Errorf("source_agent = %q, want windsurf", ev.SourceAgent)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped windsurf %q event failed Validate: %v", tc.event, err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

// A Windsurf write whose nested edits carry no real text must NOT get a
// fabricated diff, and a delete-only edit must. This mirrors the Cursor invariant
// but exercises the tool_info-nested path.
func TestWindsurfEditsDiffNoFabricationOnEmpty(t *testing.T) {
	mk := func(edits []any) map[string]any {
		return map[string]any{
			"agent_action_name": "post_write_code",
			"tool_info":         map[string]any{"file_path": "/p/f", "edits": edits},
		}
	}
	cases := []struct {
		name     string
		edits    []any
		wantDiff bool
	}{
		{"empty edit map", []any{map[string]any{}}, false},
		{"empty old and new", []any{map[string]any{"old_string": "", "new_string": ""}}, false},
		{"delete-only edit", []any{map[string]any{"old_string": "gone", "new_string": ""}}, true},
		{"mixed real and no-op", []any{map[string]any{}, map[string]any{"old_string": "a", "new_string": "b"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Map(LifecycleFileWrite, AgentWindsurf, model.AgentWindsurf, "e", mk(c.edits))
			gotDiff := ev.DiffSHA256 != "" || ev.DiffBytes != 0
			if gotDiff != c.wantDiff {
				t.Errorf("diff present = %v (sha=%q bytes=%d), want %v", gotDiff, ev.DiffSHA256, ev.DiffBytes, c.wantDiff)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event failed Validate: %v", err)
			}
		})
	}
}

// A Windsurf event with an empty or tool_info-less payload must still yield a
// well-formed, hook-stamped event so the live handler never fails the agent on a
// malformed body (the resolver degrades to reading the top level).
func TestMapWindsurfEmptyPayloadIsWellFormed(t *testing.T) {
	for _, ev := range []string{"pre_run_command", "post_write_code", "pre_read_code", "pre_mcp_tool_use", "post_cascade_response"} {
		lc, err := ResolveLifecycle(AgentWindsurf, ev)
		if err != nil {
			t.Fatalf("ResolveLifecycle(%q): %v", ev, err)
		}
		got := Map(lc, AgentWindsurf, model.AgentWindsurf, "hook-x", map[string]any{})
		assertHookProvenance(t, got)
		if err := got.Validate(); err != nil {
			t.Errorf("empty %q event failed Validate: %v", ev, err)
		}
	}
}

// The Windsurf passthrough is the inert empty object: Windsurf gates on process
// exit code (exit 2 blocks), not a stdout decision, so {} is harmless and numbat
// always exits 0. It must be a fresh map each call.
func TestWindsurfPassthroughIsEmpty(t *testing.T) {
	resp := PassthroughResponse(AgentWindsurf, LifecyclePostTool)
	if len(resp) != 0 {
		t.Errorf("windsurf passthrough = %v, want empty object", resp)
	}
	resp["x"] = 1
	if len(PassthroughResponse(AgentWindsurf, LifecyclePostTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}

package hook

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// ResolveLifecycle maps the Codex events numbat installs. Compaction events are
// deliberately rejected because they do not map to a numbat event type.
func TestResolveCodexLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"PreToolUse", LifecycleCodexPreTool},
		{"PostToolUse", LifecycleCodexPostTool},
		{"UserPromptSubmit", LifecyclePromptSubmit},
		{"PermissionRequest", LifecycleCodexPermission},
		{"SessionStart", LifecycleSessionStart},
		{"SubagentStart", LifecycleSessionStart},
		{"Stop", LifecycleStop},
		{"SubagentStop", LifecycleSessionEnd},
		// Case-insensitivity on the label.
		{"pretooluse", LifecycleCodexPreTool},
		{"POSTTOOLUSE", LifecycleCodexPostTool},
		{"userpromptsubmit", LifecyclePromptSubmit},
		// The numbat lifecycle-arg spellings the installer wires verbatim.
		{"codex-pre-tool", LifecycleCodexPreTool},
		{"codex-post-tool", LifecycleCodexPostTool},
		{"prompt-submit", LifecyclePromptSubmit},
		{"permission-request", LifecycleCodexPermission},
		{"codex-permission-request", LifecycleCodexPermission},
		{"session-start", LifecycleSessionStart},
		{"session-end", LifecycleSessionEnd},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentCodex, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(codex, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(codex, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	// Codex's event set is documented and unambiguous, so resolution is EXACT, not
	// a substring match: a near-miss that merely contains a known name must surface
	// as an unknown-event operator error (exit 2 at the cmd layer), never be
	// silently accepted as the event it resembles.
	for _, bad := range []string{
		"PreToolUseBroken",
		"PostToolUseV2",
		"UserPromptSubmitV2",
		"XPreToolUse",
		"NotAPrompt",
		"prompt",
		"tooluse",
		"compact",
		"PreCompact",
		"PostCompact",
		"",
	} {
		if _, err := ResolveLifecycle(AgentCodex, bad); err == nil {
			t.Errorf("ResolveLifecycle(codex, %q) should error: not an exact Codex event", bad)
		}
	}
}

// Installer/runtime parity: for every event the installer wires (codexHookEvents),
// the runtime resolver must map BOTH the raw documented Codex event name (the
// settingsKey, e.g. "SubagentStop") AND the numbat lifecycle arg the installer
// writes into the command (the lifecycle field, e.g. "session-end") to the same
// numbat Lifecycle — and onward to the same model.EventType. The installer wires
// the lifecycle arg verbatim, while Codex at runtime fires the raw event name;
// this test pins that those two entry paths never drift apart for any of the 10
// events (the SubagentStop->session-end alignment in particular).
func TestCodexInstallerResolverLifecycleParity(t *testing.T) {
	for _, ev := range codexHookEvents {
		// The path the installer's command takes at runtime: the numbat lifecycle arg.
		fromArg, err := ResolveLifecycle(AgentCodex, ev.lifecycle)
		if err != nil {
			t.Errorf("ResolveLifecycle(codex, lifecycle arg %q): %v", ev.lifecycle, err)
			continue
		}
		// The path Codex itself takes: the raw documented event name (settingsKey).
		fromRaw, err := ResolveLifecycle(AgentCodex, ev.settingsKey)
		if err != nil {
			t.Errorf("ResolveLifecycle(codex, raw event %q): %v", ev.settingsKey, err)
			continue
		}
		if fromArg != fromRaw {
			t.Errorf("event %q: installer lifecycle arg %q resolves to %q but raw event resolves to %q (installer/runtime drift)",
				ev.settingsKey, ev.lifecycle, fromArg, fromRaw)
			continue
		}
		// And both must yield the same mapped EventType, so any future divergence in
		// Map (not just ResolveLifecycle) is also caught.
		argEvent := Map(fromArg, AgentCodex, model.AgentCodex, "parity", map[string]any{})
		rawEvent := Map(fromRaw, AgentCodex, model.AgentCodex, "parity", map[string]any{})
		if argEvent.EventType != rawEvent.EventType {
			t.Errorf("event %q: event_type drift arg=%q raw=%q", ev.settingsKey, argEvent.EventType, rawEvent.EventType)
		}
	}
}

// cx builds a Codex hook payload. Codex is snake_case like Claude: tool_input is
// an OBJECT (not a JSON-encoded string), tool_response carries structured result
// fields, and the prompt/cwd/session_id sit at the top level.
func cx(event, toolName string, toolInput map[string]any, extra map[string]any) map[string]any {
	p := map[string]any{
		"hook_event_name": event,
		"tool_name":       toolName,
		"tool_input":      toolInput,
		"cwd":             "/proj",
		"session_id":      "sess-1",
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// Map must turn each Codex event + tool_name variant into the right model.Event
// type with key fields resolved, exercising the real resolve→map path. Every
// mapped event must satisfy the model field co-occurrence contract (Validate).
// Exit codes and tool-error flags come ONLY from structured fields, never
// prose-scraped or inferred, and never fabricated when absent.
func TestMapCodexEvents(t *testing.T) {
	const eventID = "hook-codex-1"

	tests := []struct {
		name    string
		event   string
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		{
			name:    "UserPromptSubmit → prompt.user",
			event:   "UserPromptSubmit",
			payload: map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "read the   env file", "cwd": "/proj"},
			want:    model.EventPromptUser,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorUser {
					t.Errorf("actor = %q, want user", ev.Actor)
				}
				if ev.ContentPreview != "read the env file" {
					t.Errorf("content_preview = %q, want collapsed prompt", ev.ContentPreview)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want /proj", ev.ProjectPath)
				}
			},
		},
		{
			name:  "PermissionRequest → permission.requested, verdict-looking input ignored",
			event: "PermissionRequest",
			payload: cx("PermissionRequest", "Bash",
				map[string]any{"command": "sudo true", "description": "shell escalation"},
				map[string]any{"decision": "deny", "permissionDecision": "allow", "behavior": "deny"},
			),
			want: model.EventPermissionRequested,
			check: func(t *testing.T, ev model.Event) {
				if ev.ApprovalDecision != model.DecisionAsked || ev.Decision != model.DecisionAsked {
					t.Errorf("decision = %q/%q, want asked/asked (input verdict keys ignored)", ev.Decision, ev.ApprovalDecision)
				}
				if ev.ApprovalReason != "shell escalation" {
					t.Errorf("approval_reason = %q, want tool_input.description", ev.ApprovalReason)
				}
				if ev.ToolName != "Bash" {
					t.Errorf("tool_name = %q, want Bash", ev.ToolName)
				}
			},
		},
		{
			name:  "SubagentStart → session.start with sub_agent profile",
			event: "SubagentStart",
			payload: map[string]any{
				"hook_event_name": "SubagentStart",
				"session_id":      "sess-1",
				"cwd":             "/proj",
				"agent_id":        "agent-opaque-1",
				"agent_type":      "code-reviewer",
			},
			want: model.EventSessionStart,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorSystem {
					t.Errorf("actor = %q, want system", ev.Actor)
				}
				if ev.SessionID != "agent-opaque-1" || ev.SessionTreeID != "sess-1" || ev.SubAgentID != "agent-opaque-1" || ev.SubAgent != "code-reviewer" {
					t.Errorf("subagent context = session %q tree %q id %q role %q", ev.SessionID, ev.SessionTreeID, ev.SubAgentID, ev.SubAgent)
				}
			},
		},
		{
			name:  "SubagentStop → session.end keeps opaque id separate",
			event: "SubagentStop",
			payload: map[string]any{
				"hook_event_name": "SubagentStop",
				"session_id":      "sess-1",
				"cwd":             "/proj",
				"agent_id":        "agent-opaque-2",
			},
			want: model.EventSessionEnd,
			check: func(t *testing.T, ev model.Event) {
				if ev.Actor != model.ActorSystem {
					t.Errorf("actor = %q, want system", ev.Actor)
				}
				if ev.SessionID != "agent-opaque-2" || ev.SessionTreeID != "sess-1" || ev.SubAgentID != "agent-opaque-2" || ev.SubAgent != "" {
					t.Errorf("subagent context = session %q tree %q id %q role %q", ev.SessionID, ev.SessionTreeID, ev.SubAgentID, ev.SubAgent)
				}
			},
		},
		// Shell tool, all three name variants.
		{
			name:    "PreToolUse Bash → command.exec",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "Bash", map[string]any{"command": "cat .env"}, nil),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "cat .env" {
					t.Errorf("command = %q, want cat .env", ev.Command)
				}
				if ev.ProjectPath != "/proj" {
					t.Errorf("project_path = %q, want /proj", ev.ProjectPath)
				}
			},
		},
		{
			name:    "PreToolUse shell_command with cmd fallback → command.exec",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "shell_command", map[string]any{"cmd": "ls -la"}, nil),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "ls -la" {
					t.Errorf("command = %q, want ls -la (cmd fallback)", ev.Command)
				}
			},
		},
		{
			name:    "PreToolUse exec_command with cmd → command.exec",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "exec_command", map[string]any{"cmd": "go test ./..."}, nil),
			want:    model.EventCommandExec,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "go test ./..." {
					t.Errorf("command = %q, want go test ./...", ev.Command)
				}
			},
		},
		{
			name:    "PreToolUse custom exec remains tool.call",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "exec", map[string]any{"input": "await tools.exec_command(...)"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "" {
					t.Errorf("custom exec command = %q, want empty", ev.Command)
				}
			},
		},
		{
			name:    "PostToolUse Bash → command.result with structured exit/duration",
			event:   "PostToolUse",
			payload: cx("PostToolUse", "Bash", map[string]any{"command": "false"}, map[string]any{"tool_response": map[string]any{"exit_code": float64(1), "duration_ms": float64(42)}}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "false" {
					t.Errorf("command = %q, want false", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1 (structured)", ev.ExitCode)
				}
				if ev.DurationMs == nil || *ev.DurationMs != 42 {
					t.Errorf("duration_ms = %v, want 42 (structured)", ev.DurationMs)
				}
			},
		},
		{
			name:    "PostToolUse shell with no exit reported → none fabricated",
			event:   "PostToolUse",
			payload: cx("PostToolUse", "shell", map[string]any{"command": "echo hi"}, nil),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ExitCode != nil {
					t.Errorf("exit_code = %v, want nil (none reported, none fabricated)", ev.ExitCode)
				}
				if ev.DurationMs != nil {
					t.Errorf("duration_ms = %v, want nil (none reported)", ev.DurationMs)
				}
			},
		},
		{
			name:    "PostToolUse with explicit error field → tool_error tag",
			event:   "PostToolUse",
			payload: cx("PostToolUse", "shell", map[string]any{"command": "false"}, map[string]any{"error": "command failed"}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if !hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want tool_error (explicit error field)", ev.Tags)
				}
			},
		},
		// apply_patch envelope → file.write; patch text never stored.
		{
			name:    "PreToolUse apply_patch → file.write, patch text not stored",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "apply_patch", map[string]any{"path": "/proj/x.go", "patch": "@@ -1 +1 @@\n-foo\n+bar"}, nil),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/x.go" {
					t.Errorf("file_path = %q, want /proj/x.go", ev.FilePath)
				}
				if ev.Command != "" {
					t.Errorf("file.write must carry no command, got %q", ev.Command)
				}
				if len(ev.DiffSHA256) != 64 || ev.DiffBytes != 21 {
					t.Errorf("patch digest = %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
				if !hasTag(ev.Tags, codexTagPatchRequested) {
					t.Errorf("tags = %v, want %q", ev.Tags, codexTagPatchRequested)
				}
			},
		},
		{
			name:    "PostToolUse apply_patch → tool.result",
			event:   "PostToolUse",
			payload: cx("PostToolUse", "apply_patch", map[string]any{"file_path": "/proj/y.go"}, map[string]any{"tool_response": map[string]any{"diff_sha256": testDiffSHA256, "diff_bytes": float64(12)}}),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" || ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result repeated action fields: %+v", ev)
				}
			},
		},
		// read_file → file.read, content never stored.
		{
			name:    "PreToolUse read_file → file.read, content never stored",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "read_file", map[string]any{"path": "/proj/.env", "content": "SECRET=abc123"}, nil),
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
		// create_file / edit_file → file.write.
		{
			name:    "PreToolUse create_file → file.write",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "create_file", map[string]any{"path": "/proj/new.go"}, nil),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/new.go" {
					t.Errorf("file_path = %q, want /proj/new.go", ev.FilePath)
				}
			},
		},
		{
			name:    "PostToolUse edit_file → tool.result",
			event:   "PostToolUse",
			payload: cx("PostToolUse", "edit_file", map[string]any{"filePath": "/proj/main.go"}, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" {
					t.Errorf("tool.result must not repeat file_path, got %q", ev.FilePath)
				}
			},
		},
		// web_search_call → network.indicator.
		{
			name:    "PreToolUse web_search_call with url → network.indicator",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "web_search_call", map[string]any{"url": "https://evil.example/x"}, nil),
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "https://evil.example/x" {
					t.Errorf("url = %q", ev.URL)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		{
			name:    "PreToolUse web_search_call with query → network.indicator preview",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "web_search_call", map[string]any{"query": "how to exfiltrate"}, nil),
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "" {
					t.Errorf("url = %q, want empty (search carries a query, not a url)", ev.URL)
				}
				if ev.ContentPreview != "how to exfiltrate" {
					t.Errorf("content_preview = %q, want the query text", ev.ContentPreview)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		// Unknown / MCP tool → generic tool vocabulary, narrow (no generic aliases).
		{
			name:    "PreToolUse unknown tool → tool.call",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "some_custom_tool", map[string]any{"foo": "bar"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "some_custom_tool" {
					t.Errorf("tool_name = %q, want some_custom_tool", ev.ToolName)
				}
			},
		},
		{
			name:    "PostToolUse unknown tool → tool.result",
			event:   "PostToolUse",
			payload: cx("PostToolUse", "some_custom_tool", map[string]any{"foo": "bar"}, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "some_custom_tool" {
					t.Errorf("tool_name = %q, want some_custom_tool", ev.ToolName)
				}
			},
		},
		{
			name:    "PreToolUse mcp-named tool → tool.call splits server/tool",
			event:   "PreToolUse",
			payload: cx("PreToolUse", "mcp__github__create_issue", map[string]any{"title": "x"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc, err := ResolveLifecycle(AgentCodex, tc.event)
			if err != nil {
				t.Fatalf("ResolveLifecycle(%q): %v", tc.event, err)
			}
			ev := Map(lc, AgentCodex, model.AgentCodex, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SourceAgent != model.AgentCodex {
				t.Errorf("source_agent = %q, want codex", ev.SourceAgent)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped codex %q event failed Validate: %v", tc.event, err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestMapCodexSubagentContextAcrossCallbacks(t *testing.T) {
	const (
		treeID  = "parent-tree-1"
		childID = "child-thread-1"
	)
	cases := []struct {
		event string
		want  model.EventType
	}{
		{"SubagentStart", model.EventSessionStart},
		{"PreToolUse", model.EventCommandExec},
		{"PostToolUse", model.EventCommandResult},
		{"SubagentStop", model.EventSessionEnd},
	}
	for _, tc := range cases {
		t.Run(tc.event, func(t *testing.T) {
			payload := map[string]any{
				"hook_event_name": tc.event,
				"session_id":      treeID,
				"agent_id":        childID,
				"agent_type":      "default",
				"tool_name":       "Bash",
				"tool_input":      map[string]any{"command": "printf ok"},
				"tool_response":   map[string]any{"exit_code": float64(0)},
			}
			lc, err := ResolveLifecycle(AgentCodex, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			ev := Map(lc, AgentCodex, model.AgentCodex, "child-event", payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SessionID != childID || ev.SessionTreeID != treeID || ev.ParentSessionID != "" || ev.SubAgentID != childID || ev.SubAgent != "default" {
				t.Fatalf("context = session %q tree %q parent %q id %q role %q", ev.SessionID, ev.SessionTreeID, ev.ParentSessionID, ev.SubAgentID, ev.SubAgent)
			}
		})
	}
}

func TestMapCodexConcurrentDefaultSubagentsStayDistinct(t *testing.T) {
	mapChild := func(id string) model.Event {
		return Map(LifecycleCodexPreTool, AgentCodex, model.AgentCodex, "event-"+id, map[string]any{
			"hook_event_name": "PreToolUse",
			"session_id":      "parent-tree-1",
			"agent_id":        id,
			"agent_type":      "default",
			"tool_name":       "Bash",
			"tool_input":      map[string]any{"command": "printf ok"},
		})
	}
	first := mapChild("child-thread-1")
	second := mapChild("child-thread-2")
	if first.SessionID == second.SessionID || first.SubAgentID == second.SubAgentID {
		t.Fatalf("concurrent children collapsed: first=%+v second=%+v", first, second)
	}
	if first.SubAgent != "default" || second.SubAgent != "default" || first.SessionTreeID != second.SessionTreeID {
		t.Fatalf("shared role/tree context lost: first=%+v second=%+v", first, second)
	}
}

func TestMapCodexPartialSubagentContext(t *testing.T) {
	tests := []struct {
		name        string
		extra       map[string]any
		wantSession string
		wantTree    string
		wantID      string
		wantRole    string
	}{
		{name: "role only", extra: map[string]any{"agent_type": "reviewer"}, wantSession: "parent-1", wantRole: "reviewer"},
		{name: "id only", extra: map[string]any{"agent_id": "child-1"}, wantSession: "child-1", wantTree: "parent-1", wantID: "child-1"},
		{name: "neither", extra: map[string]any{}, wantSession: "parent-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"hook_event_name": "PreToolUse",
				"session_id":      "parent-1",
				"tool_name":       "Bash",
				"tool_input":      map[string]any{"command": "printf ok"},
			}
			for k, v := range tc.extra {
				payload[k] = v
			}
			ev := Map(LifecycleCodexPreTool, AgentCodex, model.AgentCodex, "event-1", payload)
			if ev.SessionID != tc.wantSession || ev.SessionTreeID != tc.wantTree || ev.SubAgentID != tc.wantID || ev.SubAgent != tc.wantRole {
				t.Fatalf("context = session %q tree %q id %q role %q", ev.SessionID, ev.SessionTreeID, ev.SubAgentID, ev.SubAgent)
			}
			if ev.ParentSessionID != "" {
				t.Fatalf("parent_session_id = %q, Codex hooks do not report the immediate parent", ev.ParentSessionID)
			}
		})
	}
}

func TestMapEventsCodexApplyPatchExpandsPaths(t *testing.T) {
	patch := "*** Begin Patch\n" +
		"*** Update File: a.go\n@@\n-old\n+new\n" +
		"*** Delete File: b.go\n*** End Patch\n"
	payload := cx("PreToolUse", "apply_patch", map[string]any{"command": patch}, nil)
	events := MapEvents(LifecycleCodexPreTool, AgentCodex, model.AgentCodex, "patch-1", payload)
	if len(events) != 2 {
		t.Fatalf("MapEvents() returned %d events, want 2: %+v", len(events), events)
	}
	if events[0].EventType != model.EventFileWrite || events[0].FilePath != "a.go" {
		t.Errorf("first event = %+v", events[0])
	}
	if events[1].EventType != model.EventFileDelete || events[1].FilePath != "b.go" {
		t.Errorf("second event = %+v", events[1])
	}
	if events[0].EventID != "patch-1-1" || events[1].EventID != "patch-1-2" {
		t.Errorf("event ids = %q, %q", events[0].EventID, events[1].EventID)
	}
	for _, ev := range events {
		if ev.DiffSHA256 == "" || ev.DiffBytes != len(patch) {
			t.Errorf("patch digest = %q/%d", ev.DiffSHA256, ev.DiffBytes)
		}
		if ev.Command != "" || ev.ContentPreview != "" {
			t.Errorf("patch content leaked: %+v", ev)
		}
		if !hasTag(ev.Tags, codexTagPatchRequested) {
			t.Errorf("tags = %v", ev.Tags)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("Validate(%s): %v", ev.EventID, err)
		}
	}
}

// A non-zero exit code alone must NOT raise tool_error: the error flag is
// explicit-only (a clean command can exit non-zero and still not be "errored" in
// the agent's sense). This guards the no-inference rule for the structured path.
func TestMapCodexExitCodeAloneIsNotToolError(t *testing.T) {
	payload := cx("PostToolUse", "shell", map[string]any{"command": "false"}, map[string]any{
		"tool_response": map[string]any{"exit_code": float64(2)},
	})
	ev := Map(LifecycleCodexPostTool, AgentCodex, model.AgentCodex, "e", payload)
	if ev.ExitCode == nil || *ev.ExitCode != 2 {
		t.Fatalf("exit_code = %v, want 2", ev.ExitCode)
	}
	if hasTag(ev.Tags, model.TagToolError) {
		t.Errorf("tags = %v, want NO tool_error from a non-zero exit alone", ev.Tags)
	}
}

func TestMapCodexCommonModelContext(t *testing.T) {
	payload := cx("PreToolUse", "Bash", map[string]any{"command": "cat .env"}, map[string]any{
		"model": "gpt-5.5-codex",
	})
	ev := Map(LifecycleCodexPreTool, AgentCodex, model.AgentCodex, "e", payload)
	if ev.Model != "gpt-5.5-codex" {
		t.Fatalf("model = %q, want Codex hook common model field", ev.Model)
	}
	if ev.EventType != model.EventCommandExec || ev.Command != "cat .env" {
		t.Fatalf("mapped event = %q command %q, want command.exec cat .env", ev.EventType, ev.Command)
	}
}

// An apply_patch/edit whose payload carries no structured diff must NOT get a
// fabricated digest — the patch body is never hashed at the hook boundary.
func TestMapCodexPatchNoFabricatedDiff(t *testing.T) {
	for _, tool := range []string{"apply_patch", "edit_file", "create_file"} {
		payload := cx("PostToolUse", tool, map[string]any{"path": "/p/f", "patch": "@@ real patch body @@"}, nil)
		ev := Map(LifecycleCodexPostTool, AgentCodex, model.AgentCodex, "e", payload)
		if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
			t.Errorf("%s: fabricated diff %q/%d, want none (no structured diff reported)", tool, ev.DiffSHA256, ev.DiffBytes)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: event failed Validate: %v", tool, err)
		}
	}
}

// A Codex event with an empty payload must still yield a well-formed,
// hook-stamped event so the live handler never fails the agent on a bad body.
func TestMapCodexEmptyPayloadIsWellFormed(t *testing.T) {
	for _, ev := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "SessionStart", "Stop"} {
		lc, err := ResolveLifecycle(AgentCodex, ev)
		if err != nil {
			t.Fatalf("ResolveLifecycle(%q): %v", ev, err)
		}
		got := Map(lc, AgentCodex, model.AgentCodex, "hook-x", map[string]any{})
		assertHookProvenance(t, got)
		if err := got.Validate(); err != nil {
			t.Errorf("empty %q event failed Validate: %v", ev, err)
		}
	}
}

// Monitor mode returns an inert object and never overrides Codex approval.
func TestCodexPassthroughIsInert(t *testing.T) {
	resp := PassthroughResponse(AgentCodex, LifecycleCodexPreTool)
	if len(resp) != 0 {
		t.Errorf("passthrough = %v, want empty object {}", resp)
	}
	resp["x"] = 1
	if len(PassthroughResponse(AgentCodex, LifecycleCodexPreTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}

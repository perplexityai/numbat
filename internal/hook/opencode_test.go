package hook

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// ResolveLifecycle must map each OpenCode hook moment numbat wires onto the right
// numbat lifecycle. OpenCode's plugin surface exposes the whole event stream, but
// numbat wires tool, prompt, assistant, and session moments. The raw-event
// match is EXACT (case-folded), so a near-miss surfaces as an unknown-event
// operator error rather than being silently accepted.
func TestResolveOpenCodeLifecycle(t *testing.T) {
	cases := []struct {
		event string
		want  Lifecycle
	}{
		{"tool.execute.before", LifecycleOpenCodePreTool},
		{"tool.execute.after", LifecycleOpenCodePostTool},
		{"chat.message", LifecyclePromptSubmit},
		{"message.updated", LifecycleAssistant},
		{"session.created", LifecycleSessionStart},
		{"session.deleted", LifecycleSessionEnd},
		// Case-insensitivity on the raw label.
		{"TOOL.EXECUTE.BEFORE", LifecycleOpenCodePreTool},
		{"Session.Created", LifecycleSessionStart},
		// The numbat lifecycle-arg spellings the installer wires verbatim.
		{"opencode-pre-tool", LifecycleOpenCodePreTool},
		{"opencode-post-tool", LifecycleOpenCodePostTool},
		{"prompt-submit", LifecyclePromptSubmit},
		{"assistant", LifecycleAssistant},
		{"session-start", LifecycleSessionStart},
		{"session-end", LifecycleSessionEnd},
	}
	for _, c := range cases {
		got, err := ResolveLifecycle(AgentOpenCode, c.event)
		if err != nil {
			t.Errorf("ResolveLifecycle(opencode, %q) errored: %v", c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveLifecycle(opencode, %q) = %q, want %q", c.event, got, c.want)
		}
	}
	// OpenCode fires a LARGER event set than numbat wires (session.idle/updated/
	// error/compacted, command/file/permission/message events). numbat resolves ONLY
	// the events it ingests; resolution is EXACT, so an unwired event — or a near-miss
	// that merely resembles a known name — must surface as an unknown-event operator
	// error, never be silently accepted. session.idle in particular is end-of-TURN,
	// not session end, and must NOT resolve.
	for _, bad := range []string{
		"session.idle",
		"session.updated",
		"session.error",
		"session.compacted",
		"tool.execute",
		"tool.execute.beforeX",
		"command.execute.before",
		"permission.ask",
		"",
	} {
		if _, err := ResolveLifecycle(AgentOpenCode, bad); err == nil {
			t.Errorf("ResolveLifecycle(opencode, %q) should error: not a wired OpenCode event", bad)
		}
	}
}

// Installer/runtime parity: for every lifecycle the installer wires
// (openCodeHookLifecycles, surfaced via OpenCodeLifecycleArgs), the runtime
// resolver must map BOTH the numbat lifecycle arg the installer bakes into the
// plugin command AND the raw OpenCode event name OpenCode itself fires to the same
// numbat Lifecycle — and onward to the same model.EventType. This pins that the
// two entry paths (the plugin's `numbat hook <arg>` invocation vs the raw event)
// never drift apart for any wired lifecycle.
func TestOpenCodeInstallerResolverLifecycleParity(t *testing.T) {
	// rawFor maps each wired numbat lifecycle to the raw OpenCode event name the
	// plugin observes and forwards for it. The plugin invokes numbat with the
	// lifecycle arg, but OpenCode at runtime would resolve the raw event; both must
	// agree.
	rawFor := map[Lifecycle]string{
		LifecycleOpenCodePreTool:  "tool.execute.before",
		LifecycleOpenCodePostTool: "tool.execute.after",
		LifecyclePromptSubmit:     "chat.message",
		LifecycleAssistant:        "message.updated",
		LifecycleSessionStart:     "session.created",
		LifecycleSessionEnd:       "session.deleted",
	}
	for _, lc := range openCodeHookLifecycles {
		// The path the installed plugin command takes: the numbat lifecycle arg.
		fromArg, err := ResolveLifecycle(AgentOpenCode, string(lc))
		if err != nil {
			t.Errorf("ResolveLifecycle(opencode, lifecycle arg %q): %v", lc, err)
			continue
		}
		raw, ok := rawFor[lc]
		if !ok {
			t.Errorf("wired lifecycle %q has no raw-event mapping in the parity table", lc)
			continue
		}
		fromRaw, err := ResolveLifecycle(AgentOpenCode, raw)
		if err != nil {
			t.Errorf("ResolveLifecycle(opencode, raw event %q): %v", raw, err)
			continue
		}
		if fromArg != fromRaw {
			t.Errorf("lifecycle %q: installer arg resolves to %q but raw event %q resolves to %q (installer/runtime drift)",
				lc, fromArg, raw, fromRaw)
			continue
		}
		// Both entry paths must also yield the same mapped EventType, so a future
		// divergence in Map (not just ResolveLifecycle) is caught too.
		argEvent := Map(fromArg, AgentOpenCode, model.AgentOpenCode, "parity", map[string]any{})
		rawEvent := Map(fromRaw, AgentOpenCode, model.AgentOpenCode, "parity", map[string]any{})
		if argEvent.EventType != rawEvent.EventType {
			t.Errorf("lifecycle %q: event_type drift arg=%q raw=%q", lc, argEvent.EventType, rawEvent.EventType)
		}
	}
	// Every OpenCodeLifecycleArgs() string must resolve (the diagnostic surface and
	// the wired set agree).
	for _, arg := range OpenCodeLifecycleArgs() {
		if _, err := ResolveLifecycle(AgentOpenCode, arg); err != nil {
			t.Errorf("OpenCodeLifecycleArgs entry %q does not resolve: %v", arg, err)
		}
	}
}

// oc builds an OpenCode hook payload EXACTLY as numbat's generated plugin forwards
// it (see install_opencode.go openCodePluginSource): the built-in tool id is the
// bare "tool" key (OpenCode's input.tool), the arguments live under the FLAT "args"
// key, callID correlates the before/after pair, and sessionID/cwd sit at the top
// level. On the after-moment the plugin also forwards "output" (a compact
// stdout/stderr STRING) and "metadata" (the structured ExecuteResult metadata
// OBJECT carrying e.g. the bash tool's camelCase exitCode). extra merges those
// post-moment top-level keys — there is NO "tool_response" key on the live path.
func oc(toolName string, args map[string]any, extra map[string]any) map[string]any {
	p := map[string]any{
		"tool":      toolName,
		"args":      args,
		"sessionID": "sess-1",
		"callID":    "call-1",
		"cwd":       "/proj",
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// ocMeta builds the top-level "metadata" object the plugin forwards from OpenCode's
// ExecuteResult.metadata on the after-moment, used to feed structured fields
// (exitCode, ...) the way the real plugin emits them.
func ocMeta(metadata map[string]any) map[string]any {
	return map[string]any{"metadata": metadata}
}

// Map must turn each OpenCode tool + moment into the right model.Event type with
// key fields resolved, exercising the real resolve→map path. The OpenCode tool
// vocabulary (bash / read / write / edit / apply_patch / webfetch / websearch)
// must classify identically to the at-rest extractor. Exit codes and tool-error
// flags come ONLY from structured fields, never inferred or fabricated when
// absent; reads never store content; an unknown tool is never promoted to a typed
// action.
func TestMapOpenCodeEvents(t *testing.T) {
	const eventID = "hook-opencode-1"

	tests := []struct {
		name    string
		preTool bool
		payload map[string]any
		want    model.EventType
		check   func(t *testing.T, ev model.Event)
	}{
		// bash → command.exec / command.result, callID correlated.
		{
			name:    "pre bash → command.exec",
			preTool: true,
			payload: oc("bash", map[string]any{"command": "cat .env"}, nil),
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
			// The exit code comes from OpenCode's structured metadata.exitCode (camelCase,
			// the bash tool's artifact-backed field) — NOT a tool_response object, which
			// the live path never emits. OpenCode reports no wall-clock duration field, so
			// DurationMs stays nil (a documented gap, never fabricated).
			name:    "post bash → command.result with structured exitCode from metadata",
			preTool: false,
			payload: oc("bash", map[string]any{"command": "false"}, ocMeta(map[string]any{"exitCode": float64(1)})),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.Command != "false" {
					t.Errorf("command = %q, want false", ev.Command)
				}
				if ev.ExitCode == nil || *ev.ExitCode != 1 {
					t.Errorf("exit_code = %v, want 1 (structured metadata.exitCode)", ev.ExitCode)
				}
				if ev.DurationMs != nil {
					t.Errorf("duration_ms = %v, want nil (OpenCode reports no duration)", ev.DurationMs)
				}
			},
		},
		{
			name:    "post bash with no metadata → no exit fabricated",
			preTool: false,
			payload: oc("bash", map[string]any{"command": "echo hi"}, map[string]any{"output": "hi\n"}),
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
			// A clean exit 0 in metadata must surface as 0 (not be lost as "absent"):
			// the structured numeric field is present, so ExitCode is set distinctly.
			name:    "post bash with metadata.exitCode 0 → exit 0 surfaced",
			preTool: false,
			payload: oc("bash", map[string]any{"command": "true"}, ocMeta(map[string]any{"exitCode": float64(0)})),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ExitCode == nil || *ev.ExitCode != 0 {
					t.Errorf("exit_code = %v, want 0 (clean exit is distinct from absent)", ev.ExitCode)
				}
			},
		},
		// read → file.read, content never stored.
		{
			name:    "pre read → file.read, content never stored",
			preTool: true,
			payload: oc("read", map[string]any{"filePath": "/proj/.env", "content": "SECRET=abc123"}, nil),
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
		// write / edit → file.write.
		{
			name:    "pre write → file.write",
			preTool: true,
			payload: oc("write", map[string]any{"filePath": "/proj/new.go"}, nil),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "/proj/new.go" {
					t.Errorf("file_path = %q, want /proj/new.go", ev.FilePath)
				}
				if ev.Command != "" {
					t.Errorf("file.write must carry no command, got %q", ev.Command)
				}
				if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("no structured diff reported → no diff, got %q/%d", ev.DiffSHA256, ev.DiffBytes)
				}
			},
		},
		{
			name:    "post edit → tool.result",
			preTool: false,
			payload: oc("edit", map[string]any{"filePath": "/proj/y.go"}, map[string]any{"output": "patched"}),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.FilePath != "" || ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
					t.Errorf("tool.result repeated action fields: %+v", ev)
				}
			},
		},
		// apply_patch → file.write (structured multi-file edit; no per-file path).
		{
			name:    "pre apply_patch → file.write",
			preTool: true,
			payload: oc("apply_patch", map[string]any{}, nil),
			want:    model.EventFileWrite,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "apply_patch" {
					t.Errorf("tool_name = %q, want apply_patch", ev.ToolName)
				}
			},
		},
		// webfetch carries an http(s) url, promoted only when it validates.
		{
			name:    "pre webfetch with explicit http url → network.indicator",
			preTool: true,
			payload: oc("webfetch", map[string]any{"url": "https://evil.example/x"}, nil),
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
			name:    "pre webfetch with non-http url → no fabricated network target",
			preTool: true,
			payload: oc("webfetch", map[string]any{"url": "file:///etc/passwd"}, nil),
			want:    model.EventNetworkIndicator,
			check: func(t *testing.T, ev model.Event) {
				if ev.URL != "" {
					t.Errorf("url = %q, want empty (non-http(s) is not promoted)", ev.URL)
				}
				if ev.ContentPreview != "file:///etc/passwd" {
					t.Errorf("content_preview = %q, want the raw value as preview", ev.ContentPreview)
				}
				if !hasTag(ev.Tags, model.TagNetwork) {
					t.Errorf("tags = %v, want network", ev.Tags)
				}
			},
		},
		// websearch carries a query (no url fetched).
		{
			name:    "pre websearch with query → network.indicator preview, no url",
			preTool: true,
			payload: oc("websearch", map[string]any{"query": "how to exfiltrate"}, nil),
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
		// Unknown / MCP tool → generic vocabulary, narrow (no alias promotion).
		{
			name:    "pre unknown tool → tool.call, no alias promotion",
			preTool: true,
			payload: oc("some_custom_tool", map[string]any{"foo": "bar"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "some_custom_tool" {
					t.Errorf("tool_name = %q, want some_custom_tool", ev.ToolName)
				}
				if ev.Command != "" || ev.FilePath != "" || ev.URL != "" {
					t.Errorf("unknown tool must not be promoted: cmd=%q path=%q url=%q", ev.Command, ev.FilePath, ev.URL)
				}
			},
		},
		{
			name:    "post unknown tool → tool.result",
			preTool: false,
			payload: oc("some_custom_tool", map[string]any{"foo": "bar"}, nil),
			want:    model.EventToolResult,
			check: func(t *testing.T, ev model.Event) {
				if ev.ToolName != "some_custom_tool" {
					t.Errorf("tool_name = %q, want some_custom_tool", ev.ToolName)
				}
			},
		},
		{
			name:    "pre mcp-named tool → tool.call splits server/tool",
			preTool: true,
			payload: oc("mcp__github__create_issue", map[string]any{"title": "x"}, nil),
			want:    model.EventToolCall,
			check: func(t *testing.T, ev model.Event) {
				if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
					t.Errorf("mcp split = %q/%q, want github/create_issue", ev.MCPServer, ev.MCPTool)
				}
			},
		},
		{
			// HIGH-PRECISION CONTRACT: OpenCode's tool.execute.after fires only AFTER the
			// tool SUCCEEDS (a failure raises an Effect ToolFailure and the after-hook may
			// not fire), so there is NO reliable structured "errored" boolean on the live
			// after-event. numbat must NOT set a tool_error tag for OpenCode live events —
			// not even when the output STRING contains the word "error" (prose-scraping is
			// forbidden). A documented false negative beats a fabricated false positive.
			name:    "post bash with error prose in output → NO tool_error tag",
			preTool: false,
			payload: oc("bash", map[string]any{"command": "false"}, map[string]any{"output": "command failed: error"}),
			want:    model.EventCommandResult,
			check: func(t *testing.T, ev model.Event) {
				if hasTag(ev.Tags, model.TagToolError) {
					t.Errorf("tags = %v, want NO tool_error (no structured errored signal on the live path)", ev.Tags)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lc := LifecycleOpenCodePostTool
			if tc.preTool {
				lc = LifecycleOpenCodePreTool
			}
			ev := Map(lc, AgentOpenCode, model.AgentOpenCode, eventID, tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q", ev.EventType, tc.want)
			}
			if ev.SourceAgent != model.AgentOpenCode {
				t.Errorf("source_agent = %q, want opencode", ev.SourceAgent)
			}
			assertHookProvenance(t, ev)
			if err := ev.Validate(); err != nil {
				t.Errorf("mapped opencode event failed Validate: %v", err)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestMapOpenCodeCurrentNetworkTools(t *testing.T) {
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{tool: "fetch", args: map[string]any{"url": "https://example.com"}},
		{tool: "search", args: map[string]any{"query": "numbat"}},
		{tool: "code", args: map[string]any{"query": "symbol"}},
	} {
		ev := Map(LifecycleOpenCodePreTool, AgentOpenCode, model.AgentOpenCode, "e", oc(tc.tool, tc.args, nil))
		if ev.EventType != model.EventNetworkIndicator {
			t.Errorf("%s event_type = %q, want network.indicator", tc.tool, ev.EventType)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: %v", tc.tool, err)
		}
	}
}

func TestMapOpenCodeApplyPatchAndSubagent(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: old.go\n*** Move to: new.go\n*** End Patch\n"
	events := MapEvents(LifecycleOpenCodePreTool, AgentOpenCode, model.AgentOpenCode, "e", oc("apply_patch", map[string]any{"patchText": patch}, nil))
	if len(events) != 2 || events[0].EventType != model.EventFileDelete || events[0].FilePath != "old.go" ||
		events[1].EventType != model.EventFileWrite || events[1].FilePath != "new.go" {
		t.Fatalf("apply_patch events = %+v", events)
	}
	for _, ev := range events {
		if ev.DiffSHA256 == "" || ev.DiffBytes == 0 {
			t.Errorf("patch event missing digest: %+v", ev)
		}
	}

	task := Map(LifecycleOpenCodePreTool, AgentOpenCode, model.AgentOpenCode, "task", oc("task", map[string]any{"subagent_type": "research"}, nil))
	if task.SubAgent != "research" {
		t.Errorf("task sub_agent = %q, want research", task.SubAgent)
	}

	contextual := Map(LifecycleOpenCodePreTool, AgentOpenCode, model.AgentOpenCode, "ctx", map[string]any{
		"tool": "bash", "args": map[string]any{"command": "pwd"}, "subAgent": "explore",
		"model": "gpt-5", "modelProvider": "openai", "cwd": "/p",
	})
	if contextual.SubAgent != "explore" || contextual.Model != "gpt-5" || contextual.ModelProvider != "openai" || contextual.ProjectPath != "/p" {
		t.Errorf("context fields = %+v", contextual)
	}
}

// A non-zero exit code alone must NOT raise tool_error: the error flag is
// explicit-only (a clean command can exit non-zero and still not be "errored").
// Guards the no-inference rule for the structured path.
func TestMapOpenCodeExitCodeAloneIsNotToolError(t *testing.T) {
	payload := oc("bash", map[string]any{"command": "false"}, ocMeta(map[string]any{"exitCode": float64(2)}))
	ev := Map(LifecycleOpenCodePostTool, AgentOpenCode, model.AgentOpenCode, "e", payload)
	if ev.ExitCode == nil || *ev.ExitCode != 2 {
		t.Fatalf("exit_code = %v, want 2", ev.ExitCode)
	}
	if hasTag(ev.Tags, model.TagToolError) {
		t.Errorf("tags = %v, want NO tool_error from a non-zero exit alone", ev.Tags)
	}
}

// A write whose payload carries no structured diff must NOT get a fabricated
// digest — the edit body is never hashed at the hook boundary.
func TestMapOpenCodeWriteNoFabricatedDiff(t *testing.T) {
	for _, tool := range []string{"write", "edit", "apply_patch"} {
		payload := oc(tool, map[string]any{"filePath": "/p/f", "content": "real body"}, nil)
		ev := Map(LifecycleOpenCodePostTool, AgentOpenCode, model.AgentOpenCode, "e", payload)
		if ev.DiffSHA256 != "" || ev.DiffBytes != 0 {
			t.Errorf("%s: fabricated diff %q/%d, want none (no structured diff reported)", tool, ev.DiffSHA256, ev.DiffBytes)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: event failed Validate: %v", tool, err)
		}
	}
}

// An OpenCode event with an empty payload must still yield a well-formed,
// hook-stamped event so the live handler never fails the agent on a bad body. This
// covers every wired moment.
func TestMapOpenCodeEmptyPayloadIsWellFormed(t *testing.T) {
	for _, lc := range openCodeHookLifecycles {
		got := Map(lc, AgentOpenCode, model.AgentOpenCode, "hook-x", map[string]any{})
		assertHookProvenance(t, got)
		if err := got.Validate(); err != nil {
			t.Errorf("empty %q event failed Validate: %v", lc, err)
		}
	}
}

// TestMapOpenCodeLiveShapeParity is the anti-drift guard: it builds the post-tool
// payload by literally mirroring the keys numbat's generated plugin forwards on
// tool.execute.after and asserts the resolved Event carries the structured
// exitCode from metadata. If the test shape ever drifts from the plugin's real
// emission — the exact failure mode that masked the original blocking bug, where
// the test fed a synthetic tool_response the plugin never emits — this fails.
func TestMapOpenCodeLiveShapeParity(t *testing.T) {
	// EXACTLY the object the plugin's forward("opencode-post-tool", {...}) builds.
	livePayload := map[string]any{
		"tool":      "bash",
		"sessionID": "sess-1",
		"callID":    "call-xyz",
		"args":      map[string]any{"command": "false"},
		"metadata":  map[string]any{"command": "false", "cwd": "/proj", "exitCode": float64(3)},
	}
	ev := Map(LifecycleOpenCodePostTool, AgentOpenCode, model.AgentOpenCode, "live-1", livePayload)
	if ev.EventType != model.EventCommandResult {
		t.Fatalf("event_type = %q, want command.result", ev.EventType)
	}
	if ev.Command != "false" {
		t.Errorf("command = %q, want false (from live args)", ev.Command)
	}
	if ev.ExitCode == nil || *ev.ExitCode != 3 {
		t.Errorf("exit_code = %v, want 3 (from live metadata.exitCode)", ev.ExitCode)
	}
	if ev.ToolCallID != "call-xyz" {
		t.Errorf("tool_call_id = %q, want call-xyz (live callID)", ev.ToolCallID)
	}
	if hasTag(ev.Tags, model.TagToolError) {
		t.Errorf("tags = %v, want NO tool_error (no structured errored signal live)", ev.Tags)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("live-shape event failed Validate: %v", err)
	}
}

// TestMapOpenCodeCallIDCorrelatesPreAndPost pins that the plugin's callID survives
// onto BOTH the pre and post tool events as model.Event.ToolCallID, so a live
// tool.execute.before/after pair can be correlated — the same correlation the
// at-rest OpenCode extractor provides via part.CallID.
func TestMapOpenCodeCallIDCorrelatesPreAndPost(t *testing.T) {
	args := map[string]any{"command": "echo hi"}
	pre := Map(LifecycleOpenCodePreTool, AgentOpenCode, model.AgentOpenCode, "p", oc("bash", args, nil))
	post := Map(LifecycleOpenCodePostTool, AgentOpenCode, model.AgentOpenCode, "q", oc("bash", args, nil))
	if pre.ToolCallID != "call-1" || post.ToolCallID != "call-1" {
		t.Errorf("callID not stamped on both events: pre=%q post=%q, want call-1/call-1", pre.ToolCallID, post.ToolCallID)
	}
}

// TestOpenCodePluginForwardsLiveShapeKeys pins the OTHER half of the parity
// contract: the generated plugin source must actually forward the keys the runtime
// reads on the after-moment (tool, callID, args, metadata). Together with
// TestMapOpenCodeLiveShapeParity (which maps that exact shape) this catches drift
// from either side — the installer can't stop emitting a key the runtime needs, and
// the runtime test can't assert a shape the installer never emits.
func TestOpenCodePluginForwardsLiveShapeKeys(t *testing.T) {
	src := openCodePluginSourceWithArgs("/usr/local/bin/numbat", nil)
	for _, key := range []string{
		"tool: input?.tool",
		"callID: input?.callID",
		"args: input?.args",
		"metadata: output?.metadata",
	} {
		if !strings.Contains(src, key) {
			t.Errorf("generated plugin missing live-shape forward %q:\n%s", key, src)
		}
	}
	if !strings.Contains(src, "output: output?.output") {
		t.Error("generated plugin drops tool output")
	}
}

// numbat installs the OpenCode plugin OBSERVE-ONLY and the plugin never reads
// numbat's stdout, so the passthrough is the inert empty object. It must be a
// fresh map each call.
func TestOpenCodePassthroughIsInert(t *testing.T) {
	resp := PassthroughResponse(AgentOpenCode, LifecycleOpenCodePreTool)
	if len(resp) != 0 {
		t.Errorf("passthrough = %v, want empty object {}", resp)
	}
	resp["x"] = 1
	if len(PassthroughResponse(AgentOpenCode, LifecycleOpenCodePreTool)) != 0 {
		t.Error("PassthroughResponse must return a fresh map each call")
	}
}

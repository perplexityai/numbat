package extract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// jsonString encodes s as a JSON string literal (with surrounding quotes and
// escaped control characters), so a fixture can embed multi-line tool output —
// e.g. a "Exit code: N\nOutput:\n..." body — without hand-escaping it.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// codexFixture is a realistic rollout covering the shapes Codex emits: the
// session_meta header (seeds identity, emits nothing), a user message, an
// assistant message, a shell function_call with a string command, a
// local_shell_call with an argv array, an apply_patch touching two files (with a
// hunk body to prove envelope bounding), the explicit file tools, a
// custom_tool_call (MCP-routed), a web_search_call, a function_call_output, a
// tool_search_output, a turn_context that changes the cwd, the event_msg
// anomalies (turn_aborted, thread_rolled_back), and the no-twin state
// transitions (entered/exited_review_mode, thread_goal_updated). event_msg
// duplicates of response_item records (user_message/agent_message/
// patch_apply_end) and an inner compaction variant are present to prove they
// are skipped (no double-counting).
const codexFixture = `{"timestamp":"2026-06-02T10:00:00Z","type":"session_meta","payload":{"id":"thread-1","cwd":"/home/dev/proj","cli_version":"0.9.0"}}
{"timestamp":"2026-06-02T10:00:01Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"read the env then build"}]}}
{"timestamp":"2026-06-02T10:00:02Z","type":"event_msg","payload":{"type":"user_message","message":"read the env then build"}}
{"timestamp":"2026-06-02T10:00:03Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"On it."}]}}
{"timestamp":"2026-06-02T10:00:04Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":\"cat .env\"}"}}
{"timestamp":"2026-06-02T10:00:05Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"c2","status":"completed","action":{"type":"exec","command":["make","build"]}}}
{"timestamp":"2026-06-02T10:00:06Z","type":"response_item","payload":{"type":"function_call","name":"apply_patch","call_id":"c3","arguments":"{\"patch\":\"*** Begin Patch\n*** Add File: src/new.go\n+package main\n*** Update File: src/old.go\n@@\n-x\n+y\n*** End Patch\"}"}}
{"timestamp":"2026-06-02T10:00:07Z","type":"event_msg","payload":{"type":"patch_apply_end","success":true}}
{"timestamp":"2026-06-02T10:00:08Z","type":"response_item","payload":{"type":"function_call","name":"read_file","call_id":"c4","arguments":"{\"path\":\"/home/dev/proj/cfg.yaml\"}"}}
{"timestamp":"2026-06-02T10:00:09Z","type":"response_item","payload":{"type":"function_call","name":"create_file","call_id":"c5","arguments":"{\"path\":\"/home/dev/proj/out.txt\"}"}}
{"timestamp":"2026-06-02T10:00:10Z","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"c6","input":"SELECT 1"}}
{"timestamp":"2026-06-02T10:00:11Z","type":"response_item","payload":{"type":"web_search_call","call_id":"c7","action":{"query":"golang zstd"}}}
{"timestamp":"2026-06-02T10:00:12Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"SECRET=xyz"}}
{"timestamp":"2026-06-02T10:00:13Z","type":"response_item","payload":{"type":"tool_search_output","call_id":"c8","status":"completed","tools":[{"type":"function","name":"read_file"},{"type":"function","name":"mcp__codex_apps__calendar_create_event"}]}}
{"timestamp":"2026-06-02T10:00:14Z","type":"event_msg","payload":{"type":"agent_message","message":"On it."}}
{"timestamp":"2026-06-02T10:00:15Z","type":"turn_context","payload":{"cwd":"/home/dev/other"}}
{"timestamp":"2026-06-02T10:00:16Z","type":"event_msg","payload":{"type":"entered_review_mode","turn_id":"t9"}}
{"timestamp":"2026-06-02T10:00:17Z","type":"event_msg","payload":{"type":"exited_review_mode","turn_id":"t9"}}
{"timestamp":"2026-06-02T10:00:18Z","type":"event_msg","payload":{"type":"thread_goal_updated","turn_id":"t9"}}
{"timestamp":"2026-06-02T10:00:19Z","type":"event_msg","payload":{"type":"turn_aborted","reason":"interrupted","turn_id":"t9"}}
{"timestamp":"2026-06-02T10:00:20Z","type":"event_msg","payload":{"type":"thread_rolled_back"}}
{"timestamp":"2026-06-02T10:00:21Z","type":"response_item","payload":{"type":"compaction","encrypted_content":"opaque"}}
{"timestamp":"2026-06-02T10:00:22Z","type":"response_item","payload":{"type":"reasoning","content":[{"type":"text","text":"thinking"}]}}
{"timestamp":"2026-06-02T10:00:23Z","type":"compacted","payload":{"summary":"history compacted"}}`

func extractCodex(t *testing.T, body string) *Result {
	t.Helper()
	res, err := CodexExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/rollout.jsonl", CaseID: "case-1"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

func TestExtractCodexMapsAllShapes(t *testing.T) {
	res := extractCodex(t, codexFixture)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}

	type want struct {
		etype   model.EventType
		actor   string
		tool    string
		cmd     string
		path    string
		preview string
		tag     string
		conf    string
	}
	// Events follow artifact order. session_meta, turn_context, the event_msg
	// duplicates (user_message/agent_message/patch_apply_end), the inner
	// compaction variant, reasoning, and compacted emit nothing. apply_patch
	// emits one file event per touched file at medium confidence (a requested,
	// not confirmed, change) tagged patch_apply_requested.
	const reqTag = "patch_apply_requested"
	wants := []want{
		{model.EventPromptUser, model.ActorUser, "", "", "", "read the env then build", "", model.ConfidenceHigh},
		{model.EventMessageAssistant, model.ActorAssistant, "", "", "", "On it.", "", model.ConfidenceHigh},
		{model.EventCommandExec, model.ActorAssistant, "shell", "cat .env", "", "", "", model.ConfidenceHigh},
		{model.EventCommandExec, model.ActorAssistant, "shell", "make build", "", "", "", model.ConfidenceHigh},
		{model.EventFileWrite, model.ActorAssistant, "apply_patch", "", "src/new.go", "", reqTag, model.ConfidenceMedium},
		{model.EventFileWrite, model.ActorAssistant, "apply_patch", "", "src/old.go", "", reqTag, model.ConfidenceMedium},
		{model.EventFileRead, model.ActorAssistant, "read_file", "", "/home/dev/proj/cfg.yaml", "", "", model.ConfidenceHigh},
		{model.EventFileWrite, model.ActorAssistant, "create_file", "", "/home/dev/proj/out.txt", "", "", model.ConfidenceHigh},
		{model.EventToolCall, model.ActorAssistant, "mcp__db__query", "", "", "SELECT 1", "", model.ConfidenceHigh},
		{model.EventNetworkIndicator, model.ActorAssistant, "", "", "", "golang zstd", "network", model.ConfidenceHigh},
		// function_call_output for c1 pairs with the shell function_call (c1), so it
		// is a command.result, not a generic tool.result.
		{model.EventCommandResult, model.ActorTool, "", "", "", "SECRET=xyz", "", model.ConfidenceHigh},
		{model.EventToolResult, model.ActorTool, "", "", "", "read_file, mcp__codex_apps__calendar_create_event", "", model.ConfidenceHigh},
		{model.EventMessageAssistant, model.ActorSystem, "", "", "", "", "entered_review_mode", model.ConfidenceLow},
		{model.EventMessageAssistant, model.ActorSystem, "", "", "", "", "exited_review_mode", model.ConfidenceLow},
		{model.EventMessageAssistant, model.ActorSystem, "", "", "", "", "thread_goal_updated", model.ConfidenceLow},
		{model.EventMessageAssistant, model.ActorSystem, "", "", "", "turn aborted: interrupted", "turn_aborted", model.ConfidenceLow},
		{model.EventMessageAssistant, model.ActorSystem, "", "", "", "", "thread_rolled_back", model.ConfidenceLow},
	}
	acts := activityEvents(res.Events)
	if len(acts) != len(wants) {
		t.Fatalf("got %d events, want %d:\n%s", len(acts), len(wants), dumpEvents(res.Events))
	}
	for i, w := range wants {
		ev := acts[i]
		if ev.EventType != w.etype || ev.Actor != w.actor || ev.ToolName != w.tool ||
			ev.Command != w.cmd || ev.FilePath != w.path {
			t.Errorf("event %d = {%s actor=%s tool=%s cmd=%q path=%q}, want {%s actor=%s tool=%s cmd=%q path=%q}",
				i, ev.EventType, ev.Actor, ev.ToolName, ev.Command, ev.FilePath,
				w.etype, w.actor, w.tool, w.cmd, w.path)
		}
		if ev.ContentPreview != w.preview {
			t.Errorf("event %d preview = %q, want %q", i, ev.ContentPreview, w.preview)
		}
		if ev.Confidence != w.conf {
			t.Errorf("event %d confidence = %s, want %s", i, ev.Confidence, w.conf)
		}
		if w.tag != "" && (len(ev.Tags) != 1 || ev.Tags[0] != w.tag) {
			t.Errorf("event %d tags = %v, want [%s]", i, ev.Tags, w.tag)
		}
		if w.tag == "" && len(ev.Tags) != 0 {
			t.Errorf("event %d tags = %v, want none", i, ev.Tags)
		}
	}
	assertUniqueEventIDs(t, res.Events)
}

func TestExtractCodexPrefersUserMessageEvent(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t0","type":"session_meta","payload":{"id":"thread-1","cwd":"/repo"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>injected</environment_context>"}]}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"inspect the service"}]}}`,
		`{"timestamp":"t3","type":"event_msg","payload":{"type":"user_message","message":"inspect the service"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<subagent_notification>injected</subagent_notification>"}]}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want one user prompt:\n%s", len(acts), dumpEvents(acts))
	}
	prompt := acts[0]
	if prompt.EventType != model.EventPromptUser || prompt.ContentPreview != "inspect the service" {
		t.Fatalf("prompt = %+v", prompt)
	}
	if prompt.Timestamp != "t3" || prompt.Evidence.Line != 4 || prompt.Evidence.JSONPointer != "/payload/message" {
		t.Errorf("canonical prompt provenance = %q line %d %q", prompt.Timestamp, prompt.Evidence.Line, prompt.Evidence.JSONPointer)
	}
}

func TestExtractCodexPaginatedUserMessage(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t0","type":"session_meta","payload":{"id":"thread-1","cwd":"/repo","history_mode":"paginated"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"paginated prompt"}]}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"item_completed","item":{"type":"UserMessage","id":"u1","content":[{"type":"text","text":"paginated"},{"type":"text","text":" "},{"type":"text","text":"prompt"}]}}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 1 || acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != "paginated prompt" {
		t.Fatalf("paginated prompt =\n%s", dumpEvents(acts))
	}
	if acts[0].Evidence.Line != 3 || acts[0].Evidence.JSONPointer != "/payload/item/content" {
		t.Errorf("paginated prompt provenance = line %d %q", acts[0].Evidence.Line, acts[0].Evidence.JSONPointer)
	}
}

func TestExtractCodexNamespacedNativeNamesStayGeneric(t *testing.T) {
	cases := []struct {
		name   string
		tool   string
		call   string
		output string
	}{
		{
			name:   "exec command",
			tool:   "exec_command",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","namespace":"mcp__remote","name":"exec_command","call_id":"c","arguments":"{\"cmd\":\"id\"}"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"uid=1"}}`,
		},
		{
			name:   "apply patch",
			tool:   "apply_patch",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","namespace":"mcp__remote","name":"apply_patch","call_id":"c","arguments":"{\"patch\":\"*** Begin Patch\\n*** Add File: x\\n+x\\n*** End Patch\"}"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"done"}}`,
		},
		{
			name:   "read file",
			tool:   "read_file",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","namespace":"mcp__remote","name":"read_file","call_id":"c","arguments":"{\"path\":\"/etc/passwd\"}"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"body"}}`,
		},
		{
			name:   "create file",
			tool:   "create_file",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","namespace":"mcp__remote","name":"create_file","call_id":"c","arguments":"{\"path\":\"/tmp/x\"}"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"done"}}`,
		},
		{
			name:   "edit file",
			tool:   "edit_file",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","namespace":"mcp__remote","name":"edit_file","call_id":"c","arguments":"{\"path\":\"/tmp/x\"}"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"done"}}`,
		},
		{
			name:   "code mode exec",
			tool:   "exec",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","namespace":"mcp__remote","name":"exec","call_id":"c","input":"await tools.exec_command({cmd: 'id'})"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"c","output":"uid=1"}}`,
		},
		{
			name:   "custom apply patch",
			tool:   "apply_patch",
			call:   `{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","namespace":"mcp__remote","name":"apply_patch","call_id":"c","input":"*** Begin Patch\\n*** Add File: x\\n+x\\n*** End Patch"}}`,
			output: `{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"c","output":"done"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Join([]string{
				`{"timestamp":"t0","type":"session_meta","payload":{"id":"thread-1","cwd":"/repo"}}`,
				tc.call,
				tc.output,
			}, "\n")
			acts := activityEvents(extractCodex(t, body).Events)
			if len(acts) != 2 {
				t.Fatalf("got %d events, want call + result:\n%s", len(acts), dumpEvents(acts))
			}
			call, result := acts[0], acts[1]
			if call.EventType != model.EventToolCall || call.ToolName != tc.tool || call.MCPServer != "remote" || call.MCPTool != tc.tool {
				t.Errorf("call was specialized or lost namespace: %+v", call)
			}
			if call.Command != "" || call.FilePath != "" || call.DiffSHA256 != "" {
				t.Errorf("generic MCP call carries fabricated native fields: %+v", call)
			}
			if result.EventType != model.EventToolResult || result.ToolCallID != "c" {
				t.Errorf("result was promoted to a native result: %+v", result)
			}
		})
	}
}

// The running project path is seeded by session_meta's cwd and updated by a
// later turn_context; events emitted before and after the turn_context must
// carry the corresponding directory.
func TestExtractCodexTracksProjectPath(t *testing.T) {
	acts := activityEvents(extractCodex(t, codexFixture).Events)
	// The user prompt (first activity event) precedes the turn_context.
	if acts[0].ProjectPath != "/home/dev/proj" {
		t.Errorf("pre-turn project path = %q, want /home/dev/proj", acts[0].ProjectPath)
	}
	// thread_rolled_back is the last activity event, emitted after turn_context
	// changed the cwd to /home/dev/other.
	last := acts[len(acts)-1]
	if last.ProjectPath != "/home/dev/other" {
		t.Errorf("post-turn project path = %q, want /home/dev/other", last.ProjectPath)
	}
}

func TestExtractCodexStampsProvenance(t *testing.T) {
	res := extractCodex(t, codexFixture)
	first := activityEvents(res.Events)[0]
	if first.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", first.SchemaVersion, model.SchemaVersion)
	}
	if first.SourceAgent != model.AgentCodex || first.SourceType != model.SourceArtifact {
		t.Errorf("source = %s/%s, want %s/%s", first.SourceAgent, first.SourceType, model.AgentCodex, model.SourceArtifact)
	}
	if first.CaseID != "case-1" {
		t.Errorf("case_id = %q, want case-1", first.CaseID)
	}
	if first.SessionID != "thread-1" {
		t.Errorf("session_id = %q, want thread-1", first.SessionID)
	}
	if first.Timestamp != "2026-06-02T10:00:02Z" {
		t.Errorf("timestamp = %q, want 2026-06-02T10:00:02Z", first.Timestamp)
	}
	ev := first.Evidence
	// The canonical user_message is on line 3 of the fixture.
	if ev.ArtifactType != artifactCodexRollout || ev.LocalPath != "/cases/rollout.jsonl" || ev.Line != 3 {
		t.Errorf("evidence = %+v", ev)
	}
	if ev.JSONPointer != "/payload/message" {
		t.Errorf("json_pointer = %q, want /payload/message", ev.JSONPointer)
	}
	if len(ev.SHA256) != 64 {
		t.Errorf("sha256 = %q, want 64 hex chars", ev.SHA256)
	}
	// Every event from one artifact shares the same content hash.
	for _, e := range res.Events {
		if e.Evidence.SHA256 != ev.SHA256 {
			t.Fatalf("inconsistent sha256 across events")
		}
	}
	// EventID is codex-<16hex>, deterministic from path:line:idx.
	if !strings.HasPrefix(first.EventID, "codex-") || len(first.EventID) != len("codex-")+16 {
		t.Errorf("event_id = %q, want codex-<16hex>", first.EventID)
	}
}

func TestExtractCodexAgent(t *testing.T) {
	if got := (CodexExtractor{}).Agent(); got != model.AgentCodex {
		t.Errorf("Agent() = %q, want %q", got, model.AgentCodex)
	}
}

// The shell tool's command may be a string OR an argv array inside the
// JSON-encoded arguments; both must surface as a command. local_shell_call's
// action.exec.command is always an argv array.
func TestExtractCodexShellCommandShapes(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			"shell string command",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":\"ls -la\"}"}}`,
			"ls -la",
		},
		{
			"shell argv command",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"ls\"]}"}}`,
			"bash -lc ls",
		},
		{
			"shell_command legacy name",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"pwd\"}"}}`,
			"pwd",
		},
		{
			"exec_command current name and cmd field",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"go test ./...\",\"workdir\":\"/repo\"}"}}`,
			"go test ./...",
		},
		{
			"local_shell_call argv",
			`{"timestamp":"t","type":"response_item","payload":{"type":"local_shell_call","action":{"type":"exec","command":["git","status"]}}}`,
			"git status",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := extractCodex(t, tc.line)
			if len(res.Events) != 1 {
				t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
			}
			ev := res.Events[0]
			if ev.EventType != model.EventCommandExec || ev.Command != tc.want {
				t.Errorf("got %s cmd=%q, want command.exec cmd=%q", ev.EventType, ev.Command, tc.want)
			}
		})
	}
}

// apply_patch with no recognizable path header still surfaces as a single
// medium-confidence file.write so the write is never dropped, tagged as a
// requested change.
func TestExtractCodexApplyPatchUnparseableFallback(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{\"patch\":\"garbage with no headers\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventFileWrite || ev.Confidence != model.ConfidenceMedium || ev.FilePath != "" {
		t.Errorf("got %s conf=%s path=%q, want file.write/medium/empty", ev.EventType, ev.Confidence, ev.FilePath)
	}
	if len(ev.Tags) != 1 || ev.Tags[0] != "patch_apply_requested" {
		t.Errorf("tags = %v, want [patch_apply_requested]", ev.Tags)
	}
}

func TestExtractCodexCustomApplyPatch(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","call_id":"p1","input":"*** Begin Patch\n*** Update File: a.go\n@@\n-old\n+new\n*** Delete File: gone.go\n*** End Patch"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %s", len(res.Events), dumpEvents(res.Events))
	}
	for i, want := range []struct {
		type_ model.EventType
		path  string
	}{{model.EventFileWrite, "a.go"}, {model.EventFileDelete, "gone.go"}} {
		ev := res.Events[i]
		if ev.EventType != want.type_ || ev.FilePath != want.path || ev.ToolName != "apply_patch" || ev.ToolCallID != "p1" {
			t.Errorf("event %d = %+v, want %s %s", i, ev, want.type_, want.path)
		}
		if ev.Confidence != model.ConfidenceMedium || ev.DiffSHA256 == "" || ev.DiffBytes == 0 || ev.Evidence.JSONPointer != "/payload/input" || !hasTag(ev.Tags, codexTagPatchRequested) {
			t.Errorf("event %d missing custom patch context: %+v", i, ev)
		}
	}
}

func TestExtractCodexCustomExecStaysGeneric(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"e1","input":"await tools.exec_command({cmd: 'git status'})"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventToolCall || ev.ToolName != "exec" || ev.Command != "" {
		t.Errorf("custom exec was promoted to a shell command: %+v", ev)
	}
}

// A move removes its source path and writes its destination.
func TestExtractCodexApplyPatchDeleteAndMove(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{\"patch\":\"*** Begin Patch\n*** Delete File: a/gone.go\n*** Update File: b/keep.go\n*** Move to: b/moved.go\n*** End Patch\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 3 {
		t.Fatalf("got %d events, want 3: %s", len(res.Events), dumpEvents(res.Events))
	}
	type pe struct {
		path  string
		etype model.EventType
	}
	want := []pe{
		{"a/gone.go", model.EventFileDelete},
		{"b/keep.go", model.EventFileDelete},
		{"b/moved.go", model.EventFileWrite},
	}
	for i, w := range want {
		ev := res.Events[i]
		if ev.FilePath != w.path || ev.EventType != w.etype {
			t.Errorf("event %d = %s path=%q, want %s %q", i, ev.EventType, ev.FilePath, w.etype, w.path)
		}
		if ev.Confidence != model.ConfidenceMedium {
			t.Errorf("event %d confidence = %s, want medium", i, ev.Confidence)
		}
		if len(ev.Tags) != 1 || ev.Tags[0] != "patch_apply_requested" {
			t.Errorf("event %d tags = %v, want [patch_apply_requested]", i, ev.Tags)
		}
	}
	assertUniqueEventIDs(t, res.Events)
}

// Each file event from an apply_patch carries a diff digest+size summarizing the
// whole patch: DiffSHA256 is the bare hex SHA-256 of the patch text and DiffBytes
// its length. Every change from one apply_patch shares the patch, so the digest is
// identical across the events it produced — letting a reviewer confirm two edits
// came from the same patch without the patch leaving the box.
func TestExtractCodexApplyPatchDiffDigest(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{\"patch\":\"*** Begin Patch\n*** Delete File: a/gone.go\n*** Update File: b/keep.go\n*** End Patch\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %s", len(res.Events), dumpEvents(res.Events))
	}
	// Both events came from one apply_patch, so they share one digest: a non-empty
	// 64-hex SHA-256 and a positive byte count. The shared value is the invariant a
	// reviewer relies on to tie edits to the same patch.
	first := res.Events[0].DiffSHA256
	if len(first) != 64 {
		t.Errorf("diff_sha256 = %q, want a 64-char hex digest", first)
	}
	for i, ev := range res.Events {
		if ev.DiffSHA256 != first {
			t.Errorf("event %d diff_sha256 = %q, want shared %q", i, ev.DiffSHA256, first)
		}
		if ev.DiffBytes <= 0 {
			t.Errorf("event %d diff_bytes = %d, want > 0", i, ev.DiffBytes)
		}
	}
}

// An apply_patch with no recognizable path still carries the diff digest+size on
// its single fallback file.write — the summary is attached to the write even when
// the path could not be parsed.
func TestExtractCodexApplyPatchFallbackCarriesDiff(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{\"patch\":\"garbage with no headers\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.DiffSHA256 != model.HashContent([]byte("garbage with no headers")) {
		t.Errorf("diff_sha256 = %q, want digest of the patch text", ev.DiffSHA256)
	}
	if ev.DiffBytes != len("garbage with no headers") {
		t.Errorf("diff_bytes = %d, want %d", ev.DiffBytes, len("garbage with no headers"))
	}
}

// A hunk-body line that itself looks like a patch header (e.g. an added line
// "+*** Add File: bait.go" when editing a file that documents the apply_patch
// format) must not fabricate a phantom path. Only the real *** Update File
// header inside the envelope is a path; the leading-plus line is hunk content.
func TestExtractCodexApplyPatchIgnoresHunkBodyHeaders(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{\"patch\":\"*** Begin Patch\n*** Update File: docs/format.md\n@@\n+*** Add File: bait.go\n+*** Delete File: victim.go\n*** End Patch\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1 (only the real header): %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventFileWrite || ev.FilePath != "docs/format.md" {
		t.Errorf("got %s path=%q, want file.write docs/format.md", ev.EventType, ev.FilePath)
	}
}

// A unified-diff CONTEXT line begins with a single leading space (per the
// apply-patch grammar: change_line = "+"|"-"|" "). A context line whose content
// reads like a header (" *** Add File: bait.go") must not forge a phantom path:
// the leading space would otherwise be trimmed away. Only the real *** Update
// File header inside the envelope is a path.
func TestExtractCodexApplyPatchIgnoresContextLineHeaders(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{\"patch\":\"*** Begin Patch\n*** Update File: docs/format.md\n@@\n *** Add File: bait.go\n *** Delete File: victim.go\n-old\n+new\n*** End Patch\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1 (only the real header): %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventFileWrite || ev.FilePath != "docs/format.md" {
		t.Errorf("got %s path=%q, want file.write docs/format.md", ev.EventType, ev.FilePath)
	}
}

// tool_search_output carries a list of tool definitions under "tools" (the
// ToolSearchOutput wire shape), not a free-form "output" string. The preview
// must name the discovered tools, decoded from tools[].name, with the
// /payload/tools pointer.
func TestExtractCodexToolSearchOutputNamesTools(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"tool_search_output","call_id":"x","status":"completed","tools":[{"type":"function","name":"read_file","description":"d"},{"type":"function","name":"mcp__db__query"}]}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventToolResult || ev.ContentPreview != "read_file, mcp__db__query" {
		t.Errorf("got %s preview=%q, want tool.result 'read_file, mcp__db__query'", ev.EventType, ev.ContentPreview)
	}
	if ev.ToolCallID != "x" {
		t.Errorf("tool_call_id = %q, want x", ev.ToolCallID)
	}
	if ev.Evidence.JSONPointer != "/payload/tools" {
		t.Errorf("json_pointer = %q, want /payload/tools", ev.Evidence.JSONPointer)
	}
}

// Codex tool_search_call records can carry structured JSON arguments rather
// than the string-encoded JSON used by function_call. They are valid rollout
// records and should become a useful tool.call preview, not a malformed-payload
// diagnostic.
func TestExtractCodexToolSearchCallStructuredArguments(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"tool_search_call","call_id":"x","status":"completed","execution":"client","arguments":{"query":"spawn subagent code review parallel agent","limit":8}}}`
	res := extractCodex(t, line)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventToolCall || ev.ToolName != codexToolSearch {
		t.Errorf("got %s tool=%q, want tool.call %q", ev.EventType, ev.ToolName, codexToolSearch)
	}
	if ev.ToolCallID != "x" {
		t.Errorf("tool_call_id = %q, want x", ev.ToolCallID)
	}
	if ev.ContentPreview != "spawn subagent code review parallel agent" {
		t.Errorf("preview = %q, want the search query", ev.ContentPreview)
	}
	if ev.Evidence.JSONPointer != "/payload/arguments" {
		t.Errorf("json_pointer = %q, want /payload/arguments", ev.Evidence.JSONPointer)
	}
}

// The canonical MCP fetch server (modelcontextprotocol/servers src/fetch) is
// network egress and must surface on a network.indicator naming the url, the
// same as a web_search_call. Codex routes MCP tools through function_call in
// one of two shapes: flattened (name "mcp__fetch__fetch", no namespace) or split
// (namespace "fetch" + name "fetch"); both are recognized. Any other MCP tool —
// including a different tool on the fetch server, or a non-MCP tool merely named
// "fetch" — stays a generic tool.call, so the match is exact canonical-server
// identity, not a name heuristic.
func TestExtractCodexMCPFetchEgress(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		etype   model.EventType
		preview string
		tag     string
	}{
		{
			"flattened",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__fetch__fetch","call_id":"c","arguments":"{\"url\":\"https://evil.example/a\"}"}}`,
			model.EventNetworkIndicator, "https://evil.example/a", "network",
		},
		{
			// Namespaced form WITH trailing separator: flat_tool_name concatenates
			// namespace+name directly -> "mcp__fetch__"+"fetch" = "mcp__fetch__fetch".
			"namespaced_trailing_sep",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"fetch","namespace":"mcp__fetch__","call_id":"c","arguments":"{\"url\":\"https://evil.example/b\"}"}}`,
			model.EventNetworkIndicator, "https://evil.example/b", "network",
		},
		{
			// Namespaced form WITHOUT trailing separator: codex's
			// format!("mcp__{server}") path yields namespace="mcp__fetch"; the
			// matcher re-inserts the "__" separator before joining.
			"namespaced_no_trailing_sep",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"fetch","namespace":"mcp__fetch","call_id":"c","arguments":"{\"url\":\"https://evil.example/c\"}"}}`,
			model.EventNetworkIndicator, "https://evil.example/c", "network",
		},
		{
			// A bare server name (no mcp__ prefix) flattens to "fetchfetch" and is
			// NOT the canonical MCP fetch identifier, so it stays generic.
			"bare_server_namespace",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"fetch","namespace":"fetch","call_id":"c","arguments":"{\"url\":\"https://x/y\"}"}}`,
			model.EventToolCall, "", "",
		},
		{
			// A different tool on the fetch server stays generic.
			"other_tool_on_fetch_server",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__fetch__status","call_id":"c","arguments":"{\"url\":\"https://x/y\"}"}}`,
			model.EventToolCall, "", "",
		},
		{
			// A non-MCP tool merely named "fetch" (no namespace) is NOT the MCP
			// fetch server and stays generic.
			"bare_fetch_no_namespace",
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"fetch","call_id":"c","arguments":"{\"url\":\"https://x/y\"}"}}`,
			model.EventToolCall, "", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := extractCodex(t, tc.line)
			if len(res.Events) != 1 {
				t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
			}
			ev := res.Events[0]
			if ev.EventType != tc.etype {
				t.Errorf("event_type = %s, want %s", ev.EventType, tc.etype)
			}
			if ev.ContentPreview != tc.preview {
				t.Errorf("preview = %q, want %q", ev.ContentPreview, tc.preview)
			}
			if tc.tag == "" {
				if len(ev.Tags) != 0 {
					t.Errorf("tags = %v, want none", ev.Tags)
				}
			} else if len(ev.Tags) != 1 || ev.Tags[0] != tc.tag {
				t.Errorf("tags = %v, want [%s]", ev.Tags, tc.tag)
			}
			// Whatever the classification, the JSON pointer stays on the arguments.
			if ev.Evidence.JSONPointer != "/payload/arguments" {
				t.Errorf("json_pointer = %q, want /payload/arguments", ev.Evidence.JSONPointer)
			}
		})
	}
}

// Regression: an MCP-fetch arg that is not an absolute http(s) URL
// must NOT be promoted into Event.URL. file:///etc/passwd leaves URL empty (kept
// in ContentPreview); the event stays a network.indicator tagged network.
func TestExtractCodexMCPFetchRejectsNonHTTPScheme(t *testing.T) {
	const bad = "file:///etc/passwd"
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__fetch__fetch","call_id":"c","arguments":"{\"url\":\"file:///etc/passwd\"}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventNetworkIndicator {
		t.Errorf("event_type = %s, want network.indicator", ev.EventType)
	}
	if ev.URL != "" {
		t.Errorf("url = %q, want empty (non-http(s) must not be promoted)", ev.URL)
	}
	if ev.ContentPreview != bad {
		t.Errorf("ContentPreview = %q, want the raw value preserved", ev.ContentPreview)
	}
	if len(ev.Tags) != 1 || ev.Tags[0] != model.TagNetwork {
		t.Errorf("tags = %v, want [%s]", ev.Tags, model.TagNetwork)
	}
}

// function_call_output whose output is an ARRAY of content items (the untagged
// FunctionCallOutputPayload shape) decodes its text into the preview, just like
// the bare-string form.
func TestExtractCodexFunctionCallOutputArrayShape(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call_output","call_id":"x","output":[{"type":"output_text","text":"stdout line one"}]}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventToolResult || ev.ContentPreview != "stdout line one" {
		t.Errorf("got %s preview=%q, want tool.result 'stdout line one'", ev.EventType, ev.ContentPreview)
	}
	if ev.Evidence.JSONPointer != "/payload/output" {
		t.Errorf("json_pointer = %q, want /payload/output", ev.Evidence.JSONPointer)
	}
}

// A function_call_output paired by call_id with a prior local_shell_call is a
// command.result; a function_call_output for a non-shell function_call (here a
// read_file) stays tool.result. The exit code is omitted in both cases: Codex
// does not persist a structured exit status to the rollout.
func TestExtractCodexCommandResultCorrelation(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"local_shell_call","call_id":"sh","status":"completed","action":{"type":"exec","command":["make","test"]}}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"function_call","name":"read_file","call_id":"rd","arguments":"{\"path\":\"/x\"}"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call_output","call_id":"sh","output":"Exit code: 0\nOutput:\nok"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"rd","output":"file contents"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)

	var cmd, read *model.Event
	for i := range acts {
		switch acts[i].ToolCallID {
		case "sh":
			if acts[i].EventType == model.EventCommandResult {
				cmd = &acts[i]
			}
		case "rd":
			if acts[i].EventType == model.EventToolResult {
				read = &acts[i]
			}
		}
	}
	if cmd == nil {
		t.Fatalf("local_shell_call output not promoted to command.result:\n%s", dumpEvents(acts))
		return
	}
	if cmd.ExitCode != nil {
		t.Errorf("command.result exit_code = %v, want nil (Codex persists none)", cmd.ExitCode)
	}
	if cmd.Evidence.JSONPointer != "/payload/output" {
		t.Errorf("command.result pointer = %q, want /payload/output", cmd.Evidence.JSONPointer)
	}
	if read == nil {
		t.Fatalf("read_file output was reclassified away from tool.result:\n%s", dumpEvents(acts))
	}
}

func TestExtractCodexExecCommandResultCorrelation(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"ex","arguments":"{\"cmd\":\"go test ./...\"}"}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"ex","output":"ok"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 2 || acts[0].EventType != model.EventCommandExec || acts[1].EventType != model.EventCommandResult {
		t.Fatalf("exec_command pair not normalized as command events:\n%s", dumpEvents(acts))
	}
	if acts[0].Command != "go test ./..." || acts[0].ToolName != "exec_command" || acts[0].ToolCallID != "ex" || acts[1].ToolCallID != "ex" {
		t.Errorf("exec_command context not preserved:\n%s", dumpEvents(acts))
	}
}

// Codex/OTLP SHELL tool-failure parity, pinned to current extractor behavior.
// The live OTLP path (internal/otel) captures a failed shell call two ways: a
// structured exit code (process.exit.code -> ExitCode) and a tool-error signal
// (errored() -> TagToolError). Neither has a faithful carrier in the at-rest
// rollout for a SHELL call, and numbat never scrapes the prose body to invent
// one, so a non-zero exit and a clean exit-0 result look identical in the
// structured fields:
//
//   - exit code: FunctionCallOutputPayload (codex-rs protocol/src/models.rs)
//     serializes ONLY its body (string or content-items); the internal
//     success: Option<bool> flag is #[serde] dropped, and the structured
//     ExecCommandEnd carrying the real code is not persisted by policy.rs. The
//     code shows up only as a free-text "Exit code: N" line inside the body, too
//     brittle to lift without risking a fabricated number, so ExitCode stays nil.
//   - tool_error: local_shell_call's status enum is Completed|InProgress|Incomplete
//     with no failure variant (Incomplete is an abort/limit, not a tool error), so
//     there is no structured shell is_error to key off.
//
// This pins CURRENT shell behavior, not future schema evolution: it would catch a
// regression that began body-string scraping, but a new structured shell carrier
// would be absent from this fixture and would need its own positive test. (The
// MCP path, which DOES persist a structured failure, is covered separately by
// TestExtractCodexMCPToolFailureTagsToolError.)
func TestExtractCodexShellResultHasNoStructuredExitOrError(t *testing.T) {
	cases := []struct {
		name   string
		output string
	}{
		{"non-zero exit with error output", "Exit code: 127\nOutput:\nbash: foo: command not found"},
		{"clean exit zero", "Exit code: 0\nOutput:\nok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Join([]string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"local_shell_call","call_id":"sh","status":"completed","action":{"type":"exec","command":["foo"]}}}`,
				`{"timestamp":"t2","type":"response_item","payload":{"type":"function_call_output","call_id":"sh","output":` + jsonString(tc.output) + `}}`,
			}, "\n")
			acts := activityEvents(extractCodex(t, body).Events)

			var cmd *model.Event
			for i := range acts {
				if acts[i].ToolCallID == "sh" && acts[i].EventType == model.EventCommandResult {
					cmd = &acts[i]
				}
			}
			if cmd == nil {
				t.Fatalf("shell output not promoted to command.result:\n%s", dumpEvents(acts))
				return
			}
			// The output body (incl. its "Exit code:" line) is preserved as evidence in
			// the preview, so the failure is not invisible — it is just not lifted into
			// the structured ExitCode/TagToolError fields the OTLP path populates.
			if cmd.ContentPreview == "" {
				t.Errorf("command.result preview is empty, want the output body retained as evidence")
			}
			if cmd.ExitCode != nil {
				t.Errorf("command.result exit_code = %v, want nil (rollout persists no structured shell exit code)", *cmd.ExitCode)
			}
			for _, tag := range cmd.Tags {
				if tag == model.TagToolError {
					t.Errorf("command.result carries %q, want none (rollout persists no structured shell tool-error field)", model.TagToolError)
				}
			}
		})
	}
}

// An MCP tool failure IS recoverable at rest: Codex persists an mcp_tool_call_end
// event_msg whose structured Result<CallToolResult, String> records the outcome,
// keyed by the same call_id as the custom_tool_call/custom_tool_call_output the
// response_item layer emits. numbat reads ONLY that structured Result — never the
// prose body — and stamps TagToolError (the same signal Claude/Gemini use) on the
// correlated tool.result when it records a failure. Failure is an "Err" variant OR
// an "Ok" CallToolResult with is_error=true; an "Ok" without is_error is a success.
// The end-event itself is not re-emitted as a timeline event (the response_item
// layer already covered it), so no double-counting.
func TestExtractCodexMCPToolFailureTagsToolError(t *testing.T) {
	cases := []struct {
		name    string
		result  string
		wantErr bool
	}{
		{"transport error (Err variant)", `{"Err":"connection refused"}`, true},
		{"tool reported is_error", `{"Ok":{"is_error":true,"content":[{"type":"text","text":"boom"}]}}`, true},
		{"success is_error false", `{"Ok":{"is_error":false,"content":[{"type":"text","text":"rows"}]}}`, false},
		{"success is_error absent", `{"Ok":{"content":[{"type":"text","text":"rows"}]}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Join([]string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"m1","input":"SELECT 1"}}`,
				`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"m1","output":"result body"}}`,
				`{"timestamp":"t3","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"m1","result":` + tc.result + `}}`,
			}, "\n")
			acts := activityEvents(extractCodex(t, body).Events)

			var result *model.Event
			for i := range acts {
				if acts[i].ToolCallID == "m1" && acts[i].EventType == model.EventToolResult {
					result = &acts[i]
				}
			}
			if result == nil {
				t.Fatalf("custom_tool_call_output not emitted as tool.result:\n%s", dumpEvents(acts))
				return
			}
			got := false
			for _, tag := range result.Tags {
				if tag == model.TagToolError {
					got = true
				}
			}
			if got != tc.wantErr {
				t.Errorf("tool.result TagToolError = %v, want %v (result %s)", got, tc.wantErr, tc.result)
			}
			// The end-event must not add a second timeline event for the same call.
			n := 0
			for i := range acts {
				if acts[i].ToolCallID == "m1" && acts[i].EventType == model.EventToolResult {
					n++
				}
			}
			if n != 1 {
				t.Errorf("got %d tool.result events for call m1, want exactly 1 (no double-count)", n)
			}
		})
	}
}

// The mcp_tool_call_end may land BEFORE its custom_tool_call_output in the
// rollout (the event_msg and response_item layers are interleaved). The failure
// must still tag the tool.result, via the deferred call_id recorded in state.
func TestExtractCodexMCPToolFailureBeforeOutput(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"m2","input":"SELECT 1"}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"m2","result":{"Err":"timeout"}}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"m2","output":"partial"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)

	var result *model.Event
	for i := range acts {
		if acts[i].ToolCallID == "m2" && acts[i].EventType == model.EventToolResult {
			result = &acts[i]
		}
	}
	if result == nil {
		t.Fatalf("custom_tool_call_output not emitted as tool.result:\n%s", dumpEvents(acts))
		return
	}
	got := false
	for _, tag := range result.Tags {
		if tag == model.TagToolError {
			got = true
		}
	}
	if !got {
		t.Errorf("tool.result missing %q for a failure whose end-event preceded the output", model.TagToolError)
	}
}

func TestExtractCodexMCPDeferredFailureIsSingleUse(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"same","input":"SELECT 1"}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"same","result":{"Err":"timeout"}}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"first"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"duplicate"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)

	var results []model.Event
	for _, ev := range acts {
		if ev.EventType == model.EventToolResult && ev.ToolCallID == "same" {
			results = append(results, ev)
		}
	}
	if len(results) != 2 {
		t.Fatalf("got %d tool results, want 2:\n%s", len(results), dumpEvents(acts))
	}
	if !hasTag(results[0].Tags, model.TagToolError) || hasTag(results[1].Tags, model.TagToolError) {
		t.Errorf("deferred failure leaked past its first result: %+v", results)
	}
}

func TestExtractCodexNewCallClearsDeferredMCPFailure(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"same","input":"SELECT 1"}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"same","result":{"Err":"timeout"}}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"lookup","call_id":"same","arguments":"{}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"same","output":"clean"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)

	for _, ev := range acts {
		if ev.EventType == model.EventToolResult && ev.ToolCallID == "same" && hasTag(ev.Tags, model.TagToolError) {
			t.Fatalf("new call inherited a stale MCP failure: %+v", ev)
		}
	}
}

// A generic custom_tool_call_output must not become a command.result merely
// because its id collides with a direct shell call. Variant-specific state keeps
// it as a tool.result carrying the same id.
func TestExtractCodexCustomToolOutputStaysToolResult(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"response_item","payload":{"type":"local_shell_call","call_id":"dup","status":"completed","action":{"type":"exec","command":["ls"]}}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"dup","output":"rows"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	var output *model.Event
	for i := range acts {
		if acts[i].ToolCallID != "dup" {
			continue
		}
		if acts[i].EventType == model.EventCommandResult {
			t.Errorf("custom_tool_call_output promoted to command.result:\n%s", dumpEvents(acts))
		}
		if acts[i].EventType == model.EventToolResult {
			output = &acts[i]
		}
	}
	if output == nil {
		t.Fatalf("custom_tool_call_output did not surface as a tool.result with call_id dup:\n%s", dumpEvents(acts))
	}
}

// A web_search_call open_page action (url, no query) surfaces the url as the
// network indicator's preview, with the action JSON pointer.
func TestExtractCodexWebSearchOpenPage(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"web_search_call","action":{"type":"open_page","url":"https://evil.example/x"}}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventNetworkIndicator || ev.ContentPreview != "https://evil.example/x" {
		t.Errorf("got %s preview=%q, want network.indicator with the url", ev.EventType, ev.ContentPreview)
	}
	if ev.Evidence.JSONPointer != "/payload/action" {
		t.Errorf("json_pointer = %q, want /payload/action", ev.Evidence.JSONPointer)
	}
}

// The three review-mode / thread-goal state transitions have no response_item
// twin, so each is surfaced as a low-confidence system note tagged with its
// type rather than silently dropped.
func TestExtractCodexStateTransitionNotes(t *testing.T) {
	for _, typ := range []string{"entered_review_mode", "exited_review_mode", "thread_goal_updated"} {
		line := `{"timestamp":"t","type":"event_msg","payload":{"type":"` + typ + `","turn_id":"t1"}}`
		res := extractCodex(t, line)
		if len(res.Events) != 1 {
			t.Fatalf("%s: got %d events, want 1: %s", typ, len(res.Events), dumpEvents(res.Events))
		}
		ev := res.Events[0]
		if ev.EventType != model.EventMessageAssistant || ev.Actor != model.ActorSystem ||
			ev.Confidence != model.ConfidenceLow {
			t.Errorf("%s: got %s actor=%s conf=%s, want message.assistant/system/low", typ, ev.EventType, ev.Actor, ev.Confidence)
		}
		if len(ev.Tags) != 1 || ev.Tags[0] != typ {
			t.Errorf("%s: tags = %v, want [%s]", typ, ev.Tags, typ)
		}
	}
}

// The inner history-compaction variants carry only opaque encrypted content, so
// they are an explicit no-op: no event, no diagnostic.
func TestExtractCodexInnerCompactionNoOp(t *testing.T) {
	for _, typ := range []string{"compaction", "compaction_summary", "context_compaction"} {
		line := `{"timestamp":"t","type":"response_item","payload":{"type":"` + typ + `","encrypted_content":"opaque"}}`
		res := extractCodex(t, line)
		if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
			t.Errorf("%s: got %d events / %d diags, want 0/0", typ, len(res.Events), len(res.Diagnostics))
		}
	}
}

// An unknown function_call tool falls back to a generic tool.call, preserving
// coverage for tools numbat does not specifically model (e.g. update_plan).
func TestExtractCodexUnknownToolFallsBackToCall(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"update_plan","arguments":"{\"plan\":[]}"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventToolCall || ev.ToolName != "update_plan" {
		t.Errorf("got %s tool=%q, want tool.call update_plan", ev.EventType, ev.ToolName)
	}
}

// developer/system role messages are context injection, not agent activity, and
// must be skipped. An empty-text message also yields nothing.
func TestExtractCodexSkipsNonActivityMessages(t *testing.T) {
	for _, body := range []string{
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"instructions"}]}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"system","content":[{"type":"input_text","text":"policy"}]}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":[]}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":null}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"reasoning","content":[{"type":"text","text":"hmm"}]}}`,
	} {
		res := extractCodex(t, body)
		if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
			t.Errorf("body %q: got %d events / %d diags, want 0/0", body, len(res.Events), len(res.Diagnostics))
		}
	}
}

// A bare-string message.content (older/simple shape) still produces a message.
func TestExtractCodexBareStringContent(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":"plain text prompt"}}`
	res := extractCodex(t, line)
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventPromptUser {
		t.Fatalf("want one user prompt, got %s", dumpEvents(res.Events))
	}
	if res.Events[0].ContentPreview != "plain text prompt" {
		t.Errorf("preview = %q, want 'plain text prompt'", res.Events[0].ContentPreview)
	}
}

func TestExtractCodexTolerantOfMalformedLines(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":"hi"}}`,
		`{not valid json`,
		``,
		`   `,
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":"bye"}}`,
	}, "\n")
	res := extractCodex(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %s", len(res.Events), dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 1 || res.Diagnostics[0].Line != 2 {
		t.Fatalf("want one diagnostic on line 2, got %+v", res.Diagnostics)
	}
	// The good line after the bad one keeps its real line number.
	if res.Events[1].Evidence.Line != 5 {
		t.Errorf("second event line = %d, want 5", res.Events[1].Evidence.Line)
	}
}

// A line missing the outer type is a corruption signal worth a diagnostic; an
// unknown outer type is skipped quietly (a format addition, not corruption).
func TestExtractCodexMissingVsUnknownType(t *testing.T) {
	missing := extractCodex(t, `{"timestamp":"t","payload":{}}`)
	if len(missing.Events) != 0 || len(missing.Diagnostics) != 1 {
		t.Errorf("missing type: got %d events / %d diags, want 0/1", len(missing.Events), len(missing.Diagnostics))
	}
	unknown := extractCodex(t, `{"timestamp":"t","type":"future_record","payload":{}}`)
	if len(unknown.Events) != 0 || len(unknown.Diagnostics) != 0 {
		t.Errorf("unknown type: got %d events / %d diags, want 0/0", len(unknown.Events), len(unknown.Diagnostics))
	}
}

// A response_item with no inner type is a corruption signal; an unknown inner
// type is skipped quietly.
func TestExtractCodexResponseItemTypeHandling(t *testing.T) {
	missing := extractCodex(t, `{"timestamp":"t","type":"response_item","payload":{"call_id":"x"}}`)
	if len(missing.Events) != 0 || len(missing.Diagnostics) != 1 {
		t.Errorf("missing inner type: got %d events / %d diags, want 0/1", len(missing.Events), len(missing.Diagnostics))
	}
	unknown := extractCodex(t, `{"timestamp":"t","type":"response_item","payload":{"type":"new_variant"}}`)
	if len(unknown.Events) != 0 || len(unknown.Diagnostics) != 0 {
		t.Errorf("unknown inner type: got %d events / %d diags, want 0/0", len(unknown.Events), len(unknown.Diagnostics))
	}
}

func TestExtractCodexEmptyArtifact(t *testing.T) {
	res := extractCodex(t, "")
	if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
		t.Errorf("empty artifact should yield nothing, got %d events / %d diags", len(res.Events), len(res.Diagnostics))
	}
}

func TestExtractCodexOversizedArtifactErrors(t *testing.T) {
	_, err := CodexExtractor{maxBytes: 32}.Extract(strings.NewReader(strings.Repeat("x", 64)), Source{Path: "/big.jsonl"})
	if err == nil {
		t.Fatal("expected error for oversized artifact, got nil")
		return
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want it to mention the size cap", err)
	}
}

// A rollout whose FINAL line exceeds the per-line size cap (tooLong at EOF) must
// still close the session: the overlong line is a skipped diagnostic, but the
// session.start it opened earlier must get a matching session.end rather than
// leaving the stream unbounded. maxBytes is raised above the artifact so the
// whole-file cap is not what trips; the per-line cap is.
func TestExtractCodexOverlongFinalLineStillEmitsSessionEnd(t *testing.T) {
	meta := `{"timestamp":"2026-06-02T10:00:00Z","type":"session_meta","payload":{"id":"thread-1","cwd":"/p"}}`
	// A final line over maxLineSize, with NO trailing newline, so readLine returns
	// tooLong together with io.EOF — the branch that previously returned early.
	overlong := strings.Repeat("x", maxLineSize+1)
	body := meta + "\n" + overlong
	res, err := CodexExtractor{maxBytes: len(body) + 1}.Extract(strings.NewReader(body), Source{Path: "/cases/rollout.jsonl"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	evs := res.Events
	if len(evs) < 2 {
		t.Fatalf("want a start and a session.end despite the overlong final line, got %d", len(evs))
	}
	if last := evs[len(evs)-1]; last.EventType != model.EventSessionEnd || last.SessionID != "thread-1" {
		t.Errorf("last event = %s/%s, want session.end/thread-1", last.EventType, last.SessionID)
	}
	// The overlong line is reported as a skipped diagnostic, not silently dropped.
	var sawCap bool
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "exceeds size cap") {
			sawCap = true
		}
	}
	if !sawCap {
		t.Errorf("want a size-cap diagnostic for the overlong final line, got %+v", res.Diagnostics)
	}
}

// session_meta and turn_context emit no activity of their own; a rollout that is
// only those two yields nothing but the synthetic session lifecycle (a
// session.start seeded by the meta id and a matching session.end), and no
// diagnostics.
func TestExtractCodexMetaAndTurnContextEmitNothing(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"s","cwd":"/p"}}`,
		`{"timestamp":"t","type":"turn_context","payload":{"cwd":"/q"}}`,
	}, "\n")
	res := extractCodex(t, body)
	if acts := activityEvents(res.Events); len(acts) != 0 || len(res.Diagnostics) != 0 {
		t.Errorf("got %d activity events / %d diags, want 0/0", len(acts), len(res.Diagnostics))
	}
}

// extractCodexWithReasoning parses a rollout with explicit reasoning inclusion.
func extractCodexWithReasoning(t *testing.T, body string, includeReasoning bool) *Result {
	t.Helper()
	res, err := CodexExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/rollout.jsonl", CaseID: "case-1", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// The session_meta opens a synthetic session.start (carrying the cli_version on
// the typed CLIVersion field and the meta id as session identity) and EOF closes
// a matching session.end. They share the identity and carry the system actor,
// and their EventIDs are distinct from any activity via the .start/.end suffix.
// The session.end is stamped from the LAST observed record (its timestamp and
// line), not cloned from the opener, so it is evidence-faithful.
func TestExtractCodexSessionLifecycle(t *testing.T) {
	res := extractCodex(t, codexFixture)
	evs := res.Events
	if len(evs) < 2 {
		t.Fatalf("want at least a start and end, got %d", len(evs))
	}
	start, end := evs[0], evs[len(evs)-1]
	if start.EventType != model.EventSessionStart || start.Actor != model.ActorSystem {
		t.Errorf("first event = %s/%s, want session.start/system", start.EventType, start.Actor)
	}
	if end.EventType != model.EventSessionEnd || end.Actor != model.ActorSystem {
		t.Errorf("last event = %s/%s, want session.end/system", end.EventType, end.Actor)
	}
	if start.SessionID != "thread-1" || end.SessionID != "thread-1" {
		t.Errorf("lifecycle session ids = %q/%q, want thread-1", start.SessionID, end.SessionID)
	}
	if start.CLIVersion != "0.9.0" {
		t.Errorf("session.start cli_version = %q, want 0.9.0", start.CLIVersion)
	}
	if start.Entrypoint != "" {
		t.Errorf("session.start entrypoint = %q, want empty (a cli_version is not an entrypoint)", start.Entrypoint)
	}
	if !strings.HasSuffix(start.EventID, ".start") || !strings.HasSuffix(end.EventID, ".end") {
		t.Errorf("lifecycle ids = %q/%q, want .start/.end suffixes", start.EventID, end.EventID)
	}
	// session.end mirrors the running cwd at EOF, which turn_context moved.
	if end.ProjectPath != "/home/dev/other" {
		t.Errorf("session.end project path = %q, want /home/dev/other", end.ProjectPath)
	}
	// session.end provenance is the last observed record, never the opener's: a
	// later (or equal) timestamp, and a distinct evidence line.
	if end.Timestamp < start.Timestamp {
		t.Errorf("session.end timestamp %q < start %q, want >=", end.Timestamp, start.Timestamp)
	}
	if end.Timestamp != "2026-06-02T10:00:23Z" {
		t.Errorf("session.end timestamp = %q, want the last observed 2026-06-02T10:00:23Z", end.Timestamp)
	}
	if end.Evidence.Line == start.Evidence.Line {
		t.Errorf("session.end evidence line = %d, want != start line %d", end.Evidence.Line, start.Evidence.Line)
	}
	if end.Evidence.JSONPointer != "" {
		t.Errorf("session.end json_pointer = %q, want empty (artifact-level evidence)", end.Evidence.JSONPointer)
	}
	assertUniqueEventIDs(t, res.Events)
}

// A rollout with no session_meta (so no thread id) emits no lifecycle pair: the
// synthetic events are never fabricated without an identity to bound.
func TestExtractCodexNoSessionMetaNoLifecycle(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":"hi"}}`
	res := extractCodex(t, line)
	acts := activityEvents(res.Events)
	if len(acts) != 1 || acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != "hi" {
		t.Fatalf("headerless prompt fallback =\n%s", dumpEvents(acts))
	}
	for _, ev := range res.Events {
		if ev.EventType == model.EventSessionStart || ev.EventType == model.EventSessionEnd {
			t.Errorf("session lifecycle emitted without a session_meta: %+v", ev)
		}
	}
}

func TestExtractCodexResponsePromptFallbacks(t *testing.T) {
	tests := []struct {
		name        string
		lines       []string
		wantPrompt  string
		wantLine    int
		wantPointer string
	}{
		{
			name: "headerless fallback replaced by explicit prompt",
			lines: []string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"human prompt"}}`,
				`{"timestamp":"t2","type":"event_msg","payload":{"type":"user_message","message":"human prompt"}}`,
			},
			wantPrompt:  "human prompt",
			wantLine:    2,
			wantPointer: "/payload/message",
		},
		{
			name: "headered prompt retained at EOF",
			lines: []string{
				`{"timestamp":"t0","type":"session_meta","payload":{"id":"thread-1","cwd":"/repo"}}`,
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"truncated prompt"}}`,
			},
			wantPrompt:  "truncated prompt",
			wantLine:    2,
			wantPointer: "/payload/content",
		},
		{
			name: "paginated prompt retained after item start",
			lines: []string{
				`{"timestamp":"t0","type":"session_meta","payload":{"id":"thread-1","cwd":"/repo"}}`,
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"truncated prompt"}}`,
				`{"timestamp":"t2","type":"event_msg","payload":{"type":"item_started","item":{"type":"UserMessage","content":[{"type":"text","text":"truncated prompt"}]}}}`,
			},
			wantPrompt:  "truncated prompt",
			wantLine:    2,
			wantPointer: "/payload/content",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acts := activityEvents(extractCodex(t, strings.Join(tc.lines, "\n")).Events)
			if len(acts) != 1 || acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != tc.wantPrompt {
				t.Fatalf("prompt fallback =\n%s", dumpEvents(acts))
			}
			if acts[0].Evidence.Line != tc.wantLine || acts[0].Evidence.JSONPointer != tc.wantPointer {
				t.Errorf("prompt provenance = line %d %q", acts[0].Evidence.Line, acts[0].Evidence.JSONPointer)
			}
		})
	}
}

func TestExtractCodexDoesNotFlushInjectedContext(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t0","type":"session_meta","payload":{"id":"thread-1","cwd":"/repo"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"<environment_context>injected</environment_context>"}}`,
		`{"timestamp":"t2","type":"world_state","payload":{"full":false}}`,
	}, "\n")
	if acts := activityEvents(extractCodex(t, body).Events); len(acts) != 0 {
		t.Fatalf("injected context became a prompt:\n%s", dumpEvents(acts))
	}
}

// A function_call and its function_call_output share a call_id, stamped onto
// both events as tool_call_id so a consumer can join a call to its result.
func TestExtractCodexToolCallID(t *testing.T) {
	acts := activityEvents(extractCodex(t, codexFixture).Events)
	// The shell function_call (call_id c1) is the third activity event; its
	// function_call_output (also c1), correlated to that shell call, surfaces as
	// the command.result later in the stream.
	var call, result *model.Event
	for i := range acts {
		if acts[i].EventType == model.EventCommandExec && acts[i].ToolCallID == "c1" {
			call = &acts[i]
		}
		if acts[i].EventType == model.EventCommandResult && acts[i].ToolCallID == "c1" {
			result = &acts[i]
		}
	}
	if call == nil || call.ToolName != "shell" {
		t.Fatalf("shell call carrying call_id c1 not found: %+v", call)
	}
	if result == nil {
		t.Fatalf("no command.result carrying call_id c1")
	}
}

// A function_call routed through an MCP server arrives split as namespace +
// name (not a flattened mcp__server__tool name). When the name itself does not
// carry the mcp__ prefix, the server falls back to the recorded namespace and
// the tool is the bare name.
func TestExtractCodexMCPNamespaceFallbackSplit(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"get_logs","namespace":"mcp__datadog","call_id":"c","arguments":"{}"}}`
	acts := activityEvents(extractCodex(t, line).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventToolCall {
		t.Errorf("event_type = %s, want tool.call", ev.EventType)
	}
	if ev.MCPServer != "datadog" || ev.MCPTool != "get_logs" {
		t.Errorf("mcp split = %q/%q, want datadog/get_logs", ev.MCPServer, ev.MCPTool)
	}
}

// The Codex namespace is a server-only wrapper mcp__<server>, and the server
// name itself may contain "__". It must NOT be run through splitMCPName: the
// whole remainder after the mcp__ prefix is the server, and the bare name stays
// the tool. namespace "mcp__codex_apps__calendar" + name "calendar" therefore
// yields server="codex_apps__calendar" (not codex_apps/calendar), tool="calendar".
func TestExtractCodexMCPNamespaceMultiSep(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"calendar","namespace":"mcp__codex_apps__calendar","call_id":"c","arguments":"{}"}}`
	acts := activityEvents(extractCodex(t, line).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(acts))
	}
	if ev := acts[0]; ev.MCPServer != "codex_apps__calendar" || ev.MCPTool != "calendar" {
		t.Errorf("mcp split = %q/%q, want codex_apps__calendar/calendar (server name keeps its __)", ev.MCPServer, ev.MCPTool)
	}
}

// A custom_tool_call routed through an MCP server arrives split as namespace +
// name, exactly like a function_call. The namespace fallback must apply here too
// so a custom-tool MCP call still splits into typed server/tool fields.
func TestExtractCodexCustomToolCallNamespaceFallback(t *testing.T) {
	line := `{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"get_logs","namespace":"mcp__datadog","call_id":"c","input":"{}"}}`
	acts := activityEvents(extractCodex(t, line).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventToolCall {
		t.Errorf("event_type = %s, want tool.call", ev.EventType)
	}
	if ev.MCPServer != "datadog" || ev.MCPTool != "get_logs" {
		t.Errorf("mcp split = %q/%q, want datadog/get_logs", ev.MCPServer, ev.MCPTool)
	}
}

// Model reasoning is opt-in context.
func TestExtractCodexReasoningIsOptIn(t *testing.T) {
	line := `{"timestamp":"t","type":"session_meta","payload":{"id":"s","cwd":"/p"}}
{"timestamp":"t","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"plotting the next step"}]}}`

	evidence := activityEvents(extractCodexWithReasoning(t, line, false).Events)
	for _, ev := range evidence {
		if ev.EventType == model.EventMessageReasoning {
			t.Errorf("default extraction surfaced reasoning: %+v", ev)
		}
	}

	full := activityEvents(extractCodexWithReasoning(t, line, true).Events)
	var reasoning *model.Event
	for i := range full {
		if full[i].EventType == model.EventMessageReasoning {
			reasoning = &full[i]
		}
	}
	if reasoning == nil {
		t.Fatalf("reasoning option did not surface reasoning: %s", dumpEvents(full))
		return
	}
	if reasoning.Actor != model.ActorAssistant || reasoning.ContentPreview != "plotting the next step" {
		t.Errorf("reasoning = {actor=%s preview=%q}, want assistant/'plotting the next step'", reasoning.Actor, reasoning.ContentPreview)
	}
}

func TestExtractCodexIncludesRecordedModelProviderByDefault(t *testing.T) {
	line := `{"timestamp":"2026-06-02T10:00:00Z","type":"session_meta","payload":{"id":"s","cwd":"/p","model_provider":"openai"}}`
	res := extractCodexWithReasoning(t, line, false)
	if len(res.Events) == 0 || res.Events[0].EventType != model.EventSessionStart || res.Events[0].ModelProvider != "openai" {
		t.Fatalf("session context = %s", dumpEvents(res.Events))
	}
}

// Empty/encrypted reasoning carries no human-readable evidence. It is a
// recognized no-op even when reasoning is requested, not a parse diagnostic.
func TestExtractCodexEncryptedReasoningNoOp(t *testing.T) {
	line := `{"timestamp":"t","type":"session_meta","payload":{"id":"s","cwd":"/p"}}
{"timestamp":"t","type":"response_item","payload":{"type":"reasoning","summary":[],"encrypted_content":"opaque"}}`

	res := extractCodexWithReasoning(t, line, true)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	for _, ev := range activityEvents(res.Events) {
		if ev.EventType == model.EventMessageReasoning {
			t.Fatalf("encrypted empty reasoning should not surface an event: %+v", ev)
		}
	}
}

// The first session_meta is canonical for the thread id; a later session_meta
// (a resume re-emits one) must not overwrite it.
func TestExtractCodexFirstSessionMetaWins(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"first","cwd":"/p"}}`,
		`{"timestamp":"t","type":"session_meta","payload":{"id":"second","cwd":"/q"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":"hi"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"user_message","message":"hi"}}`,
	}, "\n")
	acts := activityEvents(extractCodex(t, body).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1", len(acts))
	}
	if acts[0].SessionID != "first" {
		t.Errorf("session_id = %q, want first (the first session_meta is canonical)", acts[0].SessionID)
	}
}

func TestExtractCodexForkSkipsCopiedHistory(t *testing.T) {
	const childID = "019f84fe-e5e1-7f80-8745-493ccff96186"
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"session_meta","payload":{"id":"` + childID + `","forked_from_id":"019f620e-730d-76e2-8204-f108cfe2f082","cwd":"/child"}}`,
		`{"timestamp":"t2","type":"turn_context","payload":{"cwd":"/parent"}}`,
		`not json`,
		`{"timestamp":"t4","type":"event_msg","payload":{"type":"task_started","turn_id":"019f84f6-8114-7cd3-8ac7-47ad22f4fba9"}}`,
		`{"timestamp":"t5","type":"response_item","payload":{"type":"message","role":"user","content":"parent prompt"}}`,
		`{"timestamp":"t6","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"parent","arguments":"{\"command\":\"echo parent\"}"}}`,
		`{"timestamp":"t7","type":"event_msg","payload":{"type":"task_started","turn_id":"` + childID + `"}}`,
		`{"timestamp":"t8","type":"response_item","payload":{"type":"message","role":"assistant","content":"parent answer"}}`,
		`{"timestamp":"t9","type":"event_msg","payload":{"type":"task_started","turn_id":"019f84ff-90e1-7f12-9b81-ed81048178c1"}}`,
		`{"timestamp":"t10","type":"turn_context","payload":{"cwd":"/child/live"}}`,
		`{"timestamp":"t11","type":"response_item","payload":{"type":"message","role":"user","content":"child prompt"}}`,
		`{"timestamp":"t12","type":"event_msg","payload":{"type":"user_message","message":"child prompt"}}`,
		`{"timestamp":"t13","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"child","arguments":"{\"command\":\"echo child\"}"}}`,
		`{"timestamp":"t14","type":"response_item","payload":{"type":"function_call_output","call_id":"child","output":"done"}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 3 {
		t.Fatalf("got %d activity events, want child prompt/command/result: %s", len(acts), dumpEvents(acts))
	}
	if acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != "child prompt" ||
		acts[1].EventType != model.EventCommandExec || acts[1].Command != "echo child" ||
		acts[2].EventType != model.EventCommandResult {
		t.Fatalf("events = %s, copied parent activity was not excluded", dumpEvents(acts))
	}
	for _, ev := range acts {
		if ev.SessionID != childID || ev.ProjectPath != "/child/live" {
			t.Errorf("child event identity = session %q path %q", ev.SessionID, ev.ProjectPath)
		}
	}
	if acts[0].Evidence.Line != 12 {
		t.Errorf("first child event line = %d, want 12", acts[0].Evidence.Line)
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "may be omitted") {
		t.Errorf("diagnostics = %+v, want one bounded uncertainty warning", res.Diagnostics)
	}
}

func TestExtractCodexForkWithoutChildTurnEmitsOnlyLifecycle(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"session_meta","payload":{"id":"019f84fe-e5e1-7f80-8745-493ccff96186","forked_from_id":"019f620e-730d-76e2-8204-f108cfe2f082","cwd":"/child"}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"task_started","turn_id":"019f84f6-8114-7cd3-8ac7-47ad22f4fba9"}}`,
		`{"timestamp":"t3","type":"event_msg","payload":{"type":"task_started","turn_id":"ffffffff-ffff-4fff-bfff-ffffffffffff"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"message","role":"user","content":"copied"}}`,
	}, "\n")
	res := extractCodex(t, body)
	if acts := activityEvents(res.Events); len(acts) != 0 {
		t.Fatalf("copied history emitted activity: %s", dumpEvents(acts))
	}
	if len(res.Events) != 2 || res.Events[0].EventType != model.EventSessionStart ||
		res.Events[1].EventType != model.EventSessionEnd || res.Events[1].Evidence.Line != 1 {
		t.Fatalf("events = %s, want lifecycle bounded by child session_meta", dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "orderable child task boundary") {
		t.Errorf("diagnostics = %+v, want one legacy-boundary uncertainty warning", res.Diagnostics)
	}
}

func TestExtractCodexForkIgnoresCopiedLegacyTaskID(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"session_meta","payload":{"id":"019f84fe-e5e1-7f80-8745-493ccff96186","forked_from_id":"019f620e-730d-76e2-8204-f108cfe2f082","cwd":"/child"}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"task_started","turn_id":"ffffffff-ffff-4fff-bfff-ffffffffffff"}}`,
		`{"timestamp":"t3","type":"event_msg","payload":{"type":"task_started","turn_id":"019f84f6-8114-7cd3-8ac7-47ad22f4fba9"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"message","role":"user","content":"copied"}}`,
		`{"timestamp":"t5","type":"event_msg","payload":{"type":"task_started","turn_id":"019f84ff-90e1-7f12-9b81-ed81048178c1"}}`,
		`{"timestamp":"t6","type":"response_item","payload":{"type":"message","role":"user","content":"child"}}`,
		`{"timestamp":"t7","type":"event_msg","payload":{"type":"user_message","message":"child"}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 1 || acts[0].ContentPreview != "child" {
		t.Fatalf("events = %s, copied legacy turn was not excluded", dumpEvents(acts))
	}
	if len(res.Diagnostics) != 0 {
		t.Fatalf("copied legacy task ID produced diagnostics after an ordered child boundary: %+v", res.Diagnostics)
	}
}

func TestExtractCodexForkWithLegacyIDFailsOpen(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t1","type":"session_meta","payload":{"id":"legacy-child","forked_from_id":"legacy-parent","cwd":"/child"}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"message","role":"user","content":"visible"}}`,
		`{"timestamp":"t3","type":"event_msg","payload":{"type":"user_message","message":"visible"}}`,
	}, "\n")
	res := extractCodex(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 1 || acts[0].ContentPreview != "visible" {
		t.Fatalf("legacy fork did not fail open: %s", dumpEvents(acts))
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "replay filtering disabled") {
		t.Fatalf("diagnostics = %+v, want one replay-filter warning", res.Diagnostics)
	}
}

func TestExtractCodexForkUnreadableBoundaryWarns(t *testing.T) {
	const meta = `{"timestamp":"t1","type":"session_meta","payload":{"id":"019f84fe-e5e1-7f80-8745-493ccff96186","forked_from_id":"019f620e-730d-76e2-8204-f108cfe2f082","cwd":"/child"}}`
	const boundary = `{"timestamp":"t3","type":"event_msg","payload":{"type":"task_started","turn_id":"019f84ff-90e1-7f12-9b81-ed81048178c1"}}`
	for _, tc := range []struct {
		name string
		row  string
	}{
		{name: "malformed", row: `{"type":"event_msg","payload":{"type":"task_started"`},
		{name: "missing turn id", row: `{"type":"event_msg","payload":{"type":"task_started"}}`},
		{name: "unrecognized UUID version", row: `{"type":"event_msg","payload":{"type":"task_started","turn_id":"ffffffff-ffff-ffff-bfff-ffffffffffff"}}`},
		{name: "overlong", row: strings.Repeat("x", maxLineSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Join([]string{
				meta,
				tc.row,
				boundary,
				`{"timestamp":"t4","type":"response_item","payload":{"type":"message","role":"user","content":"child"}}`,
				`{"timestamp":"t5","type":"event_msg","payload":{"type":"user_message","message":"child"}}`,
			}, "\n")
			res, err := CodexExtractor{maxBytes: len(body) + 1}.Extract(strings.NewReader(body), Source{Path: "/cases/fork.jsonl"})
			if err != nil {
				t.Fatalf("Extract returned error: %v", err)
			}
			acts := activityEvents(res.Events)
			if len(acts) != 1 || acts[0].ContentPreview != "child" {
				t.Fatalf("activity after the recovered boundary = %s", dumpEvents(acts))
			}
			if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "may be omitted") {
				t.Fatalf("diagnostics = %+v, want one bounded omission warning", res.Diagnostics)
			}
		})
	}

	body := strings.Join([]string{
		meta,
		`{"type":"event_msg","payload":{"type":"task_started"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"message","role":"user","content":"unproven"}}`,
	}, "\n")
	res, err := CodexExtractor{maxBytes: len(body) + 1}.Extract(strings.NewReader(body), Source{Path: "/cases/fork.jsonl"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if acts := activityEvents(res.Events); len(acts) != 0 {
		t.Fatalf("activity after an unproven boundary was emitted: %s", dumpEvents(acts))
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "child activity may be omitted") {
		t.Fatalf("EOF diagnostics = %+v, want one bounded omission warning", res.Diagnostics)
	}
}

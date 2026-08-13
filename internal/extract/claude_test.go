package extract

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/perplexityai/numbat/internal/model"
)

// realistic transcript covering the shapes Claude Code emits: a string-content
// user prompt, an assistant turn mixing text with several tool_use calls, and a
// tool result fed back as a user entry.
const claudeFixture = `{"type":"summary","summary":"investigate repo","leafUuid":"x"}
{"type":"user","uuid":"u1","sessionId":"s-1","timestamp":"2026-06-02T10:00:00Z","cwd":"/home/dev/proj","message":{"role":"user","content":"read the env file then run the build"}}
{"type":"assistant","uuid":"a1","sessionId":"s-1","timestamp":"2026-06-02T10:00:01Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"text","text":"On it."},{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/home/dev/proj/.env"}},{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"make build"}}]}}
{"type":"user","uuid":"u2","sessionId":"s-1","timestamp":"2026-06-02T10:00:02Z","cwd":"/home/dev/proj","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"SECRET=xyz"}]},"toolUseResult":{"stdout":"SECRET=xyz"}}
{"type":"assistant","uuid":"a2","sessionId":"s-1","timestamp":"2026-06-02T10:00:03Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Write","input":{"file_path":"/home/dev/proj/out.txt"}},{"type":"tool_use","id":"t4","name":"Grep","input":{"pattern":"token"}}]}}
{"type":"user","uuid":"u3","sessionId":"s-1","timestamp":"2026-06-02T10:00:04Z","cwd":"/home/dev/proj","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","content":"build failed","is_error":true}]}}
{"type":"system","content":"hook ran","subtype":"stop_hook_summary"}`

func extractFixture(t *testing.T, body string) *Result {
	t.Helper()
	res, err := ClaudeExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/session.jsonl", CaseID: "case-1"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

func TestExtractClaudeMapsAllShapes(t *testing.T) {
	res := extractFixture(t, claudeFixture)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}

	type want struct {
		etype model.EventType
		actor string
		tool  string
		cmd   string
		path  string
		tags  []string
	}
	// Events follow artifact order; within an assistant turn, content blocks
	// are emitted in order (text, then each tool_use).
	wants := []want{
		{model.EventPromptUser, model.ActorUser, "", "", "", nil},
		{model.EventMessageAssistant, model.ActorAssistant, "", "", "", nil},
		{model.EventFileRead, model.ActorAssistant, "Read", "", "/home/dev/proj/.env", nil},
		{model.EventCommandExec, model.ActorAssistant, "Bash", "make build", "", nil},
		// t1 is the Read call's result: its tool_use_id is not a command call, so
		// it stays tool.result even though a top-level toolUseResult is present.
		{model.EventToolResult, model.ActorTool, "", "", "", nil},
		{model.EventFileWrite, model.ActorAssistant, "Write", "", "/home/dev/proj/out.txt", nil},
		{model.EventToolCall, model.ActorAssistant, "Grep", "", "", nil},
		// t2 is the Bash call's result: correlated to the command.exec, it is a
		// command.result, and is_error still drives the tool_error tag.
		{model.EventCommandResult, model.ActorTool, "", "", "", []string{"tool_error"}},
	}
	acts := activityEvents(res.Events)
	if len(acts) != len(wants) {
		t.Fatalf("got %d activity events, want %d:\n%s", len(acts), len(wants), dumpEvents(res.Events))
	}
	for i, w := range wants {
		ev := acts[i]
		if ev.EventType != w.etype || ev.Actor != w.actor || ev.ToolName != w.tool ||
			ev.Command != w.cmd || ev.FilePath != w.path {
			t.Errorf("event %d = {%s actor=%s tool=%s cmd=%q path=%q}, want {%s actor=%s tool=%s cmd=%q path=%q}",
				i, ev.EventType, ev.Actor, ev.ToolName, ev.Command, ev.FilePath,
				w.etype, w.actor, w.tool, w.cmd, w.path)
		}
		if w.tags != nil && (len(ev.Tags) != 1 || ev.Tags[0] != w.tags[0]) {
			t.Errorf("event %d tags = %v, want %v", i, ev.Tags, w.tags)
		}
	}

	// Every emitted event must carry a unique EventID even when several come
	// from one transcript line (the assistant turn on line 3 emits three), and
	// the synthetic session.start/end must not collide with activity ids.
	assertUniqueEventIDs(t, res.Events)
}

func TestExtractClaudeStampsProvenance(t *testing.T) {
	res := extractFixture(t, claudeFixture)
	first := activityEvents(res.Events)[0]
	if first.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", first.SchemaVersion, model.SchemaVersion)
	}
	if first.SourceAgent != model.AgentClaudeCode || first.SourceType != model.SourceArtifact {
		t.Errorf("source = %s/%s, want %s/%s", first.SourceAgent, first.SourceType, model.AgentClaudeCode, model.SourceArtifact)
	}
	if first.CaseID != "case-1" {
		t.Errorf("case_id = %q, want case-1", first.CaseID)
	}
	// EventID is <uuid>#<block>: the first event comes from block 0 of u1.
	if first.EventID != "u1#0" {
		t.Errorf("event_id = %q, want u1#0 (uuid#block)", first.EventID)
	}
	if first.SessionID != "s-1" || first.ProjectPath != "/home/dev/proj" || first.Timestamp != "2026-06-02T10:00:00Z" {
		t.Errorf("identity fields wrong: %+v", first)
	}
	ev := first.Evidence
	if ev.ArtifactType != artifactClaudeJSONL || ev.LocalPath != "/cases/session.jsonl" || ev.Line != 2 {
		t.Errorf("evidence = %+v", ev)
	}
	if len(ev.SHA256) != 64 {
		t.Errorf("sha256 = %q, want 64 hex chars", ev.SHA256)
	}
	if first.Evidence.JSONPointer != "/message/content" {
		t.Errorf("json_pointer = %q, want /message/content", first.Evidence.JSONPointer)
	}
	// Every event from one artifact shares the same content hash.
	for _, e := range res.Events {
		if e.Evidence.SHA256 != ev.SHA256 {
			t.Fatalf("inconsistent sha256 across events")
		}
	}
}

// Within an assistant turn the per-block EventID and JSONPointer must track the
// content-block index, not the line, so each call is independently citable.
func TestExtractClaudeBlockEvidence(t *testing.T) {
	res := extractFixture(t, claudeFixture)
	// Line 3 (assistant a1): block 0 text, block 1 Read, block 2 Bash.
	acts := activityEvents(res.Events)
	text, read, bash := acts[1], acts[2], acts[3]
	for _, c := range []struct {
		ev      model.Event
		id      string
		pointer string
	}{
		{text, "a1#0", "/message/content/0"},
		{read, "a1#1", "/message/content/1"},
		{bash, "a1#2", "/message/content/2"},
	} {
		if c.ev.EventID != c.id {
			t.Errorf("event_id = %q, want %q", c.ev.EventID, c.id)
		}
		if c.ev.Evidence.JSONPointer != c.pointer {
			t.Errorf("json_pointer = %q, want %q", c.ev.Evidence.JSONPointer, c.pointer)
		}
	}
}

func TestExtractClaudeAgent(t *testing.T) {
	if got := (ClaudeExtractor{}).Agent(); got != model.AgentClaudeCode {
		t.Errorf("Agent() = %q, want %q", got, model.AgentClaudeCode)
	}
}

func TestExtractClaudeToolClassification(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		input   string
		etype   model.EventType
		cmd     string
		path    string
		preview string
		tag     string
	}{
		{"bash", "Bash", `{"command":"ls -la"}`, model.EventCommandExec, "ls -la", "", "", ""},
		{"read", "Read", `{"file_path":"/a/b"}`, model.EventFileRead, "", "/a/b", "", ""},
		{"notebook_read", "NotebookRead", `{"notebook_path":"/n.ipynb"}`, model.EventFileRead, "", "/n.ipynb", "", ""},
		{"write", "Write", `{"file_path":"/w"}`, model.EventFileWrite, "", "/w", "", ""},
		{"edit", "Edit", `{"file_path":"/e"}`, model.EventFileWrite, "", "/e", "", ""},
		{"multiedit", "MultiEdit", `{"file_path":"/m"}`, model.EventFileWrite, "", "/m", "", ""},
		{"notebook_edit", "NotebookEdit", `{"notebook_path":"/n.ipynb"}`, model.EventFileWrite, "", "/n.ipynb", "", ""},
		// BashOutput polls a background shell; it carries no command of its own,
		// so it must classify as a generic call, never a command.exec.
		{"bash_output", "BashOutput", `{"bash_id":"sh1"}`, model.EventToolCall, "", "", "", ""},
		// WebFetch is network egress: the url (the egress target) surfaces on a
		// network.indicator tagged network, not a bare tool.call.
		{"web_fetch", "WebFetch", `{"url":"https://evil.example/x","prompt":"q"}`, model.EventNetworkIndicator, "", "", "https://evil.example/x", "network"},
		// WebSearch egress: the query is the investigative lead on the indicator.
		{"web_search", "WebSearch", `{"query":"exfil howto"}`, model.EventNetworkIndicator, "", "", "exfil howto", "network"},
		// The canonical MCP fetch server (mcp__fetch__fetch) is network egress just
		// like WebFetch: the url surfaces on a network.indicator tagged network.
		{"mcp_fetch", "mcp__fetch__fetch", `{"url":"https://evil.example/m","max_length":100}`, model.EventNetworkIndicator, "", "", "https://evil.example/m", "network"},
		// A genuinely unknown / MCP tool still maps to a generic call so coverage
		// never silently drops a call.
		{"unknown_mcp", "mcp__db__query", `{"sql":"SELECT 1"}`, model.EventToolCall, "", "", "", ""},
		// mcp__fetch__query is a DIFFERENT tool on the fetch server (not the fetch
		// tool), so it must stay generic — the match is exact identity, not an
		// mcp__fetch__ prefix sniff.
		{"mcp_fetch_other_tool", "mcp__fetch__query", `{"url":"https://x/y"}`, model.EventToolCall, "", "", "", ""},
		{"missing_input", "Bash", `{}`, model.EventCommandExec, "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"type":"assistant","uuid":"a","message":{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"` +
				tc.tool + `","input":` + tc.input + `}]}}`
			res := extractFixture(t, body)
			if len(res.Events) != 1 {
				t.Fatalf("got %d events, want 1", len(res.Events))
			}
			ev := res.Events[0]
			if ev.EventType != tc.etype || ev.ToolName != tc.tool || ev.Command != tc.cmd || ev.FilePath != tc.path {
				t.Errorf("got {%s tool=%s cmd=%q path=%q}, want {%s tool=%s cmd=%q path=%q}",
					ev.EventType, ev.ToolName, ev.Command, ev.FilePath, tc.etype, tc.tool, tc.cmd, tc.path)
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
		})
	}
}

func TestExtractClaudeTolerantOfMalformedLines(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"user","uuid":"u1","message":{"role":"user","content":"hi"}}`,
		`{not valid json`,
		``,
		`   `,
		`{"type":"user","uuid":"u2","message":{"role":"user","content":"bye"}}`,
	}, "\n")
	res := extractFixture(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	if len(res.Diagnostics) != 1 {
		t.Fatalf("got %d diagnostics, want 1: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	if res.Diagnostics[0].Line != 2 {
		t.Errorf("diagnostic line = %d, want 2", res.Diagnostics[0].Line)
	}
	// The good line after the bad one must still be parsed with its real line number.
	if res.Events[1].Evidence.Line != 5 {
		t.Errorf("second event line = %d, want 5", res.Events[1].Evidence.Line)
	}
}

func TestExtractClaudeUnknownTypeDiagnostic(t *testing.T) {
	res := extractFixture(t, `{"type":"mystery","uuid":"x"}`)
	if len(res.Events) != 0 {
		t.Fatalf("got %d events, want 0", len(res.Events))
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "unhandled entry type") {
		t.Errorf("want one diagnostic naming the gap, got %+v", res.Diagnostics)
	}
}

func TestExtractClaudeFallbackEventID(t *testing.T) {
	// No uuid: id must be derived deterministically and prefixed.
	res := extractFixture(t, `{"type":"user","message":{"role":"user","content":"hi"}}`)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	id := res.Events[0].EventID
	if !strings.HasPrefix(id, "claude-") || len(id) != len("claude-")+16 {
		t.Errorf("fallback event id = %q, want claude-<16hex>", id)
	}
	// Determinism: same input → same id.
	res2 := extractFixture(t, `{"type":"user","message":{"role":"user","content":"hi"}}`)
	if res2.Events[0].EventID != id {
		t.Errorf("fallback id not deterministic: %q vs %q", id, res2.Events[0].EventID)
	}
}

// Without a uuid, the fallback id folds in the block index so a multi-block
// turn still yields distinct ids.
func TestExtractClaudeFallbackEventIDUniquePerBlock(t *testing.T) {
	body := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"hi"},{"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}`
	res := extractFixture(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	assertUniqueEventIDs(t, res.Events)
}

func TestExtractClaudeSkipsContentlessUser(t *testing.T) {
	// A user entry with neither text nor a tool result yields nothing.
	res := extractFixture(t, `{"type":"user","uuid":"u","message":{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"x"}}]}}`)
	if len(res.Events) != 0 {
		t.Fatalf("got %d events, want 0: %s", len(res.Events), dumpEvents(res.Events))
	}
}

// Null and empty content envelopes are tolerated as no-ops, not errors.
func TestExtractClaudeContentEdgeCases(t *testing.T) {
	for _, body := range []string{
		`{"type":"user","uuid":"u","message":null}`,
		`{"type":"user","uuid":"u","message":{"role":"user","content":null}}`,
		`{"type":"user","uuid":"u","message":{"role":"user","content":[]}}`,
		`{"type":"user","uuid":"u"}`,
	} {
		res := extractFixture(t, body)
		if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
			t.Errorf("body %q: got %d events / %d diags, want 0/0", body, len(res.Events), len(res.Diagnostics))
		}
	}
}

func TestExtractClaudeContentPreviewKeepsOverlongTokenPrefix(t *testing.T) {
	long := strings.Repeat("a", previewMax+50)
	res := extractFixture(t, `{"type":"user","uuid":"u","message":{"role":"user","content":"`+long+`"}}`)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	got := res.Events[0].ContentPreview
	if got != long[:previewMax] {
		t.Errorf("preview = %q, want rune-safe prefix", got)
	}
}

// A preview cut must land on a rune boundary so ContentPreview is always valid
// UTF-8; a byte-slice truncation would split a multibyte rune and corrupt the
// SHA-anchored evidence story.
func TestExtractClaudeContentPreviewMultibyte(t *testing.T) {
	// Repeated multibyte words overshoot the cap but still leave safe token
	// boundaries before it.
	long := strings.Repeat("世 ", previewMax+10)
	res := extractFixture(t, `{"type":"user","uuid":"u","message":{"role":"user","content":"`+long+`"}}`)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	got := res.Events[0].ContentPreview
	if !utf8.ValidString(got) {
		t.Errorf("preview is not valid UTF-8: %q", got)
	}
	if n := utf8.RuneCountInString(got); n > previewMax || !strings.HasSuffix(got, "世") {
		t.Errorf("preview = %q (%d runes), want complete multibyte words within the cap", got, n)
	}
}

func TestExtractPreviewDoesNotFabricatePartialDomain(t *testing.T) {
	input := "prefix https://" + strings.Repeat("a", previewMax) + ".example"
	if got := preview(input); got != "prefix" {
		t.Fatalf("preview = %q, want prefix without a partial domain", got)
	}
}

func TestExtractClaudeEmptyArtifact(t *testing.T) {
	res := extractFixture(t, "")
	if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
		t.Errorf("empty artifact should yield nothing, got %d events / %d diags", len(res.Events), len(res.Diagnostics))
	}
}

func TestExtractClaudeAssistantTextAsArray(t *testing.T) {
	// Assistant text can arrive as content blocks rather than a bare string.
	body := `{"type":"assistant","uuid":"a","message":{"role":"assistant","content":[{"type":"text","text":"hello"}]}}`
	res := extractFixture(t, body)
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventMessageAssistant {
		t.Fatalf("want one assistant message, got %s", dumpEvents(res.Events))
	}
	if res.Events[0].ContentPreview != "hello" {
		t.Errorf("preview = %q, want hello", res.Events[0].ContentPreview)
	}
}

// An assistant turn with several text blocks emits one assistant message per
// block, each with its own block-indexed evidence pointer.
func TestExtractClaudeMultipleTextBlocks(t *testing.T) {
	body := `{"type":"assistant","uuid":"a","message":{"role":"assistant","content":[{"type":"text","text":"first"},{"type":"thinking","thinking":"hmm"},{"type":"text","text":"second"}]}}`
	res := extractFixture(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %s", len(res.Events), dumpEvents(res.Events))
	}
	if res.Events[0].ContentPreview != "first" || res.Events[0].Evidence.JSONPointer != "/message/content/0" {
		t.Errorf("block 0 = %q @ %q", res.Events[0].ContentPreview, res.Events[0].Evidence.JSONPointer)
	}
	// Block 1 is thinking (skipped); block 2 is the second text block.
	if res.Events[1].ContentPreview != "second" || res.Events[1].Evidence.JSONPointer != "/message/content/2" {
		t.Errorf("block 2 = %q @ %q", res.Events[1].ContentPreview, res.Events[1].Evidence.JSONPointer)
	}
	assertUniqueEventIDs(t, res.Events)
}

// A single user entry can carry several tool_result blocks (parallel tool
// calls); every one must surface, with per-block error flags and pointers.
func TestExtractClaudeMultipleToolResults(t *testing.T) {
	body := `{"type":"user","uuid":"u","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"},{"type":"tool_result","tool_use_id":"t2","content":"boom","is_error":true}]}}`
	res := extractFixture(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %s", len(res.Events), dumpEvents(res.Events))
	}
	for i, ev := range res.Events {
		if ev.EventType != model.EventToolResult || ev.Actor != model.ActorTool {
			t.Errorf("event %d = %s/%s, want tool.result/tool", i, ev.EventType, ev.Actor)
		}
	}
	if res.Events[0].Evidence.JSONPointer != "/message/content/0" || len(res.Events[0].Tags) != 0 {
		t.Errorf("first result: pointer=%q tags=%v, want clean block 0", res.Events[0].Evidence.JSONPointer, res.Events[0].Tags)
	}
	if res.Events[1].Evidence.JSONPointer != "/message/content/1" ||
		len(res.Events[1].Tags) != 1 || res.Events[1].Tags[0] != "tool_error" {
		t.Errorf("second result: pointer=%q tags=%v, want errored block 1", res.Events[1].Evidence.JSONPointer, res.Events[1].Tags)
	}
	assertUniqueEventIDs(t, res.Events)
}

// When the result lives only in the top-level toolUseResult (empty content
// array, no tool_use_id to correlate), the payload's own shape decides — and the
// only faithful command signal is exit_code: a command Claude writes here always
// carries one, so an exit_code body becomes command.result with the code threaded
// through. stdout/stderr alone are NOT command-specific (a file read's
// toolUseResult also carries stdout — see the Read fixture on claude_test.go:17),
// so a stdout/stderr-only body stays tool.result rather than being mis-promoted.
// The is_error flag is preserved either way.
func TestExtractClaudeToolUseResultOnly(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		wantType model.EventType
		wantExit *int
		wantErr  bool
	}{
		// stdout-only mirrors the Read fixture shape: no exit_code, so it must NOT
		// be promoted to command.result.
		{"stdout_only_stays_tool_result", `{"stdout":"done"}`, model.EventToolResult, nil, false},
		{"is_error_only", `{"is_error":true}`, model.EventToolResult, nil, true},
		{"nonzero_exit", `{"exit_code":2,"stderr":"nope"}`, model.EventCommandResult, intp(2), true},
		{"zero_exit", `{"exit_code":0}`, model.EventCommandResult, intp(0), false},
		// stderr-only likewise lacks an exit_code, so it stays tool.result while its
		// non-empty stderr still drives the tool_error tag.
		{"stderr_only_stays_tool_result", `{"stderr":"warning"}`, model.EventToolResult, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"type":"user","uuid":"u","message":{"role":"user","content":[]},"toolUseResult":` + tc.payload + `}`
			res := extractFixture(t, body)
			if len(res.Events) != 1 {
				t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
			}
			ev := res.Events[0]
			if ev.EventType != tc.wantType || ev.Evidence.JSONPointer != "/toolUseResult" {
				t.Errorf("got %s @ %q, want %s @ /toolUseResult", ev.EventType, ev.Evidence.JSONPointer, tc.wantType)
			}
			if !eqIntp(ev.ExitCode, tc.wantExit) {
				t.Errorf("exit_code = %v, want %v", ev.ExitCode, tc.wantExit)
			}
			gotErr := len(ev.Tags) == 1 && ev.Tags[0] == "tool_error"
			if gotErr != tc.wantErr {
				t.Errorf("error tag = %v (tags=%v), want %v", gotErr, ev.Tags, tc.wantErr)
			}
		})
	}
}

func intp(i int) *int { return &i }

func eqIntp(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// A tool_result block present alongside a top-level toolUseResult must be driven
// by the block (so per-call pointers and flags win); the top-level payload is a
// fallback only.
func TestExtractClaudeToolResultBlockWinsOverTopLevel(t *testing.T) {
	body := `{"type":"user","uuid":"u","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]},"toolUseResult":{"is_error":true}}`
	res := extractFixture(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(res.Events), dumpEvents(res.Events))
	}
	ev := res.Events[0]
	if ev.Evidence.JSONPointer != "/message/content/0" {
		t.Errorf("pointer = %q, want block pointer", ev.Evidence.JSONPointer)
	}
	if len(ev.Tags) != 0 {
		t.Errorf("tags = %v, want none (block is not an error)", ev.Tags)
	}
}

// A tool_result correlated by tool_use_id to a prior Bash command.exec becomes a
// command.result with the exit code lifted from the top-level toolUseResult,
// while a Read call's result in the same entry stays tool.result — so command
// output is promoted but file/MCP output is never reclassified.
func TestExtractClaudeCommandResultCorrelation(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"assistant","uuid":"a","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"bash1","name":"Bash","input":{"command":"go test"}},{"type":"tool_use","id":"read1","name":"Read","input":{"file_path":"/x"}}]}}`,
		`{"type":"user","uuid":"u1","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"bash1","content":"FAIL"}]},"toolUseResult":{"stdout":"","stderr":"boom","exit_code":1}}`,
		`{"type":"user","uuid":"u2","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"read1","content":"file body"}]},"toolUseResult":{"stdout":"file body"}}`,
	}, "\n")
	acts := activityEvents(extractFixture(t, body).Events)

	var cmd, read *model.Event
	for i := range acts {
		switch acts[i].ToolCallID {
		case "bash1":
			if acts[i].EventType == model.EventCommandResult {
				cmd = &acts[i]
			}
		case "read1":
			if acts[i].EventType == model.EventToolResult {
				read = &acts[i]
			}
		}
	}
	if cmd == nil {
		t.Fatalf("Bash result not promoted to command.result:\n%s", dumpEvents(acts))
		return
	}
	if cmd.ExitCode == nil || *cmd.ExitCode != 1 {
		t.Errorf("command.result exit_code = %v, want 1", cmd.ExitCode)
	}
	if len(cmd.Tags) != 0 {
		// is_error absent on the block, exit handling is the result's error path
		// only via toolUseResult, but the block here is not flagged.
		t.Logf("command.result tags = %v", cmd.Tags)
	}
	if cmd.Evidence.JSONPointer != "/message/content/0" {
		t.Errorf("command.result pointer = %q, want the block pointer", cmd.Evidence.JSONPointer)
	}
	if read == nil {
		t.Fatalf("Read result was reclassified away from tool.result:\n%s", dumpEvents(acts))
		return
	}
	if read.ExitCode != nil {
		t.Errorf("file read result carried exit_code %v, want none", read.ExitCode)
	}
}

// A Bash command.result correlated by id with NO top-level toolUseResult (the
// exit code lives only there) carries no exit_code — the field is omitted, not
// zero-filled, so absent stays distinct from a real exit 0.
func TestExtractClaudeCommandResultNoExitCode(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"assistant","uuid":"a","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"b1","name":"Bash","input":{"command":"ls"}}]}}`,
		`{"type":"user","uuid":"u","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"b1","content":"out"}]}}`,
	}, "\n")
	acts := activityEvents(extractFixture(t, body).Events)
	var cmd *model.Event
	for i := range acts {
		if acts[i].EventType == model.EventCommandResult {
			cmd = &acts[i]
		}
	}
	if cmd == nil {
		t.Fatalf("no command.result emitted:\n%s", dumpEvents(acts))
		return
	}
	if cmd.ExitCode != nil {
		t.Errorf("exit_code = %v, want nil (absent)", cmd.ExitCode)
	}
}

// A Bash command.result whose toolUseResult records a durationMs carries it on
// DurationMs; totalDurationMs serves as the fallback. The duration rides the same
// command.result that exit_code does, and a Read result never picks it up.
func TestExtractClaudeCommandResultDuration(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"assistant","uuid":"a","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"b1","name":"Bash","input":{"command":"go test"}},{"type":"tool_use","id":"b2","name":"Bash","input":{"command":"go vet"}},{"type":"tool_use","id":"r1","name":"Read","input":{"file_path":"/x"}}]}}`,
		`{"type":"user","uuid":"u1","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"b1","content":"ok"}]},"toolUseResult":{"stdout":"ok","exit_code":0,"durationMs":1234}}`,
		`{"type":"user","uuid":"u2","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"b2","content":"ok"}]},"toolUseResult":{"stdout":"ok","exit_code":0,"totalDurationMs":42}}`,
		`{"type":"user","uuid":"u3","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"r1","content":"body"}]},"toolUseResult":{"stdout":"body","durationMs":99}}`,
	}, "\n")
	acts := activityEvents(extractFixture(t, body).Events)

	var primary, fallback, read *model.Event
	for i := range acts {
		switch acts[i].ToolCallID {
		case "b1":
			if acts[i].EventType == model.EventCommandResult {
				primary = &acts[i]
			}
		case "b2":
			if acts[i].EventType == model.EventCommandResult {
				fallback = &acts[i]
			}
		case "r1":
			if acts[i].EventType == model.EventToolResult {
				read = &acts[i]
			}
		}
	}
	if primary == nil || primary.DurationMs == nil || *primary.DurationMs != 1234 {
		t.Errorf("durationMs not lifted onto command.result: %+v", primary)
	}
	if fallback == nil || fallback.DurationMs == nil || *fallback.DurationMs != 42 {
		t.Errorf("totalDurationMs fallback not used: %+v", fallback)
	}
	if read == nil {
		t.Fatalf("Read result reclassified away from tool.result:\n%s", dumpEvents(acts))
		return
	}
	if read.DurationMs != nil {
		t.Errorf("file read result carried duration_ms %v, want none", read.DurationMs)
	}
}

// When a single user entry feeds back TWO Bash results, the entry carries only
// ONE top-level toolUseResult.exit_code and no per-block code — so there is no
// artifact field tying that code to either block. Stamping it on both would
// fabricate a duplicate exit code, so both blocks become command.result but BOTH
// leave ExitCode nil. (The single-Bash entry keeps its code; that is covered by
// TestExtractClaudeCommandResultCorrelation.)
func TestExtractClaudeMultipleCommandResultsNoFabricatedExit(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"assistant","uuid":"a","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"b1","name":"Bash","input":{"command":"go build"}},{"type":"tool_use","id":"b2","name":"Bash","input":{"command":"go test"}}]}}`,
		`{"type":"user","uuid":"u","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"b1","content":"ok"},{"type":"tool_result","tool_use_id":"b2","content":"fail"}]},"toolUseResult":{"exit_code":1}}`,
	}, "\n")
	acts := activityEvents(extractFixture(t, body).Events)

	var cmds []model.Event
	for _, ev := range acts {
		if ev.EventType == model.EventCommandResult && (ev.ToolCallID == "b1" || ev.ToolCallID == "b2") {
			cmds = append(cmds, ev)
		}
	}
	if len(cmds) != 2 {
		t.Fatalf("got %d command.result events, want 2:\n%s", len(cmds), dumpEvents(acts))
	}
	for _, ev := range cmds {
		if ev.ExitCode != nil {
			t.Errorf("%s exit_code = %v, want nil (no per-block code; the single entry code is not attributable)", ev.ToolCallID, *ev.ExitCode)
		}
	}
}

// An oversized single line is skipped with a diagnostic, and parsing continues
// on the following lines rather than aborting the whole artifact.
func TestExtractClaudeTolerantOfOversizedLine(t *testing.T) {
	huge := strings.Repeat("x", maxLineSize+1)
	body := strings.Join([]string{
		`{"type":"user","uuid":"a","message":{"role":"user","content":"first"}}`,
		huge,
		`{"type":"user","uuid":"b","message":{"role":"user","content":"third"}}`,
	}, "\n")
	res := extractFixture(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %s", len(res.Events), dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 1 || res.Diagnostics[0].Line != 2 ||
		!strings.Contains(res.Diagnostics[0].Msg, "size cap") {
		t.Fatalf("want one size-cap diagnostic on line 2, got %+v", res.Diagnostics)
	}
	// The good line after the oversized one keeps its true line number.
	if res.Events[1].Evidence.Line != 3 || res.Events[1].ContentPreview != "third" {
		t.Errorf("third event = line %d preview %q, want line 3 'third'", res.Events[1].Evidence.Line, res.Events[1].ContentPreview)
	}
}

func TestExtractClaudeOversizedArtifactErrors(t *testing.T) {
	// maxBytes is injectable so the oversize path is exercised cheaply without
	// a mutable global.
	_, err := ClaudeExtractor{maxBytes: 32}.Extract(strings.NewReader(strings.Repeat("x", 64)), Source{Path: "/big.jsonl"})
	if err == nil {
		t.Fatal("expected error for oversized artifact, got nil")
		return
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want it to mention the size cap", err)
	}
}

// assertUniqueEventIDs fails if any two events share an EventID.
func assertUniqueEventIDs(t *testing.T, evs []model.Event) {
	t.Helper()
	seen := make(map[string]int, len(evs))
	for i, e := range evs {
		if e.EventID == "" {
			t.Errorf("event %d has empty EventID", i)
			continue
		}
		if j, dup := seen[e.EventID]; dup {
			t.Errorf("duplicate EventID %q at events %d and %d", e.EventID, j, i)
		}
		seen[e.EventID] = i
	}
}

// activityEvents returns the events with the synthetic session.start/session.end
// lifecycle records removed, so the per-shape assertions can stay focused on the
// agent activity an artifact records. The lifecycle pair is asserted separately
// by the dedicated session tests.
func activityEvents(evs []model.Event) []model.Event {
	out := make([]model.Event, 0, len(evs))
	for _, e := range evs {
		if e.EventType == model.EventSessionStart || e.EventType == model.EventSessionEnd {
			continue
		}
		out = append(out, e)
	}
	return out
}

func dumpEvents(evs []model.Event) string {
	var b strings.Builder
	for i, e := range evs {
		b.WriteString(strings.TrimSpace(
			strings.Join([]string{
				"  [" + itoa(i) + "]", string(e.EventType), "actor=" + e.Actor,
				"tool=" + e.ToolName, "cmd=" + e.Command, "path=" + e.FilePath,
				"id=" + e.EventID,
			}, " ")) + "\n")
	}
	return b.String()
}

// A permission-mode entry is a security-posture change, surfaced as a
// config.agent event carrying the new mode. Modes that keep a human in the loop
// ("default", "plan") or are more restrictive than default ("dontAsk", which
// auto-denies unless pre-approved) carry no tag; modes that let the agent
// act without interactive approval ("acceptEdits", "auto", "bypassPermissions")
// are tagged so a reviewer can enumerate the unattended-action windows. The mode
// set matches Claude Code's six documented permission modes.
func TestExtractClaudePermissionMode(t *testing.T) {
	cases := []struct {
		mode   string
		tagged bool
	}{
		{"default", false},
		{"plan", false},
		{"dontAsk", false},
		{"acceptEdits", true},
		{"auto", true},
		{"bypassPermissions", true},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			line := `{"type":"permission-mode","permissionMode":"` + tc.mode + `","sessionId":"s-1"}`
			res := extractFixture(t, line)
			acts := activityEvents(res.Events)
			if len(acts) != 1 {
				t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(res.Events))
			}
			if len(res.Diagnostics) != 0 {
				t.Errorf("got %d diagnostics, want 0: %+v", len(res.Diagnostics), res.Diagnostics)
			}
			ev := acts[0]
			if ev.EventType != model.EventConfigAgent {
				t.Errorf("event_type = %s, want config.agent", ev.EventType)
			}
			if ev.Actor != model.ActorSystem {
				t.Errorf("actor = %s, want system", ev.Actor)
			}
			if ev.ContentPreview != tc.mode {
				t.Errorf("preview = %q, want %q", ev.ContentPreview, tc.mode)
			}
			if ev.Evidence.JSONPointer != "/permissionMode" {
				t.Errorf("json_pointer = %q, want /permissionMode", ev.Evidence.JSONPointer)
			}
			if ev.SessionID != "s-1" {
				t.Errorf("session_id = %q, want s-1", ev.SessionID)
			}
			if tc.tagged {
				if len(ev.Tags) != 1 || ev.Tags[0] != "permission_mode_elevated" {
					t.Errorf("tags = %v, want [permission_mode_elevated]", ev.Tags)
				}
			} else if len(ev.Tags) != 0 {
				t.Errorf("tags = %v, want none", ev.Tags)
			}
		})
	}
}

// A permission-mode entry with no mode value carries no information, so it is a
// silent no-op rather than an empty event.
func TestExtractClaudePermissionModeEmptySkipped(t *testing.T) {
	res := extractFixture(t, `{"type":"permission-mode","permissionMode":"","sessionId":"s-1"}`)
	if acts := activityEvents(res.Events); len(acts) != 0 || len(res.Diagnostics) != 0 {
		t.Fatalf("got %d activity events / %d diags, want 0/0: %s", len(acts), len(res.Diagnostics), dumpEvents(res.Events))
	}
}

// type:"mode" is Claude Code's other permission-mode-switch shape: the new mode
// rides on "mode" and the line carries no timestamp. It is the same
// security-posture signal as type:"permission-mode", so it surfaces as a
// config.agent event carrying the mode, must NOT warn, and inherits the last
// observed timestamp. Fixture uses the real on-disk shape (type, mode,
// sessionId; no timestamp).
func TestExtractClaudeModeEntry(t *testing.T) {
	// A prior timestamped entry so the timestamp-less mode line has something to
	// inherit; the user line itself is unrelated activity.
	body := `{"type":"user","sessionId":"s-1","timestamp":"2026-05-29T12:00:00.000Z","message":{"role":"user","content":"hi"}}
{"type":"mode","mode":"bypassPermissions","sessionId":"s-1"}`
	res := extractFixture(t, body)
	if len(res.Diagnostics) != 0 {
		t.Errorf("got %d diagnostics, want 0: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	var ev *model.Event
	for i := range res.Events {
		if res.Events[i].EventType == model.EventConfigAgent {
			ev = &res.Events[i]
		}
	}
	if ev == nil {
		t.Fatalf("no config.agent event: %s", dumpEvents(res.Events))
		return
	}
	if ev.ContentPreview != "bypassPermissions" {
		t.Errorf("preview = %q, want bypassPermissions", ev.ContentPreview)
	}
	if ev.Evidence.JSONPointer != "/mode" {
		t.Errorf("json_pointer = %q, want /mode", ev.Evidence.JSONPointer)
	}
	if ev.Timestamp != "2026-05-29T12:00:00.000Z" {
		t.Errorf("timestamp = %q, want inherited 2026-05-29T12:00:00.000Z", ev.Timestamp)
	}
	// bypassPermissions removes guardrails, so it must carry the elevated tag.
	if len(ev.Tags) != 1 || ev.Tags[0] != "permission_mode_elevated" {
		t.Errorf("tags = %v, want [permission_mode_elevated]", ev.Tags)
	}
}

// The exact production shape Claude Code emits on disk is {"type":"mode",
// "mode":"normal","sessionId":...} — "normal" is the in-loop default, NOT a
// guardrail-removing mode. It must still surface as config.agent with the mode
// as preview, must NOT warn, and must NOT carry the elevated tag. This
// locks the benign default so a future change cannot silently start tagging
// "normal" as elevated.
func TestExtractClaudeModeEntryNormalNotElevated(t *testing.T) {
	res := extractFixture(t, `{"type":"mode","mode":"normal","sessionId":"s-1"}`)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("got %d diagnostics, want 0: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	ev := acts[0]
	if ev.EventType != model.EventConfigAgent {
		t.Errorf("event_type = %s, want config.agent", ev.EventType)
	}
	if ev.ContentPreview != "normal" {
		t.Errorf("preview = %q, want normal", ev.ContentPreview)
	}
	if len(ev.Tags) != 0 {
		t.Errorf("tags = %v, want none", ev.Tags)
	}
}

func TestExtractClaudePermissionModesSuppressRepeatedSnapshots(t *testing.T) {
	body := `{"type":"mode","mode":"normal","sessionId":"s-1"}
{"type":"permission-mode","permissionMode":"default","sessionId":"s-1"}
{"type":"mode","mode":"normal","sessionId":"s-1"}
{"type":"permission-mode","permissionMode":"default","sessionId":"s-1"}
{"type":"mode","mode":"bypassPermissions","sessionId":"s-1"}
{"type":"permission-mode","permissionMode":"default","sessionId":"s-1"}`
	res := extractFixture(t, body)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	acts := activityEvents(res.Events)
	if len(acts) != 3 {
		t.Fatalf("got %d activity events, want 3: %s", len(acts), dumpEvents(res.Events))
	}
	wants := []struct {
		pointer string
		mode    string
	}{
		{"/mode", "normal"},
		{"/permissionMode", "default"},
		{"/mode", "bypassPermissions"},
	}
	for i, want := range wants {
		if got := acts[i].Evidence.JSONPointer; got != want.pointer {
			t.Errorf("event %d pointer = %q, want %q", i, got, want.pointer)
		}
		if got := acts[i].ContentPreview; got != want.mode {
			t.Errorf("event %d mode = %q, want %q", i, got, want.mode)
		}
	}
}

// A pr-link entry surfaces as a network indicator carrying the pull request URL.
func TestExtractClaudePRLinkEntry(t *testing.T) {
	line := `{"type":"pr-link","sessionId":"s-1","prNumber":42,"prUrl":"https://github.com/example/repo/pull/42","prRepository":"example/repo","timestamp":"2026-05-29T12:15:50.553Z"}`
	res := extractFixture(t, line)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("got %d diagnostics, want 0: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	ev := acts[0]
	if ev.EventType != model.EventNetworkIndicator {
		t.Errorf("event_type = %s, want network.indicator", ev.EventType)
	}
	if ev.URL != "https://github.com/example/repo/pull/42" {
		t.Errorf("url = %q, want the pull request URL", ev.URL)
	}
	if ev.Timestamp != "2026-05-29T12:15:50.553Z" {
		t.Errorf("timestamp = %q, want the entry timestamp", ev.Timestamp)
	}
	if len(ev.Tags) != 1 || ev.Tags[0] != model.TagNetwork {
		t.Errorf("tags = %v, want [network]", ev.Tags)
	}
}

// An agent-name entry surfaces the active named subagent as a config.agent event.
func TestExtractClaudeAgentNameEntry(t *testing.T) {
	// A prior timestamped entry so the timestamp-less agent-name line has
	// something to inherit; the user line itself is unrelated activity.
	body := `{"type":"user","sessionId":"bdb65fb8-6f17-4a24-a3d6-db6eb1335af3","timestamp":"2026-05-29T12:00:00.000Z","message":{"role":"user","content":"hi"}}
{"type":"agent-name","agentName":"supply-chain-reviewer","sessionId":"bdb65fb8-6f17-4a24-a3d6-db6eb1335af3"}`
	res := extractFixture(t, body)
	if len(res.Diagnostics) != 0 {
		t.Errorf("got %d diagnostics, want 0: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	var ev *model.Event
	for i := range res.Events {
		if res.Events[i].EventType == model.EventConfigAgent {
			ev = &res.Events[i]
		}
	}
	if ev == nil {
		t.Fatalf("no config.agent event: %s", dumpEvents(res.Events))
	}
	if ev.SubAgent != "supply-chain-reviewer" {
		t.Errorf("sub_agent = %q, want supply-chain-reviewer", ev.SubAgent)
	}
	if ev.ContentPreview != "supply-chain-reviewer" {
		t.Errorf("preview = %q, want supply-chain-reviewer", ev.ContentPreview)
	}
	if ev.Actor != model.ActorSystem {
		t.Errorf("actor = %s, want system", ev.Actor)
	}
	if ev.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %s, want high", ev.Confidence)
	}
	if ev.Evidence.JSONPointer != "/agentName" {
		t.Errorf("json_pointer = %q, want /agentName", ev.Evidence.JSONPointer)
	}
	if ev.SessionID != "bdb65fb8-6f17-4a24-a3d6-db6eb1335af3" {
		t.Errorf("session_id = %q, want the entry sessionId", ev.SessionID)
	}
	if ev.Timestamp != "2026-05-29T12:00:00.000Z" {
		t.Errorf("timestamp = %q, want inherited 2026-05-29T12:00:00.000Z", ev.Timestamp)
	}
	if ev.Command != "" || ev.FilePath != "" {
		t.Errorf("config.agent must set no command/file_path, got cmd=%q path=%q", ev.Command, ev.FilePath)
	}
	if len(ev.Tags) != 0 {
		t.Errorf("tags = %v, want none", ev.Tags)
	}
}

// An agent-name entry with a missing/empty agentName is malformed: it is skipped
// (no event) rather than emitting an empty config.agent, and must still not warn
// — a known type with no payload is not a coverage gap. A genuinely unknown type
// in the same batch must STILL warn, proving the agent-name handling did not
// widen the silence into a catch-all.
func TestExtractClaudeAgentNameEmptyOrUnknown(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantActs int
		wantDiag bool
	}{
		{"empty-agentName", `{"type":"agent-name","agentName":"","sessionId":"s-1"}`, 0, false},
		{"missing-agentName", `{"type":"agent-name","sessionId":"s-1"}`, 0, false},
		{"unknown-still-warns", `{"type":"some-brand-new-type","sessionId":"s-1"}`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := extractFixture(t, tc.line)
			if acts := activityEvents(res.Events); len(acts) != tc.wantActs {
				t.Errorf("got %d activity events, want %d: %s", len(acts), tc.wantActs, dumpEvents(res.Events))
			}
			gotDiag := len(res.Diagnostics) > 0
			if gotDiag != tc.wantDiag {
				t.Errorf("got diagnostics=%v (%+v), want %v", gotDiag, res.Diagnostics, tc.wantDiag)
			}
			if tc.wantDiag && !strings.Contains(res.Diagnostics[0].Msg, "unhandled entry type") {
				t.Errorf("diag = %q, want it to mention unhandled entry type", res.Diagnostics[0].Msg)
			}
		})
	}
}

func TestExtractClaudeSubagentIdentityStampsAllEvents(t *testing.T) {
	cases := []struct {
		path    string
		agentID string
		want    string
	}{
		{"/home/dev/.claude/projects/p/s-parent/subagents/agent-path-id.jsonl", "recorded-id", "recorded-id"},
		{"/home/dev/.claude/projects/p/s-parent/subagents/agent-child-7.jsonl", "", "child-7"},
		{`C:\Users\dev\.claude\projects\p\s-parent\subagents\agent-child-7.jsonl`, "", "child-7"},
	}
	for _, tc := range cases {
		body := `{"type":"user","sessionId":"s-parent","agentId":"` + tc.agentID + `","timestamp":"2026-06-02T10:00:00Z","message":{"role":"user","content":"inspect the package"}}
{"type":"assistant","sessionId":"s-parent","agentId":"` + tc.agentID + `","timestamp":"2026-06-02T10:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"go test ./..."}}]}}`
		path := tc.path
		res, err := (ClaudeExtractor{}).Extract(strings.NewReader(body), Source{Path: path})
		if err != nil {
			t.Fatalf("Extract(%q): %v", path, err)
		}
		if len(res.Diagnostics) != 0 {
			t.Fatalf("Extract(%q) diagnostics: %+v", path, res.Diagnostics)
		}
		if len(res.Events) == 0 {
			t.Fatalf("Extract(%q) emitted no events", path)
		}
		for _, ev := range res.Events {
			if ev.SubAgent != tc.want {
				t.Errorf("Extract(%q) %s sub_agent = %q, want %q", path, ev.EventType, ev.SubAgent, tc.want)
			}
			if ev.SessionID != "s-parent" {
				t.Errorf("Extract(%q) %s session_id = %q, want s-parent", path, ev.EventType, ev.SessionID)
			}
		}
		assertUniqueEventIDs(t, res.Events)
	}

	for _, path := range []string{
		"/home/dev/subagents/agent-child-7.jsonl/extra",
		"/home/dev/subagents/session.jsonl",
		"/home/dev/agents/agent-child-7.jsonl",
	} {
		if got := claudeSubAgent("", path); got != "" {
			t.Errorf("claudeSubAgent(\"\", %q) = %q, want empty", path, got)
		}
	}
}

// These records are metadata or editor bookkeeping, not distinct agent
// activity. Known shapes stay silent so diagnostics continue to signal genuine
// parser coverage gaps.
func TestExtractClaudeBenignEntryTypesAreSilent(t *testing.T) {
	lines := []string{
		`{"type":"custom-title","customTitle":"release review","sessionId":"s-1"}`,
		`{"type":"relocated","sessionId":"s-1","relocatedCwd":"/home/dev/project"}`,
		`{"type":"last-prompt","lastPrompt":"fix the merge conflict","sessionId":"s-1"}`,
		`{"type":"file-history-snapshot","messageId":"m1","snapshot":{"messageId":"m1","trackedFileBackups":{},"timestamp":"2026-04-20T20:25:17.579Z"},"isSnapshotUpdate":false}`,
		`{"type":"file-history-delta","messageId":"m2","snapshotMessageId":"m1","trackingPath":"/home/dev/project/main.go","backup":{"backupFileName":"main.go@v1","version":1,"backupTime":"2026-04-20T20:25:17.579Z"},"timestamp":"2026-04-20T20:25:17.579Z"}`,
		`{"type":"worktree-state","sessionId":"s-1","worktreeSession":{"originalCwd":"/Users/dev/code/app","worktreePath":"/Users/dev/code/app/.claude/worktrees/ion","worktreeName":"ion","worktreeBranch":"worktree-ion","originalBranch":"redteam/x","originalHeadCommit":"626429f6","sessionId":"s-1"}}`,
		`{"type":"attachment","uuid":"at1","sessionId":"s-1","attachment":{"type":"selected_lines","file":"main.go"}}`,
		`{"type":"attachment","uuid":"at2","sessionId":"s-1","attachment":{"type":"deferred_tools_delta","addedNames":[],"removedNames":[]}}`,
	}
	for _, line := range lines {
		res := extractFixture(t, line)
		if acts := activityEvents(res.Events); len(acts) != 0 {
			t.Errorf("got %d activity events, want 0 for %s: %s", len(acts), line, dumpEvents(res.Events))
		}
		if len(res.Diagnostics) != 0 {
			t.Errorf("got %d diagnostics, want 0 for %s: %+v", len(res.Diagnostics), line, res.Diagnostics)
		}
	}
}

func TestExtractClaudeRelocatedCWDSeedsProjectPath(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"relocated","sessionId":"s-1","relocatedCwd":"/home/dev/project/.claude/worktrees/review"}`,
		`{"type":"user","uuid":"u1","sessionId":"s-1","timestamp":"2026-07-09T07:30:00Z","message":{"role":"user","content":"continue"}}`,
	}, "\n")
	res := extractFixture(t, body)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("got diagnostics: %+v", res.Diagnostics)
	}
	for _, ev := range res.Events {
		if ev.ProjectPath != "/home/dev/project/.claude/worktrees/review" {
			t.Errorf("%s project_path = %q", ev.EventType, ev.ProjectPath)
		}
	}
}

// An attachment carrying a deferred_tools_delta records a change to the set of
// tools/capabilities the agent can call, including MCP-qualified tools. That
// bounds what the agent could do in the session, so it is surfaced as a
// config.mcp event (system actor, medium confidence) naming the added/removed
// tools, rather than silently dropped. Fixture uses the real on-disk shape,
// including mcp__ tool names.
func TestExtractClaudeAttachmentDeferredToolsDelta(t *testing.T) {
	line := `{"type":"attachment","uuid":"at1","sessionId":"s-1","attachment":{"type":"deferred_tools_delta","addedNames":["WebFetch","mcp__datadog__get_logs"],"removedNames":["mcp__notion__search"]}}`
	res := extractFixture(t, line)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("got %d diagnostics, want 0: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	ev := acts[0]
	if ev.EventType != model.EventConfigMCP {
		t.Errorf("event_type = %s, want config.mcp", ev.EventType)
	}
	if ev.Actor != model.ActorSystem {
		t.Errorf("actor = %s, want system", ev.Actor)
	}
	if ev.Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %s, want medium", ev.Confidence)
	}
	if ev.Evidence.JSONPointer != "/attachment" {
		t.Errorf("json_pointer = %q, want /attachment", ev.Evidence.JSONPointer)
	}
	if ev.SessionID != "s-1" {
		t.Errorf("session_id = %q, want s-1", ev.SessionID)
	}
	// The preview must name both the added and removed tools so a reviewer can
	// see the capability surface change without opening the artifact.
	for _, want := range []string{"added:", "WebFetch", "mcp__datadog__get_logs", "removed:", "mcp__notion__search"} {
		if !strings.Contains(ev.ContentPreview, want) {
			t.Errorf("preview %q missing %q", ev.ContentPreview, want)
		}
	}
}

// A genuinely unknown entry type must still produce a diagnostic, not be
// silently dropped: the recognized no-op list is a deliberate allowlist, and a
// new, unmapped type is a coverage gap a reviewer needs to see. This guards
// against accidentally widening the silence to catch-all.
func TestExtractClaudeUnknownEntryTypeWarns(t *testing.T) {
	res := extractFixture(t, `{"type":"some-brand-new-type","sessionId":"s-1"}`)
	if acts := activityEvents(res.Events); len(acts) != 0 {
		t.Errorf("got %d activity events, want 0: %s", len(acts), dumpEvents(res.Events))
	}
	if len(res.Diagnostics) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(res.Diagnostics))
	}
	if !strings.Contains(res.Diagnostics[0].Msg, "unhandled entry type") {
		t.Errorf("diag = %q, want it to mention unhandled entry type", res.Diagnostics[0].Msg)
	}
}

// extractFixtureWithReasoning parses a transcript with explicit reasoning inclusion.
func extractFixtureWithReasoning(t *testing.T, body string, includeReasoning bool) *Result {
	t.Helper()
	res, err := ClaudeExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/session.jsonl", CaseID: "case-1", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// The synthetic session lifecycle brackets the activity: a session.start is
// emitted on the first entry carrying a session id, and a matching session.end
// closes the stream. They share the session identity, carry the system actor,
// and their EventIDs are distinct from the activity event of the same entry (via
// the .start/.end suffix) so nothing collides.
func TestExtractClaudeSessionLifecycle(t *testing.T) {
	res := extractFixture(t, claudeFixture)
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
	if start.SessionID != "s-1" || end.SessionID != "s-1" {
		t.Errorf("lifecycle session ids = %q/%q, want s-1", start.SessionID, end.SessionID)
	}
	if !strings.HasSuffix(start.EventID, ".start") || !strings.HasSuffix(end.EventID, ".end") {
		t.Errorf("lifecycle ids = %q/%q, want .start/.end suffixes", start.EventID, end.EventID)
	}
	if start.GitBranch != "" {
		// The fixture carries no gitBranch; nothing is fabricated.
		t.Errorf("session.start git_branch = %q, want empty (artifact carries none)", start.GitBranch)
	}
	// session.end is stamped from the LAST observed record, not cloned from the
	// opener: a later-or-equal timestamp and a distinct evidence line, with no
	// JSON pointer (artifact-level evidence, since the close is synthetic).
	if end.Timestamp < start.Timestamp {
		t.Errorf("session.end timestamp %q < start %q, want >=", end.Timestamp, start.Timestamp)
	}
	if end.Timestamp != "2026-06-02T10:00:04Z" {
		t.Errorf("session.end timestamp = %q, want the last observed 2026-06-02T10:00:04Z", end.Timestamp)
	}
	if end.Evidence.Line == start.Evidence.Line {
		t.Errorf("session.end evidence line = %d, want != start line %d", end.Evidence.Line, start.Evidence.Line)
	}
	if end.Evidence.JSONPointer != "" {
		t.Errorf("session.end json_pointer = %q, want empty (artifact-level evidence)", end.Evidence.JSONPointer)
	}
	assertUniqueEventIDs(t, res.Events)
}

// A transcript with no session id anywhere emits no lifecycle pair (there is no
// identity to bound), so the synthetic events are never fabricated.
func TestExtractClaudeNoSessionIDNoLifecycle(t *testing.T) {
	line := `{"type":"assistant","uuid":"a1","cwd":"/p","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]}}`
	res := extractFixture(t, line)
	for _, ev := range res.Events {
		if ev.EventType == model.EventSessionStart || ev.EventType == model.EventSessionEnd {
			t.Errorf("session lifecycle emitted without a session id: %+v", ev)
		}
	}
}

// A tool_use carries its id onto the event as tool_call_id, and a tool_result
// carries the same id, so a consumer can join a call to its result.
func TestExtractClaudeToolCallID(t *testing.T) {
	acts := activityEvents(extractFixture(t, claudeFixture).Events)
	// acts: prompt, text, Read(t1), Bash(t2), result(t1), Write(t3), Grep(t4), result(t2-error)
	read := acts[2]
	if read.ToolName != "Read" || read.ToolCallID != "t1" {
		t.Errorf("Read event tool_call_id = %q, want t1", read.ToolCallID)
	}
	result := acts[4]
	if result.EventType != model.EventToolResult || result.ToolCallID != "t1" {
		t.Errorf("tool_result tool_call_id = %q, want t1", result.ToolCallID)
	}
}

// WebFetch is network egress: its url is promoted onto the typed URL field and
// the event is a network.indicator tagged for egress, naming what left the box.
func TestExtractClaudeWebFetchURL(t *testing.T) {
	line := `{"type":"assistant","uuid":"a1","sessionId":"s-1","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"WebFetch","input":{"url":"https://evil.example/x","prompt":"grab"}}]}}`
	acts := activityEvents(extractFixture(t, line).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1: %s", len(acts), dumpEvents(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventNetworkIndicator {
		t.Errorf("event_type = %s, want network.indicator", ev.EventType)
	}
	if ev.URL != "https://evil.example/x" {
		t.Errorf("url = %q, want the fetch target", ev.URL)
	}
	if len(ev.Tags) != 1 || ev.Tags[0] != model.TagNetwork {
		t.Errorf("tags = %v, want [%s]", ev.Tags, model.TagNetwork)
	}
}

// Regression: a WebFetch arg that is not an absolute http(s) URL must
// NOT be promoted into Event.URL. A tampered file:///etc/passwd, javascript:, or
// relative value leaves URL empty (kept visible in ContentPreview) so numbat
// never fabricates a network target; the network.indicator + network tag still
// stand because the fetch was attempted.
func TestExtractClaudeWebFetchRejectsNonHTTPScheme(t *testing.T) {
	for _, bad := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,<script>1</script>",
		"/relative/path",
		"not a url at all",
	} {
		line := `{"type":"assistant","uuid":"a1","sessionId":"s-1","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"WebFetch","input":{"url":` + strconv.Quote(bad) + `,"prompt":"grab"}}]}}`
		acts := activityEvents(extractFixture(t, line).Events)
		if len(acts) != 1 {
			t.Fatalf("%q: got %d activity events, want 1", bad, len(acts))
		}
		ev := acts[0]
		if ev.EventType != model.EventNetworkIndicator {
			t.Errorf("%q: event_type = %s, want network.indicator", bad, ev.EventType)
		}
		if ev.URL != "" {
			t.Errorf("%q: url = %q, want empty (non-http(s) must not be promoted)", bad, ev.URL)
		}
		if ev.ContentPreview != bad {
			t.Errorf("%q: ContentPreview = %q, want the raw value preserved", bad, ev.ContentPreview)
		}
		if len(ev.Tags) != 1 || ev.Tags[0] != model.TagNetwork {
			t.Errorf("%q: tags = %v, want [%s]", bad, ev.Tags, model.TagNetwork)
		}
	}
}

// A generic MCP tool name (mcp__<server>__<tool>) splits into the typed
// mcp_server/mcp_tool fields so a rule or SIEM can pivot on either without
// re-parsing the flattened name; the call stays a generic tool.call.
func TestExtractClaudeMCPNameSplit(t *testing.T) {
	line := `{"type":"assistant","uuid":"a1","sessionId":"s-1","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"mcp__datadog__get_logs","input":{}}]}}`
	acts := activityEvents(extractFixture(t, line).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1", len(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventToolCall {
		t.Errorf("event_type = %s, want tool.call", ev.EventType)
	}
	if ev.MCPServer != "datadog" || ev.MCPTool != "get_logs" {
		t.Errorf("mcp split = %q/%q, want datadog/get_logs", ev.MCPServer, ev.MCPTool)
	}
	if ev.ToolName != "mcp__datadog__get_logs" {
		t.Errorf("tool_name = %q, want the full flattened name retained", ev.ToolName)
	}
}

// Model reasoning (a thinking block) is opt-in context.
func TestExtractClaudeReasoningIsOptIn(t *testing.T) {
	line := `{"type":"assistant","uuid":"a1","sessionId":"s-1","message":{"role":"assistant","content":[{"type":"thinking","thinking":"plotting the next step"},{"type":"text","text":"done"}]}}`

	evidence := activityEvents(extractFixtureWithReasoning(t, line, false).Events)
	for _, ev := range evidence {
		if ev.EventType == model.EventMessageReasoning {
			t.Errorf("default extraction surfaced reasoning: %+v", ev)
		}
	}

	full := activityEvents(extractFixtureWithReasoning(t, line, true).Events)
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
		t.Errorf("reasoning event = %s/%q, want assistant/'plotting the next step'", reasoning.Actor, reasoning.ContentPreview)
	}
}

func TestExtractClaudeIncludesRecordedModelByDefault(t *testing.T) {
	line := `{"type":"assistant","uuid":"a1","sessionId":"s-1","message":{"model":"claude-sonnet","role":"assistant","content":[{"type":"text","text":"done"}]}}`
	res := extractFixtureWithReasoning(t, line, false)
	if len(res.Events) == 0 || res.Events[0].EventType != model.EventSessionStart || res.Events[0].Model != "claude-sonnet" {
		t.Fatalf("session context = %s", dumpEvents(res.Events))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

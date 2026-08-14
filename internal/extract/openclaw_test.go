package extract

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// openClawPath is the on-disk path used for every OpenClaw test transcript. The
// parser keys off the JSONL line shape, not the path, so a single representative
// sessions/ path exercises the mapping the same way on every OS.
const openClawPath = "/cases/openclaw/agents/a1/sessions/s1.jsonl"

// extractOpenClaw parses body as an OpenClaw session transcript at openClawPath.
func extractOpenClaw(t *testing.T, body string) *Result {
	t.Helper()
	return extractOpenClawSource(t, body, Source{Path: openClawPath, CaseID: "case-claw"})
}

func extractOpenClawSource(t *testing.T, body string, src Source) *Result {
	t.Helper()
	res, err := OpenClawExtractor{}.Extract(strings.NewReader(body), src)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// header is the session header line that seeds session identity. Every realistic
// transcript begins with one; helpers prepend it so the body under test reads as
// the message line(s) that follow.
const openClawHeader = `{"type":"session","id":"sess-123","cwd":"/work/proj","timestamp":"2026-06-05T10:00:00Z"}`

// withHeader prefixes the session header to one or more message lines, mirroring
// the real SessionManager layout (header first, entries after).
func withHeader(lines ...string) string {
	return openClawHeader + "\n" + strings.Join(lines, "\n")
}

func TestOpenClawAgent(t *testing.T) {
	if got := (OpenClawExtractor{}).Agent(); got != model.AgentOpenClaw {
		t.Errorf("Agent() = %q, want %q", got, model.AgentOpenClaw)
	}
}

// TestOpenClawSessionHeaderSeedsIdentity proves the first type:"session" line is
// NOT emitted as an event but seeds the session id and project path stamped onto
// every later event.
func TestOpenClawSessionHeaderSeedsIdentity(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"user","content":"hello"}}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1 (header emits nothing): %+v", len(res.Events), res.Events)
	}
	ev := res.Events[0]
	if ev.SessionID != "sess-123" {
		t.Errorf("session id = %q, want sess-123", ev.SessionID)
	}
	if ev.ProjectPath != "/work/proj" {
		t.Errorf("project path = %q, want /work/proj", ev.ProjectPath)
	}
}

// TestOpenClawStringContentRoles proves a STRING message content maps to
// prompt.user (user role) or message.assistant (assistant role) with the prose
// previewed and the correct actor.
func TestOpenClawStringContentRoles(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"user","content":"please build it"}}`,
		`{"type":"message","message":{"role":"assistant","content":"on it"}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	user, asst := res.Events[0], res.Events[1]
	if user.EventType != model.EventPromptUser || user.Actor != model.ActorUser {
		t.Errorf("user = %q/%q, want prompt.user/user", user.EventType, user.Actor)
	}
	if user.ContentPreview != "please build it" {
		t.Errorf("user preview = %q, want %q", user.ContentPreview, "please build it")
	}
	if asst.EventType != model.EventMessageAssistant || asst.Actor != model.ActorAssistant {
		t.Errorf("assistant = %q/%q, want message.assistant/assistant", asst.EventType, asst.Actor)
	}
}

func TestOpenClawThinkingIsOptIn(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"thinking","thinking":"visible thought"},{"type":"thinking","thinking":"filtered thought","redacted":true},{"type":"text","text":"final"}]}}`)
	if got := extractOpenClaw(t, body); len(got.Events) != 1 || got.Events[0].EventType != model.EventMessageAssistant {
		t.Fatalf("default events = %+v", got.Events)
	}
	res := extractOpenClawSource(t, body, Source{
		Path:             openClawPath,
		IncludeReasoning: true,
		CaptureContent:   true,
	})
	if len(res.Events) != 2 || res.Events[0].EventType != model.EventMessageReasoning ||
		res.Events[0].ContentForAnalysis() != "visible thought" ||
		res.Events[1].EventType != model.EventMessageAssistant {
		t.Fatalf("reasoning events = %+v", res.Events)
	}
}

// TestOpenClawToolUseCommand preserves the legacy provider-block compatibility
// path. Its tool_result has no structured exit field, so no code is fabricated;
// stable role:toolResult exec coverage is tested separately below.
func TestOpenClawToolUseCommand(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"make build"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"build ok"}]}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	exec, result := res.Events[0], res.Events[1]
	if exec.EventType != model.EventCommandExec || exec.Command != "make build" {
		t.Errorf("exec = %q/%q, want command.exec/make build", exec.EventType, exec.Command)
	}
	if exec.Actor != model.ActorAssistant {
		t.Errorf("exec actor = %q, want assistant", exec.Actor)
	}
	if exec.ToolName != "Bash" || exec.ToolCallID != "t1" {
		t.Errorf("exec tool/id = %q/%q, want Bash/t1", exec.ToolName, exec.ToolCallID)
	}
	if result.EventType != model.EventCommandResult {
		t.Errorf("result type = %q, want command.result (correlated by tool_use_id)", result.EventType)
	}
	if result.ToolCallID != "t1" {
		t.Errorf("result call id = %q, want t1", result.ToolCallID)
	}
	if result.ExitCode != nil {
		t.Errorf("exit code must never be fabricated, got %d", *result.ExitCode)
	}
	if hasTag(result.Tags, model.TagToolError) {
		t.Errorf("non-error result must NOT carry tool_error: %+v", result.Tags)
	}
}

// TestOpenClawReadResultNoPreview proves a Read tool_use maps to file.read with
// the path from input.file_path, and the correlated tool_result (a tool.result,
// NOT a command.result) never previews the returned file content.
func TestOpenClawReadResultNoPreview(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"r1","name":"Read","input":{"file_path":"/home/dev/.env"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"r1","content":"SECRET=hunter2\nKEY=abc"}]}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	call, result := res.Events[0], res.Events[1]
	if call.EventType != model.EventFileRead || call.FilePath != "/home/dev/.env" {
		t.Errorf("call = %q/%q, want file.read//home/dev/.env", call.EventType, call.FilePath)
	}
	if result.EventType != model.EventToolResult {
		t.Errorf("read result type = %q, want tool.result", result.EventType)
	}
	if result.ContentPreview != "" {
		t.Errorf("read result must NOT preview file content, got %q", result.ContentPreview)
	}
	if strings.Contains(result.ContentPreview, "hunter2") {
		t.Errorf("read result leaked file content: %q", result.ContentPreview)
	}
}

// TestOpenClawWritePathOnly proves a Write/Edit tool_use maps to file.write with
// the path captured and NO file body stored verbatim.
func TestOpenClawWritePathOnly(t *testing.T) {
	for _, name := range []string{"Write", "FileWrite", "Edit", "FileEdit", "write"} {
		body := withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"w1","name":"` + name + `","input":{"file_path":"/home/dev/main.go","content":"package main"}}]}}`)
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("%s: got %d events, want 1: %+v", name, len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventFileWrite || ev.FilePath != "/home/dev/main.go" {
			t.Errorf("%s: = %q/%q, want file.write//home/dev/main.go", name, ev.EventType, ev.FilePath)
		}
		if ev.ContentPreview != "" {
			t.Errorf("%s: write must not store body, got preview %q", name, ev.ContentPreview)
		}
	}
}

// TestOpenClawNetworkURL proves a WebFetch tool_use maps to network.indicator
// with a valid http(s) url promoted and the network tag set.
func TestOpenClawNetworkURL(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"n1","name":"WebFetch","input":{"url":"https://evil.example/x"}}]}}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
	}
	ev := res.Events[0]
	if ev.EventType != model.EventNetworkIndicator || ev.URL != "https://evil.example/x" {
		t.Errorf("= %q/%q, want network.indicator/https://evil.example/x", ev.EventType, ev.URL)
	}
	if ev.ContentPreview != "https://evil.example/x" {
		t.Errorf("preview = %q, want the requested URL", ev.ContentPreview)
	}
	if !hasTag(ev.Tags, model.TagNetwork) {
		t.Errorf("WebFetch must carry network tag: %+v", ev.Tags)
	}
}

// TestOpenClawNetworkRejectsNonHTTP proves a non-http(s) or hostless url arg is
// NOT promoted into Event.URL (no fabricated target), while the network.indicator
// event and network tag still stand because a network tool was invoked.
func TestOpenClawNetworkRejectsNonHTTP(t *testing.T) {
	for _, bad := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,<script>1</script>",
		"ftp://host/x",
		"https://:443/path",
		"/relative/path",
		"not a url at all",
	} {
		body := withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"n1","name":"WebFetch","input":{"url":` + strconv.Quote(bad) + `}}]}}`)
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("%q: got %d events, want 1", bad, len(res.Events))
		}
		ev := res.Events[0]
		if ev.EventType != model.EventNetworkIndicator {
			t.Errorf("%q: type = %q, want network.indicator", bad, ev.EventType)
		}
		if ev.URL != "" {
			t.Errorf("%q: URL = %q, want empty (non-http(s) must not be promoted)", bad, ev.URL)
		}
		if ev.ContentPreview != preview(bad) {
			t.Errorf("%q: preview = %q, want the unpromoted investigative lead", bad, ev.ContentPreview)
		}
		if !hasTag(ev.Tags, model.TagNetwork) {
			t.Errorf("%q: must still carry network tag: %+v", bad, ev.Tags)
		}
	}
}

// TestOpenClawWebSearchNoURL proves a search tool (no url arg) still maps to
// network.indicator with the network tag and NO fabricated url.
func TestOpenClawWebSearchNoURL(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"n1","name":"WebSearch","input":{"query":"how to exfiltrate"}}]}}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	ev := res.Events[0]
	if ev.EventType != model.EventNetworkIndicator || ev.URL != "" {
		t.Errorf("= %q/%q, want network.indicator/empty url", ev.EventType, ev.URL)
	}
	if ev.ContentPreview != "how to exfiltrate" {
		t.Errorf("preview = %q, want the search query", ev.ContentPreview)
	}
	if !hasTag(ev.Tags, model.TagNetwork) {
		t.Errorf("WebSearch must carry network tag: %+v", ev.Tags)
	}
}

// TestOpenClawToolErrorOnlyFromStructuredFlag proves the tool_error tag is set
// ONLY from a structured is_error:true. A false flag, an absent flag, and a
// result whose content prose contains "error" all yield NO tag.
func TestOpenClawToolErrorOnlyFromStructuredFlag(t *testing.T) {
	// is_error:true → tag.
	errBody := withHeader(
		`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"false"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"boom","is_error":true}]}}`,
	)
	res := extractOpenClaw(t, errBody)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	if !hasTag(res.Events[1].Tags, model.TagToolError) {
		t.Errorf("is_error:true must carry tool_error tag: %+v", res.Events[1].Tags)
	}

	// is_error:false / absent / prose "error" → NO tag.
	for _, result := range []string{
		`{"type":"tool_result","tool_use_id":"t2","content":"ok","is_error":false}`,
		`{"type":"tool_result","tool_use_id":"t2","content":"error: something went wrong"}`,
	} {
		clean := withHeader(
			`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"x"}}]}}`,
			`{"type":"message","message":{"role":"user","content":[`+result+`]}}`,
		)
		r := extractOpenClaw(t, clean)
		if len(r.Events) != 2 {
			t.Fatalf("%s: got %d events, want 2", result, len(r.Events))
		}
		if hasTag(r.Events[1].Tags, model.TagToolError) {
			t.Errorf("%s: must NOT carry tool_error (no structured true): %+v", result, r.Events[1].Tags)
		}
	}
}

// TestOpenClawUnknownToolGeneric proves an unknown tool name falls through to a
// generic tool.call (NO alias promotion), and its correlated result is a
// tool.result.
func TestOpenClawUnknownToolGeneric(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"u1","name":"some_future_tool","input":{"foo":"bar"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"u1","content":"done"}]}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	call, result := res.Events[0], res.Events[1]
	if call.EventType != model.EventToolCall || call.ToolName != "some_future_tool" {
		t.Errorf("call = %q/%q, want tool.call/some_future_tool", call.EventType, call.ToolName)
	}
	if call.Command != "" || call.FilePath != "" || call.URL != "" {
		t.Errorf("unknown tool must fabricate no typed field: %+v", call)
	}
	if result.EventType != model.EventToolResult {
		t.Errorf("result type = %q, want tool.result", result.EventType)
	}
}

// TestOpenClawMCPToolSplit proves an MCP-qualified tool name (mcp__server__tool)
// splits into the typed mcp_server/mcp_tool fields on both the call and the
// correlated result.
func TestOpenClawMCPToolSplit(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"m1","name":"mcp__github__create_issue","input":{"title":"hi"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"m1","name":"mcp__github__create_issue","content":"issue #1"}]}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	for i, ev := range res.Events {
		if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
			t.Errorf("event[%d] mcp split = %q/%q, want github/create_issue", i, ev.MCPServer, ev.MCPTool)
		}
	}
}

// TestOpenClawCustomMessageNoOp proves a custom_message entry (the real
// top-level {type, customType, content, display} shape — context replay, NOT an
// agent action) is recognized and intentionally no-op'd: it emits NO event and
// NEVER fabricates a tool event. Because it is RECOGNIZED, a file of only
// custom_message rows does not trip the "no recognized entries" diagnostic — but
// it does still surface the "0 tool/message events" coverage gap.
func TestOpenClawCustomMessageNoOp(t *testing.T) {
	body := withHeader(`{"type":"custom_message","customType":"reminder","content":"injected note","display":true}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 0 {
		t.Fatalf("custom_message must emit no event, got %+v", res.Events)
	}
	// The header + custom_message are both recognized, but no tool/message event
	// was produced: a coverage diagnostic must name the gap (not "no recognized
	// entries", since the rows WERE recognized).
	if len(res.Diagnostics) == 0 {
		t.Fatalf("a transcript with no tool/message events must record a coverage diagnostic")
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "no recognized entries") {
			t.Errorf("custom_message rows are recognized; diagnostic must not claim none were: %q", d.Msg)
		}
	}
}

// TestOpenClawIgnoredTypes proves custom / compaction / branch_summary entries
// are an explicit no-op: no event and NO diagnostic (recognized, not guessed).
func TestOpenClawIgnoredTypes(t *testing.T) {
	body := withHeader(
		`{"type":"custom","id":"c1"}`,
		`{"type":"compaction","firstKeptEntryId":"e1","tokensBefore":100}`,
		`{"type":"branch_summary","id":"b1"}`,
		`{"type":"message","message":{"role":"user","content":"real prompt"}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1 (only the message): %+v", len(res.Events), res.Events)
	}
	if len(res.Diagnostics) != 0 {
		t.Errorf("ignored types must not diagnose: %+v", res.Diagnostics)
	}
}

// TestOpenClawMissingTypeDiagnostic proves a line missing a type discriminator,
// and a line with an unknown type, each record a diagnostic (a coverage gap is
// visible, not silent).
func TestOpenClawMissingTypeDiagnostic(t *testing.T) {
	missing := extractOpenClaw(t, withHeader(`{"message":{"role":"user","content":"x"}}`))
	if len(missing.Diagnostics) == 0 {
		t.Errorf("missing type must record a diagnostic")
	}
	unknown := extractOpenClaw(t, withHeader(`{"type":"future_kind","id":"x"}`))
	if len(unknown.Diagnostics) == 0 {
		t.Errorf("unknown type must record a diagnostic")
	}
}

// TestOpenClawMalformedLineSkipped proves a single malformed line is diagnosed
// and skipped while the rest of the transcript still parses.
func TestOpenClawMalformedLineSkipped(t *testing.T) {
	body := withHeader(
		`{not valid json`,
		`{"type":"message","message":{"role":"user","content":"after the bad line"}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1 (good line still parses): %+v", len(res.Events), res.Events)
	}
	if len(res.Diagnostics) == 0 {
		t.Errorf("malformed line must record a diagnostic")
	}
	if res.Events[0].ContentPreview != "after the bad line" {
		t.Errorf("preview = %q, want %q", res.Events[0].ContentPreview, "after the bad line")
	}
}

// TestOpenClawEmptyFileNoOp proves an empty/whitespace transcript is a clean
// no-op: no events, NO diagnostic — matching the other extractors' contract.
func TestOpenClawEmptyFileNoOp(t *testing.T) {
	for _, body := range []string{"", "   ", "\n\t "} {
		res := extractOpenClaw(t, body)
		if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
			t.Errorf("empty body %q: got events=%d diags=%d, want 0/0", body, len(res.Events), len(res.Diagnostics))
		}
	}
}

// TestOpenClawHeaderOnlyDiagnostic proves a transcript that parsed lines but
// produced no tool/message activity (a header-only session) records a DIAGNOSTIC
// rather than a silent empty result.
func TestOpenClawHeaderOnlyDiagnostic(t *testing.T) {
	res := extractOpenClaw(t, openClawHeader)
	if len(res.Events) != 0 {
		t.Errorf("header-only must emit no events, got %+v", res.Events)
	}
	if len(res.Diagnostics) == 0 {
		t.Errorf("header-only transcript must record a coverage diagnostic")
	}
}

// TestOpenClawJSONPointer proves the Evidence.JSONPointer resolves into the
// transcript line at the decode position, and the 1-based line number is stamped.
func TestOpenClawJSONPointer(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	exec, result := res.Events[0], res.Events[1]
	if exec.Evidence.JSONPointer != "/message/content/0/input" {
		t.Errorf("exec pointer = %q, want /message/content/0/input", exec.Evidence.JSONPointer)
	}
	if exec.Evidence.Line != 2 {
		t.Errorf("exec line = %d, want 2 (header is line 1)", exec.Evidence.Line)
	}
	if result.Evidence.JSONPointer != "/message/content/0" {
		t.Errorf("result pointer = %q, want /message/content/0", result.Evidence.JSONPointer)
	}
	if result.Evidence.Line != 3 {
		t.Errorf("result line = %d, want 3", result.Evidence.Line)
	}
}

// TestOpenClawMultiBlockOrder proves a single message carrying several content
// blocks emits one event per block, in block order, with unique event ids.
func TestOpenClawMultiBlockOrder(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"assistant","content":[` +
		`{"type":"text","text":"running checks"},` +
		`{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"go test"}},` +
		`{"type":"tool_use","id":"t2","name":"Read","input":{"file_path":"/x"}}` +
		`]}}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventMessageAssistant {
		t.Errorf("block 0 type = %q, want message.assistant", res.Events[0].EventType)
	}
	if res.Events[1].EventType != model.EventCommandExec || res.Events[2].EventType != model.EventFileRead {
		t.Errorf("block order wrong: %q, %q", res.Events[1].EventType, res.Events[2].EventType)
	}
	if res.Events[1].EventID == res.Events[2].EventID {
		t.Errorf("blocks in one line must have distinct event ids")
	}
}

// TestOpenClawUncorrelatedResultIsToolResult proves a tool_result whose
// tool_use_id was never seen as a command call degrades to a tool.result (not a
// command.result), since the command-vs-read distinction is recovered from the
// correlated call.
func TestOpenClawUncorrelatedResultIsToolResult(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"orphan","content":"x"}]}}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	if res.Events[0].EventType != model.EventToolResult {
		t.Errorf("uncorrelated result = %q, want tool.result", res.Events[0].EventType)
	}
}

// TestOpenClawEventsSatisfyContract runs every distinct mapping through
// model.Event.Validate so a field set outside the co-occurrence allow-list is
// caught at the boundary.
func TestOpenClawEventsSatisfyContract(t *testing.T) {
	bodies := []string{
		withHeader(`{"type":"message","message":{"role":"user","content":"a prompt"}}`),
		withHeader(`{"type":"message","message":{"role":"assistant","content":"a reply"}}`),
		withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"x"}}]}}`),
		withHeader(
			`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"y"}}]}}`,
			`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","content":"o","is_error":true}]}}`,
		),
		withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"r1","name":"Read","input":{"file_path":"/x"}}]}}`),
		withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"w1","name":"Write","input":{"file_path":"/x"}}]}}`),
		withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"n1","name":"WebFetch","input":{"url":"https://x.example"}}]}}`),
		withHeader(`{"type":"message","message":{"role":"assistant","content":[{"type":"tool_use","id":"u1","name":"thing","input":{}}]}}`),
		withHeader(`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"u1","name":"mcp__s__t","content":"o"}]}}`),
	}
	for _, body := range bodies {
		res := extractOpenClaw(t, body)
		if len(res.Events) == 0 {
			t.Fatalf("body produced no events: %s", body)
		}
		for _, ev := range res.Events {
			if err := ev.Validate(); err != nil {
				t.Errorf("emitted event violates contract: %v\n  event=%+v", err, ev)
			}
		}
	}
}

// TestOpenClawSizeCap proves an artifact larger than the configured cap is
// rejected with an error rather than read into memory.
func TestOpenClawSizeCap(t *testing.T) {
	big := strings.Repeat("x", 64)
	_, err := OpenClawExtractor{maxBytes: 16}.Extract(strings.NewReader(big), Source{Path: openClawPath})
	if err == nil {
		t.Fatalf("oversized artifact must return an error")
	}
}

// TestOpenClawStringContentPointerResolves proves the source-faithfulness fix
// (B3): when message.content is a STRING, the evidence pointer is /message/content
// (the value that exists on disk), NOT a fabricated /message/content/0/text that
// cannot resolve. An ARRAY text block keeps the indexed /message/content/<i>/text.
func TestOpenClawStringContentPointerResolves(t *testing.T) {
	body := withHeader(
		`{"type":"message","message":{"role":"user","content":"plain string prompt"}}`,
		`{"type":"message","message":{"role":"assistant","content":[{"type":"text","text":"array block reply"}]}}`,
	)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].Evidence.JSONPointer != "/message/content" {
		t.Errorf("string-content pointer = %q, want /message/content", res.Events[0].Evidence.JSONPointer)
	}
	if res.Events[1].Evidence.JSONPointer != "/message/content/0/text" {
		t.Errorf("array-block pointer = %q, want /message/content/0/text", res.Events[1].Evidence.JSONPointer)
	}
}

// TestOpenClawEveryPointerResolves is the source-faithfulness regression: for a
// transcript exercising string content, array text, tool_use, and tool_result,
// EVERY emitted Evidence.JSONPointer must resolve against the ORIGINAL JSON line
// via an RFC-6901 resolver. A pointer that does not resolve is a forensic lie.
func TestOpenClawEveryPointerResolves(t *testing.T) {
	lines := []string{
		`{"type":"message","message":{"role":"user","content":"a string prompt"}}`,
		`{"type":"message","message":{"role":"assistant","content":[{"type":"text","text":"thinking out loud"},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}`,
		`{"type":"message","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}}`,
	}
	body := withHeader(lines...)
	res := extractOpenClaw(t, body)
	if len(res.Events) == 0 {
		t.Fatalf("expected events")
	}
	// All lines including the header; Evidence.Line is 1-based over them.
	all := append([]string{openClawHeader}, lines...)
	for _, ev := range res.Events {
		if ev.Evidence.Line < 1 || ev.Evidence.Line > len(all) {
			t.Fatalf("event line %d out of range", ev.Evidence.Line)
		}
		var doc any
		if err := json.Unmarshal([]byte(all[ev.Evidence.Line-1]), &doc); err != nil {
			t.Fatalf("line %d not valid JSON: %v", ev.Evidence.Line, err)
		}
		if _, err := resolveJSONPointer(doc, ev.Evidence.JSONPointer); err != nil {
			t.Errorf("pointer %q does not resolve against line %d (%s): %v",
				ev.Evidence.JSONPointer, ev.Evidence.Line, all[ev.Evidence.Line-1], err)
		}
	}
}

// resolveJSONPointer is a minimal RFC-6901 resolver used only by the pointer
// regression test: it walks "/"-separated, ~-unescaped reference tokens through
// decoded JSON (maps and slices). It returns an error if any token does not
// resolve, which is exactly the source-faithfulness property under test.
func resolveJSONPointer(doc any, pointer string) (any, error) {
	if pointer == "" {
		return doc, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, errBadPointer
	}
	cur := doc
	for _, tok := range strings.Split(pointer[1:], "/") {
		tok = strings.ReplaceAll(tok, "~1", "/")
		tok = strings.ReplaceAll(tok, "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return nil, errBadPointer
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, errBadPointer
			}
			cur = node[idx]
		default:
			return nil, errBadPointer
		}
	}
	return cur, nil
}

var errBadPointer = errInvalidPointer{}

type errInvalidPointer struct{}

func (errInvalidPointer) Error() string { return "pointer does not resolve" }

// TestOpenClawSystemRoleActor proves a system-role text message is attributed to
// the SYSTEM actor (not the assistant), so the timeline does not misreport a
// system instruction as the assistant speaking.
func TestOpenClawSystemRoleActor(t *testing.T) {
	body := withHeader(`{"type":"message","message":{"role":"system","content":"system note"}}`)
	res := extractOpenClaw(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].Actor != model.ActorSystem {
		t.Errorf("system-role actor = %q, want %q", res.Events[0].Actor, model.ActorSystem)
	}
}

// TestOpenClawOverLongOnlyDiagnostic proves a file consisting ONLY of an
// over-long (skipped) line still surfaces a coverage diagnostic rather than a
// silent clean 0/0.
func TestOpenClawOverLongOnlyDiagnostic(t *testing.T) {
	// A single line longer than readLine's per-line cap; no decodable line at all.
	res := extractOpenClaw(t, longLine()+"\n")
	if len(res.Events) != 0 {
		t.Fatalf("over-long-only file must emit no events, got %+v", res.Events)
	}
	if len(res.Diagnostics) == 0 {
		t.Errorf("over-long-only file must record a diagnostic, got none")
	}
}

// longLine returns a single JSONL line longer than readLine's size cap so it is
// skipped as over-long.
func longLine() string {
	return `{"type":"message","message":{"role":"user","content":"` + strings.Repeat("A", maxLineSize+16) + `"}}`
}

// --- Codex flavor ---------------------------------------------------------

// TestOpenClawCodexFlavorFunctionCall proves a Codex-flavor OpenClaw transcript
// (response_item rows, function_call with a JSON-string arguments) is detected
// and parsed with full fidelity: a shell function_call → command.exec, its
// function_call_output correlated by call_id → command.result, and NO exit code
// fabricated.
func TestOpenClawCodexFlavorFunctionCall(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-1","cwd":"/work/cx"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":\"go build\"}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}`,
	}, "\n")
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	exec, result := res.Events[0], res.Events[1]
	if exec.EventType != model.EventCommandExec || exec.Command != "go build" {
		t.Errorf("exec = %q/%q, want command.exec/go build", exec.EventType, exec.Command)
	}
	if exec.SessionID != "cx-1" || exec.ProjectPath != "/work/cx" {
		t.Errorf("session identity not seeded: id=%q cwd=%q", exec.SessionID, exec.ProjectPath)
	}
	if result.EventType != model.EventCommandResult || result.ToolCallID != "c1" {
		t.Errorf("result = %q/%q, want command.result/c1", result.EventType, result.ToolCallID)
	}
	if result.ContentPreview != "ok" {
		t.Errorf("result preview = %q, want ok", result.ContentPreview)
	}
	if result.ExitCode != nil {
		t.Errorf("codex command result must never fabricate an exit code, got %d", *result.ExitCode)
	}
}

// Codex-flavor OpenClaw transcripts use the current exec_command name and cmd
// argument for shell calls. Other function calls remain generic tools.
func TestOpenClawCodexExecCommandFunctionCall(t *testing.T) {
	t.Run("exec command", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-ex","cwd":"/work/cx"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"ex1","arguments":"{\"cmd\":\"go test ./...\",\"workdir\":\"/repo\"}"}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventCommandExec {
			t.Errorf("event_type = %q, want command.exec", ev.EventType)
		}
		if ev.Command != "go test ./..." {
			t.Errorf("command = %q, want the exec_command cmd field", ev.Command)
		}
		if ev.ToolName != codexToolExecCommand || ev.ToolCallID != "ex1" {
			t.Errorf("tool = %q/%q, want %s/ex1", ev.ToolName, ev.ToolCallID, codexToolExecCommand)
		}
	})

	t.Run("generic tool", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-nf","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"some_future_tool","call_id":"nf1","arguments":"{\"foo\":\"bar\"}"}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventToolCall || ev.ToolName != "some_future_tool" {
			t.Errorf("event_type = %q tool = %q, want tool.call/some_future_tool", ev.EventType, ev.ToolName)
		}
		if ev.Command != "" {
			t.Errorf("non-shell function_call must not fabricate a command: %q", ev.Command)
		}
	})
}

// Regression: the OpenClaw embedded-Codex parser must emit events for
// the four response_item variants canonical codex.go handles —
// custom_tool_call, tool_search_output, image_generation_call, tool_search_call —
// rather than silently dropping them via the default no-op. Fails on current main
// (silent drop yields 0 events), passes after the four cases are added.
func TestOpenClawCodexResponseItemParity(t *testing.T) {
	t.Run("custom_tool_call emits tool.call with input pointer and MCP split", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-c","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"ct1","input":"SELECT 1"}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventToolCall {
			t.Errorf("event_type = %q, want tool.call", ev.EventType)
		}
		if ev.ToolName != "mcp__db__query" || ev.ToolCallID != "ct1" {
			t.Errorf("tool = %q/%q, want mcp__db__query/ct1", ev.ToolName, ev.ToolCallID)
		}
		if ev.ContentPreview != "SELECT 1" {
			t.Errorf("content_preview = %q, want the input previewed", ev.ContentPreview)
		}
		if ev.Evidence.JSONPointer != "/payload/input" {
			t.Errorf("json_pointer = %q, want /payload/input", ev.Evidence.JSONPointer)
		}
		if ev.MCPServer != "db" || ev.MCPTool != "query" {
			t.Errorf("mcp split = %q/%q, want db/query", ev.MCPServer, ev.MCPTool)
		}
	})

	t.Run("tool_search_output emits tool.result with tools pointer", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-s","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"tool_search_call","call_id":"search1","arguments":{"query":"database tools"}}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"tool_search_output","call_id":"search1","tools":[{"name":"mcp__db__query"},{"name":"shell"}]}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 2 {
			t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
		}
		if call := res.Events[0]; call.EventType != model.EventToolCall || call.ToolCallID != "search1" {
			t.Errorf("call = %s/%q, want tool.call/search1", call.EventType, call.ToolCallID)
		}
		ev := res.Events[1]
		if ev.EventType != model.EventToolResult {
			t.Errorf("event_type = %q, want tool.result", ev.EventType)
		}
		if ev.ToolCallID != "search1" {
			t.Errorf("tool_call_id = %q, want search1", ev.ToolCallID)
		}
		if ev.ContentPreview != "mcp__db__query, shell" {
			t.Errorf("content_preview = %q, want the discovered tool names", ev.ContentPreview)
		}
		if ev.Evidence.JSONPointer != "/payload/tools" {
			t.Errorf("json_pointer = %q, want /payload/tools", ev.Evidence.JSONPointer)
		}
	})

	t.Run("image_generation_call emits named tool.call", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-i","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"image_generation_call","call_id":"img1"}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventToolCall || ev.ToolName != codexToolImage || ev.ToolCallID != "img1" {
			t.Errorf("got %s tool=%q id=%q, want tool.call %s/img1", ev.EventType, ev.ToolName, ev.ToolCallID, codexToolImage)
		}
		if ev.Evidence.JSONPointer != "/payload" {
			t.Errorf("json_pointer = %q, want /payload", ev.Evidence.JSONPointer)
		}
	})

	t.Run("tool_search_call emits named tool.call with structured argument preview", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-ts","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"tool_search_call","call_id":"ts1","arguments":{"query":"find repo review agents","limit":8}}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Diagnostics) != 0 {
			t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
		}
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventToolCall || ev.ToolName != codexToolSearch || ev.ToolCallID != "ts1" {
			t.Errorf("got %s tool=%q id=%q, want tool.call %s/ts1", ev.EventType, ev.ToolName, ev.ToolCallID, codexToolSearch)
		}
		if ev.ContentPreview != "find repo review agents" {
			t.Errorf("content_preview = %q, want the search query", ev.ContentPreview)
		}
		if ev.Evidence.JSONPointer != "/payload/arguments" {
			t.Errorf("json_pointer = %q, want /payload/arguments", ev.Evidence.JSONPointer)
		}
	})
}

func TestOpenClawCodexReasoningIsOptIn(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-r","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"source summary"}]}}`,
	}, "\n")
	if got := extractOpenClaw(t, body); len(got.Events) != 0 {
		t.Fatalf("default reasoning events = %+v", got.Events)
	}
	res := extractOpenClawSource(t, body, Source{
		Path:             openClawPath,
		CaseID:           "case-claw",
		IncludeReasoning: true,
		CaptureContent:   true,
	})
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventMessageReasoning ||
		res.Events[0].ContentForAnalysis() != "source summary" {
		t.Fatalf("reasoning events = %+v", res.Events)
	}
}

func TestOpenClawEmbeddedCodexCodeModeParity(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"git status", workdir:"/w"}); text(r);`
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-code","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"code1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"code1","output":[{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":"{\"exit_code\":3,\"wall_time_seconds\":0.012,\"output\":\"failed\\n\"}"}]}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want command + result: %+v", len(res.Events), res.Events)
	}
	call, result := res.Events[0], res.Events[1]
	if call.EventType != model.EventCommandExec || call.ToolName != codexToolExecCommand || call.Command != "git status" {
		t.Errorf("call = %+v, want code-mode command.exec", call)
	}
	if result.EventType != model.EventCommandResult || result.ToolCallID != "code1" ||
		result.ToolName != codexToolExecCommand || result.ContentPreview != "failed" ||
		result.ExitCode == nil || *result.ExitCode != 3 || result.DurationMs == nil ||
		*result.DurationMs != 12 || !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("result = %+v, want correlated command.result with preview", result)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawEmbeddedCodexLongRunningCodeModeParity(t *testing.T) {
	input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
	poll := `const r = await tools.write_stdin({session_id:25546, chars:""}); text(r);`
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-code","cwd":"/w"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":` + jsonString(input) + `}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
		`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":[{"type":"input_text","text":"Script completed\nWall time 30.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"session_id\":25546,\"output\":\"still running\"}"}]}}`,
		`{"timestamp":"t5","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"poll1","input":` + jsonString(poll) + `}}`,
		`{"timestamp":"t6","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"poll1","output":"Script running with cell ID 19\nWall time 30.0 seconds\nOutput:\n"}}`,
		`{"timestamp":"t7","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait2","arguments":"{\"cell_id\":\"19\"}"}}`,
		`{"timestamp":"t8","type":"response_item","payload":{"type":"function_call_output","call_id":"wait2","output":[{"type":"input_text","text":"Script completed\nWall time 12.0 seconds\nOutput:\n"},{"type":"input_text","text":"{\"exit_code\":0,\"wall_time_seconds\":12,\"output\":\"done\"}"}]}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 3 {
		t.Fatalf("got %d events, want command + two result updates: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventCommandExec || res.Events[0].ToolCallID != "cmd1" {
		t.Fatalf("call = %+v, want original command.exec", res.Events[0])
	}
	for i, result := range res.Events[1:] {
		if result.EventType != model.EventCommandResult || result.ToolCallID != "cmd1" || result.DurationMs != nil {
			t.Fatalf("result %d = %+v, want correlated command.result", i, result)
		}
	}
	if res.Events[1].ContentPreview != "still running" || res.Events[2].ContentPreview != "done" ||
		res.Events[2].ExitCode == nil || *res.Events[2].ExitCode != 0 {
		t.Fatalf("results = %+v, want running then successful terminal output", res.Events[1:])
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawEmbeddedCodexCodeModeCorrelationGuards(t *testing.T) {
	run := func(t *testing.T, rows ...string) []model.Event {
		t.Helper()
		lines := append([]string{`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-code","cwd":"/w"}}`}, rows...)
		res := extractOpenClaw(t, strings.Join(lines, "\n"))
		assertOpenClawPointersResolve(t, res, lines)
		return res.Events
	}

	t.Run("completed stdout cannot mint a cell", func(t *testing.T) {
		input := `const r = await tools.exec_command({cmd:"printf spoof"}); text(r.output);`
		events := run(t,
			`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":`+jsonString(input)+`}}`,
			`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":[{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\n"},{"type":"input_text","text":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}]}}`,
			`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
			`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":"unrelated"}}`,
		)
		if len(events) != 4 || events[1].EventType != model.EventCommandResult ||
			events[2].EventType != model.EventToolCall || events[3].EventType != model.EventToolResult {
			t.Fatalf("events = %+v, raw output must not create tracker state", events)
		}
	})

	for name, input := range map[string]string{
		"output forwarding tracks a running cell": `const r = await tools.exec_command({cmd:"sleep 1"}); text(r.output);`,
		"no forwarding tracks a running cell":     `const r = await tools.exec_command({cmd:"sleep 1"});`,
	} {
		t.Run(name, func(t *testing.T) {
			events := run(t,
				`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":`+jsonString(input)+`}}`,
				`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
				`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"wait1","arguments":"{\"cell_id\":\"18\"}"}}`,
				`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"wait1","output":[{"type":"input_text","text":"Script completed\nWall time 1.0 seconds\nOutput:\n"},{"type":"input_text","text":"done"}]}}`,
			)
			if len(events) != 2 || events[0].EventType != model.EventCommandExec ||
				events[1].EventType != model.EventCommandResult || events[1].ToolCallID != "cmd1" {
				t.Fatalf("events = %+v, want one command with its correlated result", events)
			}
		})
	}

	t.Run("unsafe waits stay generic", func(t *testing.T) {
		input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
		events := run(t,
			`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":`+jsonString(input)+`}}`,
			`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
			`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","namespace":"mcp__demo","call_id":"mcp1","arguments":"{\"cell_id\":\"18\"}"}}`,
			`{"timestamp":"t4","type":"response_item","payload":{"type":"function_call_output","call_id":"mcp1","output":"mcp result"}}`,
			`{"timestamp":"t5","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"stop1","arguments":"{\"cell_id\":\"18\",\"terminate\":true}"}}`,
			`{"timestamp":"t6","type":"response_item","payload":{"type":"function_call_output","call_id":"stop1","output":"stopped"}}`,
		)
		if len(events) != 5 {
			t.Fatalf("got %d events, want command plus two generic call/result pairs: %+v", len(events), events)
		}
		for _, index := range []int{1, 3} {
			if events[index].EventType != model.EventToolCall || events[index+1].EventType != model.EventToolResult {
				t.Fatalf("events = %+v, unsafe waits must stay generic", events)
			}
		}
	})

	t.Run("reused call id drops old owner", func(t *testing.T) {
		input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
		events := run(t,
			`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":`+jsonString(input)+`}}`,
			`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
			`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"same","arguments":"{\"cell_id\":\"18\"}"}}`,
			`{"timestamp":"t4","type":"response_item","payload":{"type":"custom_tool_call","name":"other","call_id":"same","input":"{}"}}`,
			`{"timestamp":"t5","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"new owner"}}`,
		)
		if len(events) != 3 || events[1].EventType != model.EventToolCall || events[2].EventType != model.EventToolResult {
			t.Fatalf("events = %+v, reused call id must not retain old command ownership", events)
		}
	})

	t.Run("local shell takes reused wait id", func(t *testing.T) {
		input := `const r = await tools.exec_command({cmd:"sleep 60"}); text(r);`
		events := run(t,
			`{"timestamp":"t1","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"cmd1","input":`+jsonString(input)+`}}`,
			`{"timestamp":"t2","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"cmd1","output":"Script running with cell ID 18\nWall time 11.0 seconds\nOutput:\n"}}`,
			`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"same","arguments":"{\"cell_id\":\"18\"}"}}`,
			`{"timestamp":"t4","type":"response_item","payload":{"type":"local_shell_call","call_id":"same","action":{"type":"exec","command":["echo","new"]}}}`,
			`{"timestamp":"t5","type":"response_item","payload":{"type":"function_call_output","call_id":"same","output":"new"}}`,
		)
		if len(events) != 3 || events[1].EventType != model.EventCommandExec || events[1].ToolCallID != "same" ||
			events[2].EventType != model.EventCommandResult || events[2].ToolCallID != "same" {
			t.Fatalf("events = %+v, local shell must replace the pending wait owner", events)
		}
	})

	t.Run("generic function takes reused shell id", func(t *testing.T) {
		events := run(t,
			`{"timestamp":"t1","type":"response_item","payload":{"type":"local_shell_call","call_id":"same","action":{"type":"exec","command":["echo","old"]}}}`,
			`{"timestamp":"t2","type":"response_item","payload":{"type":"function_call","name":"other","call_id":"same","arguments":"{}"}}`,
			`{"timestamp":"t3","type":"response_item","payload":{"type":"function_call_output","call_id":"same","output":"new owner"}}`,
		)
		if len(events) != 3 || events[1].EventType != model.EventToolCall || events[2].EventType != model.EventToolResult {
			t.Fatalf("events = %+v, generic function must replace the shell owner", events)
		}
	})
}

func TestOpenClawEmbeddedCodexAmbiguousCodeModeStaysGeneric(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-code","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"same","arguments":"{\"cmd\":\"true\"}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"same","input":"const r = await tools.exec_command({cmd:\"id\"}); text(r.output);"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"same","input":"await tools.exec_command({cmd: dynamic})"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"unknown"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 4 {
		t.Fatalf("got %d events, want 4: %+v", len(res.Events), res.Events)
	}
	if res.Events[2].EventType != model.EventToolCall || res.Events[3].EventType != model.EventToolResult {
		t.Errorf("ambiguous custom call/result = %s/%s, want tool.call/tool.result", res.Events[2].EventType, res.Events[3].EventType)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

// Regression: the OpenClaw embedded-Codex web_search_call must carry
// the action locator in ContentPreview exactly like canonical codex.go, so a
// bare search query (no url) still surfaces WHAT was searched instead of
// emitting a network.indicator with both URL and preview empty. A concrete
// open_page url is promoted into Event.URL. Fails on main (preview omitted),
// passes after the preview line is mirrored.
func TestOpenClawCodexWebSearchPreviewParity(t *testing.T) {
	t.Run("bare query previews the search term and leaves URL empty", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-w","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"web_search_call","call_id":"w1","action":{"query":"how to exfiltrate secrets"}}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.EventType != model.EventNetworkIndicator {
			t.Errorf("event_type = %q, want network.indicator", ev.EventType)
		}
		if ev.ContentPreview != "how to exfiltrate secrets" {
			t.Errorf("content_preview = %q, want the search query (the investigative lead must not be lost)", ev.ContentPreview)
		}
		if ev.URL != "" {
			t.Errorf("url = %q, want empty (a bare query has no egress target to promote)", ev.URL)
		}
		if !hasTag(ev.Tags, model.TagNetwork) {
			t.Errorf("tags = %v, want network", ev.Tags)
		}
	})

	t.Run("open_page url is promoted and previewed", func(t *testing.T) {
		body := strings.Join([]string{
			`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-w","cwd":"/w"}}`,
			`{"timestamp":"t","type":"response_item","payload":{"type":"web_search_call","call_id":"w2","action":{"url":"https://evil.example/x"}}}`,
		}, "\n")
		res := extractOpenClaw(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1: %+v", len(res.Events), res.Events)
		}
		ev := res.Events[0]
		if ev.URL != "https://evil.example/x" {
			t.Errorf("url = %q, want the concrete open_page target promoted", ev.URL)
		}
		if ev.ContentPreview != "https://evil.example/x" {
			t.Errorf("content_preview = %q, want the action locator", ev.ContentPreview)
		}
	})
}

// Regression: an embedded-Codex `compacted` outer row must be a
// recognized no-op (like canonical codex.go), producing no event AND no "not
// modeled" diagnostic. Fails on main (compacted hits the default and is
// diagnosed as not modeled), passes after the explicit case is added.
func TestOpenClawCodexCompactedIsRecognizedNoOp(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-k","cwd":"/w"}}`,
		`{"timestamp":"t","type":"compacted","payload":{"message":"history summary"}}`,
	}, "\n")
	res := extractOpenClaw(t, body)
	if len(res.Events) != 0 {
		t.Fatalf("compacted row should emit no event, got %d: %+v", len(res.Events), res.Events)
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "not modeled") {
			t.Errorf("compacted row produced a 'not modeled' diagnostic, want a clean recognized skip: %q", d.Msg)
		}
	}
}

// TestOpenClawCodexApplyPatch proves a Codex apply_patch function_call maps each
// touched file to a file.write/file.delete REQUEST (medium confidence, intent
// tag) with the diff digest recorded and no patch body stored.
func TestOpenClawCodexApplyPatch(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\n+hi\n*** Delete File: b.txt\n*** End Patch"
	args, _ := json.Marshal(map[string]string{"patch": patch})
	payload := `{"type":"function_call","name":"apply_patch","call_id":"p1","arguments":` + strconv.Quote(string(args)) + `}`
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-2","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":` + payload + `}`,
	}, "\n")
	res := extractOpenClaw(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2 (add + delete): %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventFileWrite || res.Events[0].FilePath != "a.txt" {
		t.Errorf("event0 = %q/%q, want file.write/a.txt", res.Events[0].EventType, res.Events[0].FilePath)
	}
	if res.Events[1].EventType != model.EventFileDelete || res.Events[1].FilePath != "b.txt" {
		t.Errorf("event1 = %q/%q, want file.delete/b.txt", res.Events[1].EventType, res.Events[1].FilePath)
	}
	for _, ev := range res.Events {
		if ev.DiffSHA256 == "" || ev.DiffBytes == 0 {
			t.Errorf("apply_patch event must record diff digest/size: %+v", ev)
		}
		if ev.ContentPreview != "" {
			t.Errorf("apply_patch must not store patch body: %q", ev.ContentPreview)
		}
	}
}

// TestOpenClawCodexFlavorDetected proves detection is content-based: a file whose
// rows are Codex-shaped is parsed as Codex even at the standard sessions/ path.
func TestOpenClawCodexFlavorDetected(t *testing.T) {
	if got := detectOpenClawFlavor([]byte(`{"type":"response_item","payload":{}}`)); got != openClawFlavorCodex {
		t.Errorf("response_item must detect as codex, got %v", got)
	}
	if got := detectOpenClawFlavor([]byte(`{"type":"session_meta","payload":{}}`)); got != openClawFlavorCodex {
		t.Errorf("session_meta must detect as codex, got %v", got)
	}
	if got := detectOpenClawFlavor([]byte(openClawHeader)); got != openClawFlavorNative {
		t.Errorf("session header must detect as native, got %v", got)
	}
	if got := detectOpenClawFlavor([]byte(`{"type":"event_msg","payload":{"type":"user_message"}}`)); got != openClawFlavorEventMsg {
		t.Errorf("event_msg must detect as event_msg, got %v", got)
	}
	if got := detectOpenClawFlavor([]byte(`{"type":"mystery"}`)); got != openClawFlavorUnknown {
		t.Errorf("unrecognized rows must detect as unknown, got %v", got)
	}
}

// TestOpenClawEventMsgFailLoud proves an event_msg-flavor file is NOT coerced
// through the native path and NOT silently zeroed: it emits no events and a
// fail-loud diagnostic naming the unparsed flavor.
func TestOpenClawEventMsgFailLoud(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"event_msg","payload":{"type":"user_message","message":"hi"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"agent_message","message":"yo"}}`,
	}, "\n")
	res := extractOpenClaw(t, body)
	if len(res.Events) != 0 {
		t.Fatalf("event_msg flavor must emit no events (not coerced), got %+v", res.Events)
	}
	if len(res.Diagnostics) == 0 {
		t.Fatalf("event_msg flavor must record a fail-loud diagnostic")
	}
	found := false
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "flavor event_msg not parsed") {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnostic must name the unparsed flavor: %+v", res.Diagnostics)
	}
}

// TestOpenClawUnknownFlavorFailLoud proves a file whose rows match no known flavor
// emits no events and a fail-loud unknown-flavor diagnostic (never coerced).
func TestOpenClawUnknownFlavorFailLoud(t *testing.T) {
	body := strings.Join([]string{
		`{"type":"mystery_a","foo":1}`,
		`{"type":"mystery_b","bar":2}`,
	}, "\n")
	res := extractOpenClaw(t, body)
	if len(res.Events) != 0 {
		t.Fatalf("unknown flavor must emit no events, got %+v", res.Events)
	}
	found := false
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "flavor unknown not parsed") {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnostic must name the unknown flavor: %+v", res.Diagnostics)
	}
}

// TestOpenClawCodexEventsSatisfyContract runs the Codex-flavor mappings through
// model.Event.Validate so a field set outside the co-occurrence allow-list is
// caught at the boundary.
func TestOpenClawCodexEventsSatisfyContract(t *testing.T) {
	body := strings.Join([]string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":\"ls\"}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"read_file","call_id":"c2","arguments":"{\"path\":\"/x\"}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"web_search_call","call_id":"c3","action":{"type":"open_page","url":"https://x.example"}}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__db__query","call_id":"c4","arguments":"{}"}}`,
	}, "\n")
	res := extractOpenClaw(t, body)
	if len(res.Events) == 0 {
		t.Fatalf("codex body produced no events")
	}
	for _, ev := range res.Events {
		if err := ev.Validate(); err != nil {
			t.Errorf("emitted codex event violates contract: %v\n  event=%+v", err, ev)
		}
	}
}

// assertOpenClawPointersResolve checks that every emitted Evidence.JSONPointer
// resolves (RFC-6901) into its original transcript line — the source-faithfulness
// property the other OpenClaw pointer tests enforce.
func assertOpenClawPointersResolve(t *testing.T, res *Result, lines []string) {
	t.Helper()
	for _, ev := range res.Events {
		if ev.Evidence.Line < 1 || ev.Evidence.Line > len(lines) {
			t.Fatalf("event line %d out of range (have %d lines)", ev.Evidence.Line, len(lines))
		}
		var doc any
		if err := json.Unmarshal([]byte(lines[ev.Evidence.Line-1]), &doc); err != nil {
			t.Fatalf("line %d not valid JSON: %v", ev.Evidence.Line, err)
		}
		if _, err := resolveJSONPointer(doc, ev.Evidence.JSONPointer); err != nil {
			t.Errorf("pointer %q does not resolve against line %d (%s): %v",
				ev.Evidence.JSONPointer, ev.Evidence.Line, lines[ev.Evidence.Line-1], err)
		}
	}
}

// TestOpenClawCodexEventMsgMcpToolErrorTagsResult proves a Codex-flavor OpenClaw
// transcript that mixes response_item rows with an event_msg mcp_tool_call_end
// recording a FAILURE tags the matching tool.result (by call_id) TagToolError —
// the structured MCP tool-error must not be a false negative on the OpenClaw path,
// just as on the canonical Codex path.
func TestOpenClawCodexEventMsgMcpToolErrorTagsResult(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-mcp","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__db__query","call_id":"m1","arguments":"{}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"m1","output":"boom"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"m1","result":{"Ok":{"is_error":true}}}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	var result *model.Event
	for i := range res.Events {
		if res.Events[i].EventType == model.EventToolResult && res.Events[i].ToolCallID == "m1" {
			result = &res.Events[i]
		}
	}
	if result == nil {
		t.Fatalf("expected a tool.result for m1, events=%+v", res.Events)
		return
	}
	if !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("structured MCP failure must tag tool.result tool_error: %+v", result.Tags)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

// TestOpenClawCodexEventMsgMcpToolErrorOutOfOrder proves the out-of-order variant:
// when the mcp_tool_call_end FAILURE arrives BEFORE the custom_tool_call_output,
// the failed call_id is remembered in state and the later output still carries
// TagToolError.
func TestOpenClawCodexEventMsgMcpToolErrorOutOfOrder(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-ooo","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__db__query","call_id":"m2","arguments":"{}"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"m2","result":{"Err":"transport closed"}}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"m2","output":"late"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	var result *model.Event
	for i := range res.Events {
		if res.Events[i].EventType == model.EventToolResult && res.Events[i].ToolCallID == "m2" {
			result = &res.Events[i]
		}
	}
	if result == nil {
		t.Fatalf("expected a tool.result for m2, events=%+v", res.Events)
		return
	}
	if !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("out-of-order MCP failure must still tag the later tool.result: %+v", result.Tags)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawCodexDeferredMCPFailureIsSingleUse(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-single","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"same","input":"SELECT 1"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"same","result":{"Err":"timeout"}}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"first"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"same","output":"duplicate"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))

	var results []model.Event
	for _, ev := range res.Events {
		if ev.EventType == model.EventToolResult && ev.ToolCallID == "same" {
			results = append(results, ev)
		}
	}
	if len(results) != 2 {
		t.Fatalf("got %d tool results, want 2: %+v", len(results), res.Events)
	}
	if !hasTag(results[0].Tags, model.TagToolError) || hasTag(results[1].Tags, model.TagToolError) {
		t.Errorf("deferred failure leaked past its first result: %+v", results)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawCodexNewCallClearsDeferredMCPFailure(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-reuse","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__db__query","call_id":"same","input":"SELECT 1"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"same","result":{"Err":"timeout"}}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"lookup","call_id":"same","arguments":"{}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call_output","call_id":"same","output":"clean"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))

	for _, ev := range res.Events {
		if ev.EventType == model.EventToolResult && ev.ToolCallID == "same" && hasTag(ev.Tags, model.TagToolError) {
			t.Fatalf("new call inherited a stale MCP failure: %+v", ev)
		}
	}
	assertOpenClawPointersResolve(t, res, lines)
}

// TestOpenClawCodexEventMsgMcpToolSuccessNoTag proves a SUCCESS mcp_tool_call_end
// leaves the tool.result untagged — no false positive (high-precision boundary:
// tool_error only from a structured failure).
func TestOpenClawCodexEventMsgMcpToolSuccessNoTag(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-ok","cwd":"/w"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"function_call","name":"mcp__db__query","call_id":"m3","arguments":"{}"}}`,
		`{"timestamp":"t","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"m3","output":"rows"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"m3","result":{"Ok":{"is_error":false}}}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	for _, ev := range res.Events {
		if ev.EventType == model.EventToolResult && ev.ToolCallID == "m3" {
			if hasTag(ev.Tags, model.TagToolError) {
				t.Errorf("successful MCP result must NOT carry tool_error: %+v", ev.Tags)
			}
		}
	}
}

// TestOpenClawCodexEventMsgStateTransitions proves each no-twin state transition
// (turn_aborted / thread_rolled_back / entered_review_mode / exited_review_mode /
// thread_goal_updated) becomes a low-confidence system note tagged with the
// transition type, with a /payload JSONPointer that resolves into the record.
func TestOpenClawCodexEventMsgStateTransitions(t *testing.T) {
	lines := []string{
		`{"timestamp":"t","type":"session_meta","payload":{"id":"cx-st","cwd":"/w"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"turn_aborted","reason":"interrupted"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"thread_rolled_back"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"entered_review_mode"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"exited_review_mode"}}`,
		`{"timestamp":"t","type":"event_msg","payload":{"type":"thread_goal_updated"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	wantTags := []string{"turn_aborted", "thread_rolled_back", "entered_review_mode", "exited_review_mode", "thread_goal_updated"}
	if len(res.Events) != len(wantTags) {
		t.Fatalf("got %d events, want %d: %+v", len(res.Events), len(wantTags), res.Events)
	}
	for i, want := range wantTags {
		ev := res.Events[i]
		if ev.EventType != model.EventMessageAssistant || ev.Actor != model.ActorSystem {
			t.Errorf("%s: type/actor = %q/%q, want message.assistant/system", want, ev.EventType, ev.Actor)
		}
		if ev.Confidence != model.ConfidenceLow {
			t.Errorf("%s: confidence = %q, want low", want, ev.Confidence)
		}
		if !hasTag(ev.Tags, want) {
			t.Errorf("%s: missing tag, got %+v", want, ev.Tags)
		}
		if ev.Evidence.JSONPointer != "/payload" {
			t.Errorf("%s: pointer = %q, want /payload", want, ev.Evidence.JSONPointer)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: event violates contract: %v", want, err)
		}
	}
	if preview := res.Events[0].ContentPreview; !strings.Contains(preview, "turn aborted: interrupted") {
		t.Errorf("turn_aborted preview should carry the reason, got %q", preview)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

// TestOpenClawStableNativeAgentMessageContract is derived from OpenClaw
// v2026.7.1's SessionManager replay fixture and AgentMessage types. Stable
// transcripts persist normalized toolCall blocks and a separate role:toolResult
// envelope (not provider-native tool_use/tool_result blocks). Native exec adds
// the structured details.exitCode contract exercised here.
func TestOpenClawStableNativeAgentMessageContract(t *testing.T) {
	lines := []string{
		`{"type":"session","version":3,"id":"string-tool-result-session","timestamp":"2026-07-01T00:00:00.000Z","cwd":"/tmp/tool-result-replay"}`,
		`{"type":"message","id":"user-1","parentId":null,"timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"user","content":"run lookup","timestamp":1}}`,
		`{"type":"message","id":"assistant-1","parentId":"user-1","timestamp":"2026-07-01T00:00:02.000Z","message":{"role":"assistant","provider":"anthropic","api":"anthropic-messages","model":"claude-sonnet-4-6","stopReason":"toolUse","timestamp":2,"content":[{"type":"toolCall","id":"call_1","name":"exec","arguments":{"command":"false"}}]}}`,
		`{"type":"message","id":"tool-result-1","parentId":"assistant-1","timestamp":"2026-07-01T00:00:03.000Z","message":{"role":"toolResult","toolCallId":"call_1","toolName":"exec","content":[{"type":"text","text":"Command exited with code 7"}],"details":{"status":"failed","exitCode":7},"isError":true,"timestamp":3}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 3 {
		t.Fatalf("got %d events, want prompt + exec + result: %+v", len(res.Events), res.Events)
	}
	prompt, call, result := res.Events[0], res.Events[1], res.Events[2]
	if prompt.EventType != model.EventPromptUser || prompt.Timestamp != "2026-07-01T00:00:01.000Z" {
		t.Errorf("prompt = %q @ %q", prompt.EventType, prompt.Timestamp)
	}
	if call.EventType != model.EventCommandExec || call.Command != "false" || call.ToolName != "exec" || call.ToolCallID != "call_1" {
		t.Errorf("call = %+v, want structured exec call", call)
	}
	if call.Timestamp != "2026-07-01T00:00:02.000Z" || call.Evidence.JSONPointer != "/message/content/0/arguments" {
		t.Errorf("call timestamp/pointer = %q/%q", call.Timestamp, call.Evidence.JSONPointer)
	}
	if result.EventType != model.EventCommandResult || result.ToolName != "exec" || result.ToolCallID != "call_1" {
		t.Errorf("result = %+v, want correlated exec result", result)
	}
	if result.ExitCode == nil || *result.ExitCode != 7 {
		t.Errorf("result exit code = %v, want 7", result.ExitCode)
	}
	if result.Timestamp != "2026-07-01T00:00:03.000Z" || result.Evidence.JSONPointer != "/message" {
		t.Errorf("result timestamp/pointer = %q/%q", result.Timestamp, result.Evidence.JSONPointer)
	}
	if !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("isError:true must tag the result: %+v", result.Tags)
	}
	if result.ContentPreview != "" {
		t.Errorf("tool result text must not be previewed, got %q", result.ContentPreview)
	}
	for _, ev := range res.Events {
		if err := ev.Validate(); err != nil {
			t.Errorf("stable native event violates contract: %v\n  event=%+v", err, ev)
		}
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawStableBashExecutionAndCustomContext(t *testing.T) {
	lines := []string{
		openClawHeader,
		`{"type":"message","id":"bash-1","timestamp":"2026-05-16T00:00:02.500Z","message":{"role":"bashExecution","command":"echo ok","output":"ok\n","exitCode":7,"cancelled":false,"truncated":false}}`,
		`{"type":"message","id":"custom-1","timestamp":"2026-05-16T00:00:03.000Z","message":{"role":"custom","customType":"runtime-context","content":"application context, not assistant output","display":false}}`,
		`{"type":"message","id":"bash-2","timestamp":"2026-05-16T00:00:04.000Z","message":{"role":"bashExecution","command":"sleep 30","output":"","cancelled":true,"truncated":false}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 4 {
		t.Fatalf("got %d events, want two bash call/result pairs and no custom event: %+v", len(res.Events), res.Events)
	}
	firstCall, firstResult, cancelledCall, cancelledResult := res.Events[0], res.Events[1], res.Events[2], res.Events[3]
	if firstCall.EventType != model.EventCommandExec || firstCall.Actor != model.ActorUser ||
		firstCall.ToolName != "bash" || firstCall.Command != "echo ok" ||
		firstCall.Evidence.JSONPointer != "/message/command" {
		t.Errorf("bash call = %+v", firstCall)
	}
	if firstResult.EventType != model.EventCommandResult || firstResult.Actor != model.ActorTool ||
		firstResult.ExitCode == nil || *firstResult.ExitCode != 7 || !hasTag(firstResult.Tags, model.TagToolError) ||
		firstResult.ContentPreview != "" {
		t.Errorf("bash result = %+v", firstResult)
	}
	if cancelledCall.Command != "sleep 30" || cancelledResult.ExitCode != nil ||
		!hasTag(cancelledResult.Tags, model.TagToolError) {
		t.Errorf("cancelled bash mapping = %+v / %+v", cancelledCall, cancelledResult)
	}
	for _, ev := range res.Events {
		if err := ev.Validate(); err != nil {
			t.Errorf("bash event violates contract: %v\n  event=%+v", err, ev)
		}
	}
	assertOpenClawPointersResolve(t, res, lines)
}

// TestOpenClawStableNativeToolVocabulary pins the v2026.7.1 built-in names and
// argument keys. Unknown/plugin tools still fall through to generic tool.call.
func TestOpenClawStableNativeToolVocabulary(t *testing.T) {
	line := `{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"assistant","content":[` +
		`{"type":"toolCall","id":"r","name":"read","arguments":{"path":"/tmp/in"}},` +
		`{"type":"toolCall","id":"w","name":"write","arguments":{"path":"/tmp/out","content":"secret"}},` +
		`{"type":"toolCall","id":"e","name":"edit","arguments":{"path":"/tmp/edit","oldText":"a","newText":"b"}},` +
		`{"type":"toolCall","id":"f","name":"web_fetch","arguments":{"url":"https://fetch.example/x"}},` +
		`{"type":"toolCall","id":"s","name":"web_search","arguments":{"query":"numbat"}},` +
		`{"type":"toolCall","id":"b","name":"browser","arguments":{"targetUrl":"https://browser.example/x"}},` +
		`{"type":"toolCall","id":"bt","name":"browser","arguments":{"action":"tabs"}},` +
		`{"type":"toolCall","id":"p","name":"plugin_widget","arguments":{}}` +
		`]}}`
	lines := []string{openClawHeader, line}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 8 {
		t.Fatalf("got %d events, want 8: %+v", len(res.Events), res.Events)
	}
	want := []struct {
		typ     model.EventType
		path    string
		url     string
		preview string
	}{
		{model.EventFileRead, "/tmp/in", "", ""},
		{model.EventFileWrite, "/tmp/out", "", ""},
		{model.EventFileWrite, "/tmp/edit", "", ""},
		{model.EventNetworkIndicator, "", "https://fetch.example/x", "https://fetch.example/x"},
		{model.EventNetworkIndicator, "", "", "numbat"},
		{model.EventNetworkIndicator, "", "https://browser.example/x", "https://browser.example/x"},
		{model.EventToolCall, "", "", ""},
		{model.EventToolCall, "", "", ""},
	}
	for i, expected := range want {
		ev := res.Events[i]
		if ev.EventType != expected.typ || ev.FilePath != expected.path || ev.URL != expected.url || ev.ContentPreview != expected.preview {
			t.Errorf("event %d = %q path=%q url=%q preview=%q, want %q path=%q url=%q preview=%q", i, ev.EventType, ev.FilePath, ev.URL, ev.ContentPreview, expected.typ, expected.path, expected.url, expected.preview)
		}
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawStableCodeModeExecStaysGeneric(t *testing.T) {
	callLine := `{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"assistant","content":[` +
		`{"type":"toolCall","id":"code","name":"exec","arguments":{"code":"await fetch('https://example.com')","language":"javascript"}},` +
		`{"type":"toolCall","id":"empty","name":"exec","arguments":{}},` +
		`{"type":"toolCall","id":"shell","name":"exec","arguments":{"command":"git status"}}` +
		`]}}`
	lines := []string{
		openClawHeader,
		callLine,
		`{"type":"message","timestamp":"2026-07-01T00:00:02.000Z","message":{"role":"toolResult","toolCallId":"code","toolName":"exec","content":"ok","details":{"exitCode":0}}}`,
		`{"type":"message","timestamp":"2026-07-01T00:00:03.000Z","message":{"role":"toolResult","toolCallId":"empty","toolName":"exec","content":"ok","details":{"exitCode":0}}}`,
		`{"type":"message","timestamp":"2026-07-01T00:00:04.000Z","message":{"role":"toolResult","toolCallId":"shell","toolName":"exec","content":"ok","details":{"exitCode":0}}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 6 {
		t.Fatalf("got %d events, want 6: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventToolCall || res.Events[0].Command != "" ||
		res.Events[1].EventType != model.EventToolCall || res.Events[1].Command != "" {
		t.Errorf("code-mode/malformed exec mapping = %+v / %+v", res.Events[0], res.Events[1])
	}
	if res.Events[2].EventType != model.EventCommandExec || res.Events[2].Command != "git status" {
		t.Errorf("shell exec mapping = %+v", res.Events[2])
	}
	if res.Events[3].EventType != model.EventToolResult || res.Events[3].ExitCode != nil ||
		res.Events[4].EventType != model.EventToolResult || res.Events[4].ExitCode != nil {
		t.Errorf("generic exec results = %+v / %+v", res.Events[3], res.Events[4])
	}
	if res.Events[5].EventType != model.EventCommandResult || res.Events[5].ExitCode == nil || *res.Events[5].ExitCode != 0 {
		t.Errorf("shell exec result = %+v", res.Events[5])
	}
}

// TestOpenClawSourceBackedProviderCallVariants pins the stable replay contract
// in v2026.7.1: OpenClaw deliberately retains Anthropic toolUse/input and
// OpenAI functionCall/arguments blocks, and accepts provider-specific result-ID
// aliases alongside canonical toolCallId.
func TestOpenClawSourceBackedProviderCallVariants(t *testing.T) {
	lines := []string{
		openClawHeader,
		`{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"toolUse","id":"r","name":"read","input":{"path":"/tmp/provider-input"}},{"type":"functionCall","id":"f","name":"exec","arguments":{"command":"true"}}]}}`,
		`{"type":"message","timestamp":"2026-07-01T00:00:02.000Z","message":{"role":"toolResult","toolUseId":" r ","toolName":"read","content":"ok"}}`,
		`{"type":"message","timestamp":"2026-07-01T00:00:03.000Z","message":{"role":"toolResult","call_id":" f ","toolName":"exec","content":"ok","details":{"status":"completed","exitCode":0}}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 4 {
		t.Fatalf("got %d events, want two calls + two results: %+v", len(res.Events), res.Events)
	}
	read, exec, readResult, execResult := res.Events[0], res.Events[1], res.Events[2], res.Events[3]
	if read.EventType != model.EventFileRead || read.FilePath != "/tmp/provider-input" || read.ToolCallID != "r" {
		t.Errorf("toolUse call = %+v, want correlated file.read", read)
	}
	if read.Evidence.JSONPointer != "/message/content/0/input" {
		t.Errorf("toolUse pointer = %q, want provider input field", read.Evidence.JSONPointer)
	}
	if exec.EventType != model.EventCommandExec || exec.Command != "true" || exec.ToolCallID != "f" {
		t.Errorf("functionCall = %+v, want correlated command.exec", exec)
	}
	if exec.Evidence.JSONPointer != "/message/content/1/arguments" {
		t.Errorf("functionCall pointer = %q, want provider arguments field", exec.Evidence.JSONPointer)
	}
	if readResult.EventType != model.EventToolResult || readResult.ToolCallID != "r" {
		t.Errorf("toolUseId result = %+v, want tool.result correlated to r", readResult)
	}
	if execResult.EventType != model.EventCommandResult || execResult.ToolCallID != "f" || execResult.ExitCode == nil || *execResult.ExitCode != 0 {
		t.Errorf("call_id result = %+v, want successful command.result correlated to f", execResult)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

// TestOpenClawSourceBackedSnakeCallVariants covers the additional raw call
// spellings accepted by stable transcript repair. In particular, legacy
// function_call may persist arguments as a JSON-encoded string and call IDs may
// live in tool_call_id/call_id rather than id.
func TestOpenClawSourceBackedSnakeCallVariants(t *testing.T) {
	lines := []string{
		openClawHeader,
		`{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"tool_call","tool_call_id":"w","name":"write","arguments":{"path":"/tmp/snake-write","content":"secret"}},{"type":"function_call","call_id":"e","name":"exec","arguments":"{\"command\":\"true\"}"},{"type":"tool_use","id":"r","name":"read","input":{"path":"/tmp/snake-read"}}]}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 3 {
		t.Fatalf("got %d events, want three source-backed calls: %+v", len(res.Events), res.Events)
	}
	write, exec, read := res.Events[0], res.Events[1], res.Events[2]
	if write.EventType != model.EventFileWrite || write.FilePath != "/tmp/snake-write" || write.ToolCallID != "w" || write.ContentPreview != "" {
		t.Errorf("tool_call = %+v, want path-only file.write correlated to w", write)
	}
	if exec.EventType != model.EventCommandExec || exec.Command != "true" || exec.ToolCallID != "e" {
		t.Errorf("function_call = %+v, want decoded command.exec correlated to e", exec)
	}
	if read.EventType != model.EventFileRead || read.FilePath != "/tmp/snake-read" || read.ToolCallID != "r" {
		t.Errorf("tool_use = %+v, want file.read correlated to r", read)
	}
	if write.Evidence.JSONPointer != "/message/content/0/arguments" ||
		exec.Evidence.JSONPointer != "/message/content/1/arguments" ||
		read.Evidence.JSONPointer != "/message/content/2/input" {
		t.Errorf("provider argument pointers = %q, %q, %q", write.Evidence.JSONPointer, exec.Evidence.JSONPointer, read.Evidence.JSONPointer)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawStableNativeApplyPatch(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\n+hello\n*** Delete File: b.txt\n*** End Patch"
	line := `{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"patch-1","name":"apply_patch","arguments":{"input":` + strconv.Quote(patch) + `}}]}}`
	lines := []string{openClawHeader, line}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want add + delete: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventFileWrite || res.Events[0].FilePath != "a.txt" {
		t.Errorf("first patch event = %q/%q", res.Events[0].EventType, res.Events[0].FilePath)
	}
	if res.Events[1].EventType != model.EventFileDelete || res.Events[1].FilePath != "b.txt" {
		t.Errorf("second patch event = %q/%q", res.Events[1].EventType, res.Events[1].FilePath)
	}
	if res.Events[0].EventID == res.Events[1].EventID {
		t.Errorf("expanded patch events must have unique IDs")
	}
	for _, ev := range res.Events {
		if ev.Confidence != model.ConfidenceMedium || !hasTag(ev.Tags, codexTagPatchRequested) {
			t.Errorf("patch event must be medium-confidence requested intent: %+v", ev)
		}
		if ev.DiffSHA256 == "" || ev.DiffBytes != len(patch) || ev.ContentPreview != "" {
			t.Errorf("patch digest/size/data minimization failed: %+v", ev)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("patch event violates contract: %v", err)
		}
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawStableNativeExitCodeIsStrictlyStructured(t *testing.T) {
	cases := []struct {
		name    string
		details string
		want    *int
	}{
		{"zero", `,"details":{"status":"completed","exitCode":0}`, intPtr(0)},
		{"absent", "", nil},
		{"null", `,"details":{"exitCode":null}`, nil},
		{"string", `,"details":{"exitCode":"1"}`, nil},
		{"fraction", `,"details":{"exitCode":1.5}`, nil},
		{"wrong envelope", `,"details":{"code":1}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := `{"type":"message","timestamp":"2026-07-01T00:00:00.500Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"x","name":"exec","arguments":{"command":"true"}}]}}`
			line := `{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"toolResult","toolCallId":"x","toolName":"exec","content":"error in prose","isError":false,"timestamp":1` + tc.details + `}}`
			res := extractOpenClaw(t, withHeader(call, line))
			if len(res.Events) != 2 {
				t.Fatalf("got %d events, want call + result: %+v", len(res.Events), res.Events)
			}
			ev := res.Events[1]
			if tc.want == nil && ev.ExitCode != nil || tc.want != nil && (ev.ExitCode == nil || *ev.ExitCode != *tc.want) {
				t.Errorf("exit code = %v, want %v", ev.ExitCode, tc.want)
			}
			if hasTag(ev.Tags, model.TagToolError) {
				t.Errorf("isError:false must win over error-looking prose: %+v", ev.Tags)
			}
		})
	}
}

func TestOpenClawStableNativeMetadataEntriesAreRecognized(t *testing.T) {
	lines := []string{
		openClawHeader,
		`{"type":"thinking_level_change","id":"a","timestamp":"2026-07-01T00:00:01.000Z","thinkingLevel":"high"}`,
		`{"type":"model_change","id":"b","timestamp":"2026-07-01T00:00:02.000Z","provider":"anthropic","modelId":"m"}`,
		`{"type":"label","id":"c","timestamp":"2026-07-01T00:00:03.000Z","label":"branch"}`,
		`{"type":"session_info","id":"d","timestamp":"2026-07-01T00:00:04.000Z","name":"name"}`,
		`{"type":"leaf","id":"e","timestamp":"2026-07-01T00:00:05.000Z","targetId":"b"}`,
		`{"type":"message","id":"f","timestamp":"2026-07-01T00:00:06.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"x","name":"read","arguments":{"path":"/x"}}]}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventFileRead {
		t.Fatalf("got events %+v, want only final read", res.Events)
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "not modeled") {
			t.Errorf("stable metadata entry produced false coverage diagnostic: %q", d.Msg)
		}
	}
}

func TestOpenClawOuterTimestampDoesNotLeakBetweenRows(t *testing.T) {
	lines := []string{
		openClawHeader,
		`{"type":"message","timestamp":"2026-07-01T00:00:01.000Z","message":{"role":"user","content":"timed"}}`,
		`{"type":"message","message":{"role":"assistant","content":"legacy untimed"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	if res.Events[0].Timestamp != "2026-07-01T00:00:01.000Z" || res.Events[1].Timestamp != "" {
		t.Errorf("timestamps = %q, %q; prior row must not leak", res.Events[0].Timestamp, res.Events[1].Timestamp)
	}
}

func TestOpenClawCodexOuterTimestamp(t *testing.T) {
	lines := []string{
		`{"timestamp":"2026-07-01T00:00:00.000Z","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
		`{"timestamp":"2026-07-01T00:00:01.000Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":\"true\"}"}}`,
		`{"timestamp":"2026-07-01T00:00:02.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].Timestamp != "2026-07-01T00:00:01.000Z" || res.Events[1].Timestamp != "2026-07-01T00:00:02.000Z" {
		t.Errorf("codex timestamps = %q, %q", res.Events[0].Timestamp, res.Events[1].Timestamp)
	}
}

func TestOpenClawCodexPrefersUserMessageEvent(t *testing.T) {
	lines := []string{
		`{"timestamp":"t0","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>injected</environment_context>"}]}}`,
		`{"timestamp":"t2","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"human prompt"}]}}`,
		`{"timestamp":"t3","type":"event_msg","payload":{"type":"user_message","message":"human prompt"}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventPromptUser || res.Events[0].ContentPreview != "human prompt" {
		t.Fatalf("canonical prompt mapping = %+v", res.Events)
	}
	if res.Events[0].Evidence.Line != 4 || res.Events[0].Evidence.JSONPointer != "/payload/message" {
		t.Errorf("canonical prompt provenance = line %d %q", res.Events[0].Evidence.Line, res.Events[0].Evidence.JSONPointer)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawCodexPaginatedUserMessage(t *testing.T) {
	lines := []string{
		`{"timestamp":"t0","type":"session_meta","payload":{"id":"cx","cwd":"/w","history_mode":"paginated"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"paginated prompt"}]}}`,
		`{"timestamp":"t2","type":"event_msg","payload":{"type":"item_completed","item":{"type":"UserMessage","id":"u1","content":[{"type":"text","text":"paginated"},{"type":"text","text":" "},{"type":"text","text":"prompt"}]}}}`,
	}
	res := extractOpenClaw(t, strings.Join(lines, "\n"))
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventPromptUser || res.Events[0].ContentPreview != "paginated prompt" {
		t.Fatalf("paginated prompt mapping = %+v", res.Events)
	}
	if res.Events[0].Evidence.Line != 3 || res.Events[0].Evidence.JSONPointer != "/payload/item/content" {
		t.Errorf("paginated prompt provenance = line %d %q", res.Events[0].Evidence.Line, res.Events[0].Evidence.JSONPointer)
	}
	assertOpenClawPointersResolve(t, res, lines)
}

func TestOpenClawCodexResponsePromptFallbacks(t *testing.T) {
	tests := []struct {
		name        string
		lines       []string
		wantLine    int
		wantPointer string
	}{
		{
			name: "headerless response only",
			lines: []string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"human prompt"}}`,
			},
			wantLine:    1,
			wantPointer: "/payload/content",
		},
		{
			name: "headerless response replaced by explicit prompt",
			lines: []string{
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"human prompt"}}`,
				`{"timestamp":"t2","type":"event_msg","payload":{"type":"user_message","message":"human prompt"}}`,
			},
			wantLine:    2,
			wantPointer: "/payload/message",
		},
		{
			name: "headered response retained at EOF",
			lines: []string{
				`{"timestamp":"t0","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"human prompt"}}`,
			},
			wantLine:    2,
			wantPointer: "/payload/content",
		},
		{
			name: "paginated response retained after item start",
			lines: []string{
				`{"timestamp":"t0","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
				`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"human prompt"}}`,
				`{"timestamp":"t2","type":"event_msg","payload":{"type":"item_started","item":{"type":"UserMessage","content":[{"type":"text","text":"human prompt"}]}}}`,
			},
			wantLine:    2,
			wantPointer: "/payload/content",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := extractOpenClaw(t, strings.Join(tc.lines, "\n"))
			if len(res.Events) != 1 || res.Events[0].EventType != model.EventPromptUser || res.Events[0].ContentPreview != "human prompt" {
				t.Fatalf("prompt fallback = %+v", res.Events)
			}
			if res.Events[0].Evidence.Line != tc.wantLine || res.Events[0].Evidence.JSONPointer != tc.wantPointer {
				t.Errorf("prompt provenance = line %d %q", res.Events[0].Evidence.Line, res.Events[0].Evidence.JSONPointer)
			}
			assertOpenClawPointersResolve(t, res, tc.lines)
		})
	}
}

func TestOpenClawCodexDoesNotFlushInjectedContext(t *testing.T) {
	lines := []string{
		`{"timestamp":"t0","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
		`{"timestamp":"t1","type":"response_item","payload":{"type":"message","role":"user","content":"<environment_context>injected</environment_context>"}}`,
		`{"timestamp":"t2","type":"world_state","payload":{"full":false}}`,
	}
	if res := extractOpenClaw(t, strings.Join(lines, "\n")); len(res.Events) != 0 {
		t.Fatalf("injected context became a prompt: %+v", res.Events)
	}
}

func TestOpenClawCodexNamespacedNativeNamesStayGeneric(t *testing.T) {
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				`{"timestamp":"t0","type":"session_meta","payload":{"id":"cx","cwd":"/w"}}`,
				tc.call,
				tc.output,
			}
			res := extractOpenClaw(t, strings.Join(lines, "\n"))
			if len(res.Events) != 2 {
				t.Fatalf("got %d events, want call + result: %+v", len(res.Events), res.Events)
			}
			call, result := res.Events[0], res.Events[1]
			if call.EventType != model.EventToolCall || call.ToolName != tc.tool || call.MCPServer != "remote" || call.MCPTool != tc.tool {
				t.Errorf("call was specialized or lost namespace: %+v", call)
			}
			if call.Command != "" || call.FilePath != "" || call.DiffSHA256 != "" {
				t.Errorf("generic MCP call carries fabricated native fields: %+v", call)
			}
			if result.EventType != model.EventToolResult || result.ToolCallID != "c" {
				t.Errorf("result was promoted to a native result: %+v", result)
			}
			assertOpenClawPointersResolve(t, res, lines)
		})
	}
}

func intPtr(v int) *int { return &v }

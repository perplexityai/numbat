package extract

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// extractOpenCodePath parses body as an OpenCode storage record at the given
// on-disk path. The path is built with filepath.Join so the parser's
// path-independent dispatch (it keys off the record's JSON shape, not the path)
// is exercised the same way on every OS, and the helper stays macOS-symlink safe
// by never comparing a full path.
func extractOpenCodePath(t *testing.T, path, body string) *Result {
	return extractOpenCodePathWithReasoning(t, path, body, false)
}

func extractOpenCodePathWithReasoning(t *testing.T, path, body string, includeReasoning bool) *Result {
	t.Helper()
	res, err := OpenCodeExtractor{}.Extract(strings.NewReader(body), Source{Path: path, CaseID: "case-oc", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// extractOpenCode parses body as a part record under a current-layout part path.
func extractOpenCode(t *testing.T, body string) *Result {
	t.Helper()
	path := filepath.Join("/cases", "opencode", "storage", "part", "msg1", "prt1.json")
	return extractOpenCodePath(t, path, body)
}

// extractOpenCodeWithReasoning parses body with an explicit reasoning setting.
func extractOpenCodeWithReasoning(t *testing.T, body string, includeReasoning bool) *Result {
	t.Helper()
	path := filepath.Join("/cases", "opencode", "storage", "part", "msg1", "prt1.json")
	res, err := OpenCodeExtractor{}.Extract(strings.NewReader(body), Source{Path: path, CaseID: "case-oc", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

func TestOpenCodeAgent(t *testing.T) {
	if got := (OpenCodeExtractor{}).Agent(); got != model.AgentOpenCode {
		t.Errorf("Agent() = %q, want %q", got, model.AgentOpenCode)
	}
}

// TestOpenCodeBashToolPart proves a completed bash tool part maps to a
// command.exec followed by a correlated command.result (exec ordered first,
// both keyed by callID), the command is lifted from input.command and the output
// previewed on the result, NO exit code is fabricated, and a completed state
// carries NO tool_error tag.
func TestOpenCodeBashToolPart(t *testing.T) {
	body := `{
	  "id":"prt1","sessionID":"s1","messageID":"m1","type":"tool","callID":"call_a","tool":"bash",
	  "state":{"status":"completed","input":{"command":"make build"},"output":"build ok","time":{"start":1700000000000,"end":1700000000123}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	exec, result := res.Events[0], res.Events[1]
	if exec.EventType != model.EventCommandExec {
		t.Errorf("event[0] type = %q, want command.exec", exec.EventType)
	}
	if exec.Command != "make build" {
		t.Errorf("exec command = %q, want %q", exec.Command, "make build")
	}
	if exec.Actor != model.ActorAssistant {
		t.Errorf("exec actor = %q, want assistant", exec.Actor)
	}
	if result.EventType != model.EventCommandResult {
		t.Errorf("event[1] type = %q, want command.result", result.EventType)
	}
	if result.Command != "make build" {
		t.Errorf("result command = %q, want %q", result.Command, "make build")
	}
	if result.ContentPreview != "build ok" {
		t.Errorf("result preview = %q, want %q", result.ContentPreview, "build ok")
	}
	if exec.ToolCallID != "call_a" || result.ToolCallID != "call_a" {
		t.Errorf("callID not propagated: exec=%q result=%q", exec.ToolCallID, result.ToolCallID)
	}
	if exec.SessionID != "s1" || result.SessionID != "s1" {
		t.Errorf("sessionID not propagated: exec=%q result=%q", exec.SessionID, result.SessionID)
	}
	if exec.Timestamp != "2023-11-14T22:13:20Z" || result.Timestamp != "2023-11-14T22:13:20.123Z" {
		t.Errorf("tool timestamps not propagated: exec=%q result=%q", exec.Timestamp, result.Timestamp)
	}
	if result.ExitCode != nil {
		t.Errorf("exit code must not be fabricated, got %d", *result.ExitCode)
	}
	if hasTag(result.Tags, model.TagToolError) {
		t.Errorf("completed state must NOT carry tool_error: %+v", result.Tags)
	}
}

// TestOpenCodeToolErrorOnlyFromStatus proves the tool_error tag comes ONLY from
// a structured state.status=="error" — never from prose, never from an exit
// code. The error state's result carries the tag; a sibling completed state does
// not.
func TestOpenCodeToolErrorOnlyFromStatus(t *testing.T) {
	body := `{
	  "id":"prt1","type":"tool","callID":"call_e","tool":"bash",
	  "state":{"status":"error","input":{"command":"false"},"error":"command failed with exit 1","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	result := res.Events[1]
	if result.EventType != model.EventCommandResult {
		t.Errorf("result type = %q, want command.result", result.EventType)
	}
	if !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("error state must carry tool_error tag: %+v", result.Tags)
	}
}

// TestOpenCodeCompletedNotError proves a completed non-shell tool result is NOT
// flagged as an error even when its output prose contains the word "error".
func TestOpenCodeCompletedNotError(t *testing.T) {
	body := `{
	  "type":"tool","callID":"c1","tool":"someplugin",
	  "state":{"status":"completed","input":{"x":1},"output":"no error occurred","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	if hasTag(res.Events[1].Tags, model.TagToolError) {
		t.Errorf("prose 'error' must NOT trigger tool_error: %+v", res.Events[1].Tags)
	}
}

// TestOpenCodeReadTool proves a read tool part maps to file.read with the path
// from input.filePath, and the read RESULT never previews the output (file
// content is never stored).
func TestOpenCodeReadTool(t *testing.T) {
	body := `{
	  "type":"tool","callID":"c1","tool":"read",
	  "state":{"status":"completed","input":{"filePath":"/home/dev/.env"},"output":"SECRET=hunter2\nKEY=abc","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	call, result := res.Events[0], res.Events[1]
	if call.EventType != model.EventFileRead {
		t.Errorf("call type = %q, want file.read", call.EventType)
	}
	if call.FilePath != "/home/dev/.env" {
		t.Errorf("file path = %q, want /home/dev/.env", call.FilePath)
	}
	if result.ContentPreview != "" {
		t.Errorf("read result must NOT store content, got preview %q", result.ContentPreview)
	}
	if strings.Contains(result.ContentPreview, "hunter2") {
		t.Errorf("read result leaked file content: %q", result.ContentPreview)
	}
}

// TestOpenCodeWriteAndEdit proves write and edit tool parts both map to
// file.write with the path from input.filePath.
func TestOpenCodeWriteAndEdit(t *testing.T) {
	for _, tool := range []string{"write", "edit"} {
		body := `{
		  "type":"tool","callID":"c1","tool":"` + tool + `",
		  "state":{"status":"completed","input":{"filePath":"/home/dev/main.go"},"output":"ok","time":{"start":1,"end":2}}
		}`
		res := extractOpenCode(t, body)
		if len(res.Events) == 0 {
			t.Fatalf("%s: no events", tool)
		}
		if res.Events[0].EventType != model.EventFileWrite {
			t.Errorf("%s: type = %q, want file.write", tool, res.Events[0].EventType)
		}
		if res.Events[0].FilePath != "/home/dev/main.go" {
			t.Errorf("%s: path = %q, want /home/dev/main.go", tool, res.Events[0].FilePath)
		}
	}
}

// TestOpenCodeWebFetchURL proves a webfetch tool part maps to network.indicator
// with the url lifted from input.url and the network tag set.
func TestOpenCodeWebFetchURL(t *testing.T) {
	body := `{
	  "type":"tool","callID":"c1","tool":"webfetch",
	  "state":{"status":"completed","input":{"url":"https://evil.example/x"},"output":"<html>","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) == 0 {
		t.Fatalf("no events")
	}
	call := res.Events[0]
	if call.EventType != model.EventNetworkIndicator {
		t.Errorf("type = %q, want network.indicator", call.EventType)
	}
	if call.URL != "https://evil.example/x" {
		t.Errorf("url = %q, want https://evil.example/x", call.URL)
	}
	if !hasTag(call.Tags, model.TagNetwork) {
		t.Errorf("webfetch must carry network tag: %+v", call.Tags)
	}
}

// TestOpenCodeWebFetchRejectsNonHTTPScheme proves a webfetch arg that is not an
// absolute http(s) URL is NOT promoted into Event.URL: a tampered or malformed
// record carrying file://, javascript:, data:, or a relative/junk value leaves
// URL empty (kept as a preview instead) so numbat never fabricates a network
// target out of a non-egress string. The network.indicator + network tag still
// stand because the tool invoked was webfetch.
func TestOpenCodeWebFetchRejectsNonHTTPScheme(t *testing.T) {
	for _, bad := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,<script>1</script>",
		"ftp://host/x",
		"/relative/path",
		"not a url at all",
	} {
		body := `{
		  "type":"tool","callID":"c1","tool":"webfetch",
		  "state":{"status":"completed","input":{"url":` + strconv.Quote(bad) + `},"output":"x","time":{"start":1,"end":2}}
		}`
		res := extractOpenCode(t, body)
		if len(res.Events) == 0 {
			t.Fatalf("%q: no events", bad)
		}
		call := res.Events[0]
		if call.EventType != model.EventNetworkIndicator {
			t.Errorf("%q: type = %q, want network.indicator", bad, call.EventType)
		}
		if call.URL != "" {
			t.Errorf("%q: URL = %q, want empty (non-http(s) must not be promoted)", bad, call.URL)
		}
		if !hasTag(call.Tags, model.TagNetwork) {
			t.Errorf("%q: webfetch must still carry network tag: %+v", bad, call.Tags)
		}
	}
}

// TestOpenCodeWebSearchNoURL proves a websearch tool part maps to
// network.indicator with the query previewed and NO fabricated url.
func TestOpenCodeWebSearchNoURL(t *testing.T) {
	body := `{
	  "type":"tool","callID":"c1","tool":"websearch",
	  "state":{"status":"completed","input":{"query":"how to exfiltrate"},"output":"results","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) == 0 {
		t.Fatalf("no events")
	}
	call := res.Events[0]
	if call.EventType != model.EventNetworkIndicator {
		t.Errorf("type = %q, want network.indicator", call.EventType)
	}
	if call.URL != "" {
		t.Errorf("websearch must NOT fabricate a url, got %q", call.URL)
	}
	if call.ContentPreview != "how to exfiltrate" {
		t.Errorf("query preview = %q, want %q", call.ContentPreview, "how to exfiltrate")
	}
}

// TestOpenCodeUnknownTool proves an unknown tool id falls through to a generic
// tool.call / tool.result with NO alias promotion to a typed action.
func TestOpenCodeUnknownTool(t *testing.T) {
	body := `{
	  "type":"tool","callID":"c1","tool":"some_future_tool",
	  "state":{"status":"completed","input":{"foo":"bar"},"output":"done","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventToolCall {
		t.Errorf("call type = %q, want tool.call (no promotion)", res.Events[0].EventType)
	}
	if res.Events[1].EventType != model.EventToolResult {
		t.Errorf("result type = %q, want tool.result", res.Events[1].EventType)
	}
	if res.Events[0].ToolName != "some_future_tool" {
		t.Errorf("tool_name = %q, want preserved id", res.Events[0].ToolName)
	}
}

// TestOpenCodeEmptyOrBareToolPart pins the defensible behavior for a tool part
// that is structurally thin: an empty tool id, or a bare {"type":"tool"} with no
// state at all. Such a part must not panic and must not fabricate a typed
// action — it degrades to a nameless generic tool.call (and, when a terminal
// state is present, a matching tool.result), never a guessed command/file/url.
func TestOpenCodeEmptyOrBareToolPart(t *testing.T) {
	// Empty tool id with a completed state: nameless call + result, no promotion.
	emptyID := `{"type":"tool","callID":"c1","tool":"","state":{"status":"completed","output":"x"}}`
	res := extractOpenCode(t, emptyID)
	if len(res.Events) != 2 {
		t.Fatalf("empty tool id: got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].EventType != model.EventToolCall || res.Events[1].EventType != model.EventToolResult {
		t.Errorf("empty tool id: types = %q/%q, want tool.call/tool.result", res.Events[0].EventType, res.Events[1].EventType)
	}
	if res.Events[0].ToolName != "" || res.Events[0].Command != "" || res.Events[0].FilePath != "" || res.Events[0].URL != "" {
		t.Errorf("empty tool id must stay nameless and fabricate nothing: %+v", res.Events[0])
	}

	// Bare {"type":"tool"}: no state, so no terminal result — only the call.
	bare := `{"type":"tool"}`
	br := extractOpenCode(t, bare)
	if len(br.Events) != 1 {
		t.Fatalf("bare tool part: got %d events, want 1 (call only): %+v", len(br.Events), br.Events)
	}
	if br.Events[0].EventType != model.EventToolCall {
		t.Errorf("bare tool part: type = %q, want tool.call", br.Events[0].EventType)
	}
}

// TestOpenCodeMCPToolSplit proves an MCP-qualified tool id (mcp__server__tool)
// splits into the typed mcp_server/mcp_tool fields on both the call and result.
func TestOpenCodeMCPToolSplit(t *testing.T) {
	body := `{
	  "type":"tool","callID":"c1","tool":"mcp__github__create_issue",
	  "state":{"status":"completed","input":{"title":"hi"},"output":"issue #1","time":{"start":1,"end":2}}
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	for i, ev := range res.Events {
		if ev.EventType != model.EventToolCall && ev.EventType != model.EventToolResult {
			t.Errorf("event[%d] type = %q, want tool.call/result", i, ev.EventType)
		}
		if ev.MCPServer != "github" || ev.MCPTool != "create_issue" {
			t.Errorf("event[%d] mcp split = %q/%q, want github/create_issue", i, ev.MCPServer, ev.MCPTool)
		}
	}
}

// TestOpenCodePendingToolNoResult proves a pending/running tool part (no result
// yet) emits ONLY the call event, never a fabricated result.
func TestOpenCodePendingToolNoResult(t *testing.T) {
	for _, status := range []string{"pending", "running"} {
		body := `{
		  "type":"tool","callID":"c1","tool":"read",
		  "state":{"status":"` + status + `","input":{"filePath":"/x"}}
		}`
		res := extractOpenCode(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("%s: got %d events, want 1 (call only): %+v", status, len(res.Events), res.Events)
		}
		if res.Events[0].EventType != model.EventFileRead {
			t.Errorf("%s: type = %q, want file.read", status, res.Events[0].EventType)
		}
	}
}

// TestOpenCodeShellPart proves a legacy "shell" part maps to a command.exec +
// command.result with the command/output lifted directly, no exit fabricated.
func TestOpenCodeShellPart(t *testing.T) {
	body := `{
	  "id":"prt1","type":"shell","callID":"c1","command":"ls -la","output":"total 0"
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	exec, result := res.Events[0], res.Events[1]
	if exec.EventType != model.EventCommandExec || exec.Command != "ls -la" {
		t.Errorf("exec = %q/%q, want command.exec/ls -la", exec.EventType, exec.Command)
	}
	if result.EventType != model.EventCommandResult || result.ContentPreview != "total 0" {
		t.Errorf("result = %q/%q, want command.result/total 0", result.EventType, result.ContentPreview)
	}
	if result.ExitCode != nil {
		t.Errorf("shell part must not fabricate exit code")
	}
}

// TestOpenCodePatchPart proves a patch part maps to one file.write per touched
// file, each carrying the SHA-256 content hash as its diff digest.
func TestOpenCodePatchPart(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	body := `{
	  "id":"prt1","type":"patch","hash":"` + digest + `","files":["/home/dev/a.go","/home/dev/b.go"]
	}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(res.Events), res.Events)
	}
	for i, ev := range res.Events {
		if ev.EventType != model.EventFileWrite {
			t.Errorf("event[%d] type = %q, want file.write", i, ev.EventType)
		}
		if ev.DiffSHA256 != digest {
			t.Errorf("event[%d] diff digest = %q, want %s", i, ev.DiffSHA256, digest)
		}
	}
	if res.Events[0].FilePath != "/home/dev/a.go" || res.Events[1].FilePath != "/home/dev/b.go" {
		t.Errorf("patch file paths wrong: %q, %q", res.Events[0].FilePath, res.Events[1].FilePath)
	}
}

// TestOpenCodePatchInvalidHash proves a malformed or short patch hash is NOT
// stamped as a diff digest (no fabricated value), while the file.write is still
// emitted.
func TestOpenCodePatchInvalidHash(t *testing.T) {
	for _, hash := range []string{"not-a-hash!", "a1b2c3d4"} {
		body := `{"type":"patch","hash":"` + hash + `","files":["/x"]}`
		res := extractOpenCode(t, body)
		if len(res.Events) != 1 {
			t.Fatalf("got %d events, want 1", len(res.Events))
		}
		if res.Events[0].DiffSHA256 != "" {
			t.Errorf("invalid hash %q must not be stamped, got %q", hash, res.Events[0].DiffSHA256)
		}
	}
}

// TestOpenCodeTextAndReasoningAreNoOps proves text and reasoning parts are
// prose-only and OUT of scope for this forensic parser: they emit NO event and
// store NO preview, so numbat never retains assistant prose or model reasoning.
// Their absence is by design, so it is not a diagnostic gap either.
func TestOpenCodeTextAndReasoningAreNoOps(t *testing.T) {
	for _, body := range []string{
		`{"type":"text","text":"here is the plan"}`,
		`{"type":"reasoning","text":"let me think"}`,
	} {
		if r := extractOpenCode(t, body); len(r.Events) != 0 || len(r.Diagnostics) != 0 {
			t.Errorf("default %s: want no events and no diagnostics, got events=%+v diags=%+v", body, r.Events, r.Diagnostics)
		}
		if r := extractOpenCodeWithReasoning(t, body, true); len(r.Events) != 0 || len(r.Diagnostics) != 0 {
			t.Errorf("with reasoning %s: want no events and no diagnostics, got events=%+v diags=%+v", body, r.Events, r.Diagnostics)
		}
	}
}

// TestOpenCodeMessageRole proves a message file maps to prompt.user /
// message.assistant by role, and an unrecognized role records a diagnostic.
func TestOpenCodeMessageRole(t *testing.T) {
	userPath := filepath.Join("/cases", "opencode", "storage", "message", "s1", "m1.json")
	res := extractOpenCodePath(t, userPath, `{"id":"m1","sessionID":"s1","role":"user","time":{"created":1700000000000},"model":{"providerID":"openai","modelID":"gpt-5"}}`)
	if len(res.Events) != 1 || res.Events[0].EventType != model.EventPromptUser {
		t.Fatalf("user message: got %+v, want prompt.user", res.Events)
	}
	if res.Events[0].Actor != model.ActorUser {
		t.Errorf("user message actor = %q, want user", res.Events[0].Actor)
	}
	if res.Events[0].SessionID != "s1" || res.Events[0].Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("user message context = session %q at %q", res.Events[0].SessionID, res.Events[0].Timestamp)
	}
	if res.Events[0].Model != "gpt-5" || res.Events[0].ModelProvider != "openai" {
		t.Errorf("default extraction omitted model identity: %+v", res.Events[0])
	}

	asst := extractOpenCodePathWithReasoning(t, userPath, `{"id":"m1","sessionID":"s1","role":"assistant","time":{"created":1700000000123},"modelID":"gpt-5","providerID":"openai","path":{"cwd":"/repo"}}`, true)
	if len(asst.Events) != 1 || asst.Events[0].EventType != model.EventMessageAssistant {
		t.Fatalf("assistant message: got %+v, want message.assistant", asst.Events)
	}
	if got := asst.Events[0]; got.SessionID != "s1" || got.Timestamp != "2023-11-14T22:13:20.123Z" || got.ProjectPath != "/repo" || got.Model != "gpt-5" || got.ModelProvider != "openai" {
		t.Errorf("assistant message context not propagated: %+v", got)
	}

	sys := extractOpenCodePath(t, userPath, `{"id":"m1","role":"system"}`)
	if len(sys.Events) != 0 {
		t.Errorf("system role should emit no event, got %+v", sys.Events)
	}
	if len(sys.Diagnostics) == 0 {
		t.Errorf("unrecognized role should record a diagnostic")
	}
}

// TestOpenCodeEmptyFile proves an empty/whitespace file is a clean no-op (no
// events, NO diagnostic) — matching the other extractors' empty-input contract.
func TestOpenCodeEmptyFile(t *testing.T) {
	for _, body := range []string{"", "   ", "\n\t "} {
		res := extractOpenCode(t, body)
		if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
			t.Errorf("empty body %q: got events=%d diags=%d, want 0/0", body, len(res.Events), len(res.Diagnostics))
		}
	}
}

// TestOpenCodeEmptyObjectDiagnostic proves a decodable-but-empty record ({}) is
// surfaced as a DIAGNOSTIC, never a silent 0/0.
func TestOpenCodeEmptyObjectDiagnostic(t *testing.T) {
	res := extractOpenCode(t, `{}`)
	if len(res.Events) != 0 {
		t.Errorf("empty object should emit no events, got %+v", res.Events)
	}
	if len(res.Diagnostics) == 0 {
		t.Errorf("empty object must record a diagnostic, got none")
	}
}

// TestOpenCodeUnmodeledPartDiagnostic proves a valid part of an unmodeled kind
// (e.g. step-start) records a diagnostic rather than silently dropping.
func TestOpenCodeUnmodeledPartDiagnostic(t *testing.T) {
	res := extractOpenCode(t, `{"type":"step-start","id":"prt1"}`)
	if len(res.Events) != 0 {
		t.Errorf("unmodeled part should emit no events, got %+v", res.Events)
	}
	if len(res.Diagnostics) == 0 {
		t.Errorf("unmodeled part must record a diagnostic")
	}
}

// TestOpenCodeMalformedFailsSafe proves a malformed/truncated file fails SAFE: a
// diagnostic and no panic, no fabricated events.
func TestOpenCodeMalformedFailsSafe(t *testing.T) {
	for _, body := range []string{`{"type":"tool",`, `[1,2,3]`, `"just a string"`, `{not json}`} {
		res := extractOpenCode(t, body)
		if len(res.Events) != 0 {
			t.Errorf("malformed %q: emitted events %+v", body, res.Events)
		}
		if len(res.Diagnostics) == 0 {
			t.Errorf("malformed %q: should record a diagnostic", body)
		}
	}
}

// TestOpenCodeJSONPointer proves the Evidence.JSONPointer resolves into the
// original record at the decode position.
func TestOpenCodeJSONPointer(t *testing.T) {
	body := `{"type":"tool","callID":"c1","tool":"read","state":{"status":"completed","input":{"filePath":"/x"},"output":"y","time":{"start":1,"end":2}}}`
	res := extractOpenCode(t, body)
	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	if res.Events[0].Evidence.JSONPointer != "/state/input" {
		t.Errorf("call pointer = %q, want /state/input", res.Events[0].Evidence.JSONPointer)
	}
	if res.Events[1].Evidence.JSONPointer != "/state" {
		t.Errorf("result pointer = %q, want /state", res.Events[1].Evidence.JSONPointer)
	}
}

// TestOpenCodeEventsSatisfyContract runs every distinct mapping through
// model.Event.Validate so a field set outside the co-occurrence allow-list is
// caught at the boundary.
func TestOpenCodeEventsSatisfyContract(t *testing.T) {
	bodies := []string{
		`{"type":"tool","callID":"c1","tool":"bash","state":{"status":"error","input":{"command":"x"},"error":"boom","time":{"start":1,"end":2}}}`,
		`{"type":"tool","callID":"c2","tool":"read","state":{"status":"completed","input":{"filePath":"/x"},"output":"y","time":{"start":1,"end":2}}}`,
		`{"type":"tool","callID":"c3","tool":"write","state":{"status":"completed","input":{"filePath":"/x"},"output":"y","time":{"start":1,"end":2}}}`,
		`{"type":"tool","callID":"c4","tool":"webfetch","state":{"status":"completed","input":{"url":"https://x.example"},"output":"y","time":{"start":1,"end":2}}}`,
		`{"type":"tool","callID":"c5","tool":"websearch","state":{"status":"completed","input":{"query":"q"},"output":"y","time":{"start":1,"end":2}}}`,
		`{"type":"tool","callID":"c6","tool":"mcp__s__t","state":{"status":"completed","input":{},"output":"y","time":{"start":1,"end":2}}}`,
		`{"type":"tool","callID":"c7","tool":"x","state":{"status":"completed","input":{},"output":"y","time":{"start":1,"end":2}}}`,
		`{"type":"shell","callID":"c8","command":"ls","output":"o"}`,
		`{"type":"patch","hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","files":["/a"]}`,
		`{"id":"m1","role":"user","time":{"created":1}}`,
		`{"id":"m2","role":"assistant","time":{"created":1}}`,
	}
	for _, body := range bodies {
		res := extractOpenCodeWithReasoning(t, body, true)
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

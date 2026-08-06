package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// cursorFixture is a small Cursor agent-transcripts JSONL: a user prompt, an
// assistant turn whose array content mixes prose with a Shell tool call, and a
// separate tool record carrying the shell result with a structured exit code.
// The shapes exercise the tolerant decoder (string content, array content with
// lifted tool blocks, top-level toolResult) and the command-result correlation.
const cursorFixture = `{"type":"user","id":"cu1","conversationId":"cur-1","timestamp":"2026-06-03T10:00:00Z","cwd":"/home/dev/proj","content":"why is the auth middleware failing?"}
{"type":"assistant","id":"ca1","conversationId":"cur-1","timestamp":"2026-06-03T10:00:01Z","cwd":"/home/dev/proj","content":[{"type":"text","text":"Let me search for it."},{"type":"tool_call","name":"Shell","callId":"t1","input":{"command":"grep -r authMiddleware src/"}}]}
{"type":"tool","id":"ct1","conversationId":"cur-1","timestamp":"2026-06-03T10:00:02Z","cwd":"/home/dev/proj","toolResult":{"callId":"t1","exitCode":0}}`

func extractCursor(t *testing.T, body string, profile Profile) *Result {
	t.Helper()
	res, err := CursorExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/transcript.jsonl", CaseID: "case-cur", Profile: profile})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// The Cursor parser maps a prompt, an assistant message, a shell command.exec,
// and the correlated command.result — every event stamped with the cursor
// source identity and the cursor artifact type.
func TestExtractCursorMapsShapesWithCursorIdentity(t *testing.T) {
	res := extractCursor(t, cursorFixture, ProfileEvidence)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}

	type want struct {
		etype model.EventType
		actor string
		cmd   string
	}
	wants := []want{
		{model.EventPromptUser, model.ActorUser, ""},
		{model.EventMessageAssistant, model.ActorAssistant, ""},
		{model.EventCommandExec, model.ActorAssistant, "grep -r authMiddleware src/"},
		{model.EventCommandResult, model.ActorTool, ""},
	}
	acts := activityEvents(res.Events)
	if len(acts) != len(wants) {
		t.Fatalf("got %d activity events, want %d:\n%s", len(acts), len(wants), dumpEvents(res.Events))
	}
	for i, w := range wants {
		ev := acts[i]
		if ev.EventType != w.etype || ev.Actor != w.actor || ev.Command != w.cmd {
			t.Errorf("event %d = {%s actor=%s cmd=%q}, want {%s actor=%s cmd=%q}",
				i, ev.EventType, ev.Actor, ev.Command, w.etype, w.actor, w.cmd)
		}
	}

	// Every event — activity and the synthetic session.start/end — must carry the
	// Cursor agent identity, the Cursor artifact type, and the case id.
	for _, ev := range res.Events {
		if ev.SourceAgent != model.AgentCursor {
			t.Errorf("event %q source_agent = %q, want %q", ev.EventID, ev.SourceAgent, model.AgentCursor)
		}
		if ev.SourceType != model.SourceArtifact {
			t.Errorf("event %q source_type = %q, want %q", ev.EventID, ev.SourceType, model.SourceArtifact)
		}
		if ev.Evidence.ArtifactType != artifactCursorTranscript {
			t.Errorf("event %q artifact_type = %q, want %q", ev.EventID, ev.Evidence.ArtifactType, artifactCursorTranscript)
		}
		if ev.CaseID != "case-cur" {
			t.Errorf("event %q case_id = %q, want case-cur", ev.EventID, ev.CaseID)
		}
	}

	// The command.exec and its correlated command.result share the tool call id,
	// and the exit code rides on the result — proving the correlation runs.
	exec := acts[2]
	result := acts[3]
	if exec.ToolCallID != "t1" || result.ToolCallID != "t1" {
		t.Errorf("tool call correlation = exec %q / result %q, want both t1", exec.ToolCallID, result.ToolCallID)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Errorf("command.result exit_code = %v, want 0", result.ExitCode)
	}

	assertUniqueEventIDs(t, res.Events)
}

// Current Cursor transcripts wrap content blocks in message and end each turn
// with a bookkeeping record. Both the text and tool call must still surface,
// while turn_ended should be silent.
func TestExtractCursorCurrentMessageEnvelope(t *testing.T) {
	const body = `{"role":"user","message":{"content":[{"type":"text","text":"inspect the readme"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"I will open it."},{"type":"tool_use","name":"Read","input":{"path":"/workspace/README.md"}}]}}
{"type":"turn_ended","status":"success"}`
	res := extractCursor(t, body, ProfileEvidence)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}

	acts := activityEvents(res.Events)
	wantTypes := []model.EventType{
		model.EventPromptUser,
		model.EventMessageAssistant,
		model.EventFileRead,
	}
	wantPointers := []string{
		"/message/content/0",
		"/message/content/0",
		"/message/content/1",
	}
	if len(acts) != len(wantTypes) {
		t.Fatalf("got %d activity events, want %d:\n%s", len(acts), len(wantTypes), dumpEvents(res.Events))
	}
	for i := range wantTypes {
		if acts[i].EventType != wantTypes[i] || acts[i].Evidence.JSONPointer != wantPointers[i] {
			t.Errorf("event %d = {%s pointer=%q}, want {%s pointer=%q}",
				i, acts[i].EventType, acts[i].Evidence.JSONPointer, wantTypes[i], wantPointers[i])
		}
	}
	if acts[2].FilePath != "/workspace/README.md" || acts[2].ToolName != "Read" {
		t.Errorf("file event = {path=%q tool=%q}, want {/workspace/README.md Read}", acts[2].FilePath, acts[2].ToolName)
	}
	assertUniqueEventIDs(t, res.Events)
}

func TestExtractCursorToleratesNonObjectMessageEnvelope(t *testing.T) {
	res := extractCursor(t, `{"type":"system","message":"bookkeeping"}`, ProfileEvidence)
	if len(res.Diagnostics) != 0 || len(res.Events) != 0 {
		t.Fatalf("scalar message produced output: events=%s diagnostics=%+v", dumpEvents(res.Events), res.Diagnostics)
	}
}

// A tool result whose call id was never a shell command stays a generic
// tool.result (never a command.result), and a structurally-marked failure is
// tagged tool_error. This covers the non-command correlation branch.
func TestExtractCursorNonCommandResultAndError(t *testing.T) {
	const body = `{"type":"assistant","id":"a","conversationId":"c","content":[{"type":"tool_call","name":"Read","callId":"r1","input":{"file_path":"/etc/hosts"}}]}
{"type":"tool","id":"b","conversationId":"c","toolResult":{"callId":"r1","isError":true}}`
	res := extractCursor(t, body, ProfileEvidence)
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
	if acts[0].EventType != model.EventFileRead || acts[0].FilePath != "/etc/hosts" {
		t.Errorf("first = {%s file=%q}, want {file.read /etc/hosts}", acts[0].EventType, acts[0].FilePath)
	}
	if acts[1].EventType != model.EventToolResult {
		t.Errorf("result event = %s, want tool.result (a Read result is not a command.result)", acts[1].EventType)
	}
	if !hasTag(acts[1].Tags, model.TagToolError) {
		t.Errorf("errored tool.result tags = %v, want to include %q", acts[1].Tags, model.TagToolError)
	}
}

// A web_fetch tool call surfaces as a network.indicator carrying the url and the
// network tag, mirroring the Claude classifier.
func TestExtractCursorWebFetchNetworkIndicator(t *testing.T) {
	const body = `{"type":"assistant","id":"a","conversationId":"c","content":[{"type":"tool_call","name":"web_fetch","callId":"w1","input":{"url":"https://example.com/x"}}]}`
	res := extractCursor(t, body, ProfileEvidence)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(res.Events))
	}
	ev := acts[0]
	if ev.EventType != model.EventNetworkIndicator || ev.URL != "https://example.com/x" {
		t.Errorf("event = {%s url=%q}, want {network.indicator https://example.com/x}", ev.EventType, ev.URL)
	}
	if !hasTag(ev.Tags, model.TagNetwork) {
		t.Errorf("tags = %v, want to include %q", ev.Tags, model.TagNetwork)
	}
}

// Regression: a web_fetch arg that is not an absolute http(s) URL must
// NOT be promoted into Event.URL. file:///etc/passwd leaves URL empty (kept in
// ContentPreview), but the event is still a network.indicator tagged network.
func TestExtractCursorWebFetchRejectsNonHTTPScheme(t *testing.T) {
	const bad = "file:///etc/passwd"
	const body = `{"type":"assistant","id":"a","conversationId":"c","content":[{"type":"tool_call","name":"web_fetch","callId":"w1","input":{"url":"file:///etc/passwd"}}]}`
	acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1", len(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventNetworkIndicator {
		t.Errorf("event_type = %s, want network.indicator", ev.EventType)
	}
	if ev.URL != "" {
		t.Errorf("url = %q, want empty (non-http(s) must not be promoted)", ev.URL)
	}
	if ev.ContentPreview != bad {
		t.Errorf("ContentPreview = %q, want the raw value preserved", ev.ContentPreview)
	}
	if !hasTag(ev.Tags, model.TagNetwork) {
		t.Errorf("tags = %v, want to include %q", ev.Tags, model.TagNetwork)
	}
}

// A malformed line is skipped with a diagnostic, and the surrounding good
// records still parse — the tolerant-parse contract.
func TestExtractCursorToleratesMalformedLine(t *testing.T) {
	const body = `{"type":"user","id":"u","conversationId":"c","content":"hello"}
{not json}
{"type":"assistant","id":"a","conversationId":"c","content":"hi"}`
	res := extractCursor(t, body, ProfileEvidence)
	if len(res.Diagnostics) != 1 {
		t.Fatalf("got %d diagnostics, want 1: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
}

// A SINGLE record whose content[] carries both a shell tool_call AND its matching
// tool_result must correlate within that record: the result is a command.result
// carrying the structured exit code, emitted AFTER its command.exec. This is the
// same-record shape the parser claims to support; a regression here drops the
// exit code and inverts the order.
func TestExtractCursorSameRecordCommandCorrelation(t *testing.T) {
	const body = `{"type":"assistant","id":"a","conversationId":"c","content":[{"type":"text","text":"running it"},{"type":"tool_call","name":"Shell","callId":"s1","input":{"command":"go test ./..."}},{"type":"tool_result","callId":"s1","exitCode":2}]}`
	res := extractCursor(t, body, ProfileEvidence)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	acts := activityEvents(res.Events)
	if len(acts) != 3 {
		t.Fatalf("got %d activity events, want 3 (message, command.exec, command.result):\n%s", len(acts), dumpEvents(res.Events))
	}
	if acts[0].EventType != model.EventMessageAssistant {
		t.Errorf("event 0 = %s, want message.assistant", acts[0].EventType)
	}
	exec, result := acts[1], acts[2]
	if exec.EventType != model.EventCommandExec || exec.Command != "go test ./..." {
		t.Errorf("event 1 = {%s cmd=%q}, want {command.exec go test ./...}", exec.EventType, exec.Command)
	}
	if result.EventType != model.EventCommandResult {
		t.Fatalf("event 2 = %s, want command.result (same-record correlation must promote it)", result.EventType)
	}
	if exec.ToolCallID != "s1" || result.ToolCallID != "s1" {
		t.Errorf("correlation = exec %q / result %q, want both s1", exec.ToolCallID, result.ToolCallID)
	}
	if result.ExitCode == nil || *result.ExitCode != 2 {
		t.Errorf("command.result exit_code = %v, want 2 (structured exit code must survive same-record correlation)", result.ExitCode)
	}
	assertUniqueEventIDs(t, res.Events)
}

// Evidence.JSONPointer is an RFC 6901 locator back into the SOURCE record, so each
// emitted event must point at the field it was actually read from — never a
// synthetic normalized bucket. This pins the pointer for every source shape:
// array-indexed content blocks, a plain-string content, a flat text body, and the
// top-level toolCall / toolResult / output encodings.
func TestExtractCursorJSONPointersAreSourceFaithful(t *testing.T) {
	t.Run("content_array_blocks", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","conversationId":"c","content":[{"type":"text","text":"hi"},{"type":"tool_call","name":"Shell","callId":"s1","input":{"command":"ls"}},{"type":"tool_result","callId":"s1","exitCode":0}]}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		wantPtr := []string{"/content/0", "/content/1", "/content/2"}
		if len(acts) != len(wantPtr) {
			t.Fatalf("got %d events, want %d:\n%s", len(acts), len(wantPtr), dumpEvents(acts))
		}
		for i, want := range wantPtr {
			if acts[i].Evidence.JSONPointer != want {
				t.Errorf("event %d (%s) pointer = %q, want %q", i, acts[i].EventType, acts[i].Evidence.JSONPointer, want)
			}
		}
	})

	t.Run("plain_string_content", func(t *testing.T) {
		const body = `{"type":"user","id":"u","conversationId":"c","content":"hello"}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/content" {
			t.Fatalf("plain-string content pointer = %q, want /content:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("flat_text_body", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","conversationId":"c","text":"just text"}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/text" {
			t.Fatalf("flat text pointer = %q, want /text:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_toolCall", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","conversationId":"c","toolCall":{"name":"Read","callId":"r1","input":{"file_path":"/x"}}}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/toolCall" {
			t.Fatalf("top-level toolCall pointer = %q, want /toolCall:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_toolCalls_list", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","conversationId":"c","toolCalls":[{"name":"Read","callId":"r1","input":{"file_path":"/x"}}]}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/toolCalls/0" {
			t.Fatalf("top-level toolCalls[0] pointer = %q, want /toolCalls/0:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_toolResult", func(t *testing.T) {
		const body = `{"type":"tool","id":"t","conversationId":"c","toolResult":{"callId":"r1","isError":true}}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/toolResult" {
			t.Fatalf("top-level toolResult pointer = %q, want /toolResult:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_output", func(t *testing.T) {
		const body = `{"type":"tool","id":"t","conversationId":"c","output":{"callId":"r1","status":"ok"}}`
		acts := activityEvents(extractCursor(t, body, ProfileEvidence).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/output" {
			t.Fatalf("top-level output pointer = %q, want /output:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})
}

func TestExtractCursorAgent(t *testing.T) {
	if got := (CursorExtractor{}).Agent(); got != model.AgentCursor {
		t.Errorf("Agent() = %q, want %q", got, model.AgentCursor)
	}
}

// ptrOf renders the JSON pointers of evs for a failure message.
func ptrOf(evs []model.Event) string {
	ptrs := make([]string, len(evs))
	for i, e := range evs {
		ptrs[i] = e.Evidence.JSONPointer
	}
	return strings.Join(ptrs, ",")
}

// hasTag reports whether tags contains want.
func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

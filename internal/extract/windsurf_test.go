package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// windsurfFixture is a small Windsurf (Cascade) transcripts JSONL: a user prompt,
// an assistant turn whose array content mixes prose with a run_command tool call
// and its matching tool_result in the same record, proving same-record
// correlation and structured exit-code survival. The shapes exercise the
// tolerant decoder (string content, array content with lifted tool blocks) and
// the command-result correlation.
const windsurfFixture = `{"type":"user","id":"wu1","trajectoryId":"traj-1","timestamp":"2026-06-03T10:00:00Z","cwd":"/home/dev/proj","content":"why is the auth middleware failing?"}
{"type":"assistant","id":"wa1","trajectoryId":"traj-1","timestamp":"2026-06-03T10:00:01Z","cwd":"/home/dev/proj","content":[{"type":"text","text":"Let me run the tests."},{"type":"tool_call","name":"run_command","callId":"t1","input":{"command":"go test ./..."}},{"type":"tool_result","callId":"t1","exitCode":1,"isError":true}]}`

func extractWindsurf(t *testing.T, body string) *Result {
	t.Helper()
	res, err := WindsurfExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/windsurf.jsonl", CaseID: "case-ws"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// The Windsurf parser maps a prompt, an assistant message, a shell command.exec,
// and the same-record correlated command.result carrying the structured exit
// code — every event stamped with the windsurf source identity and the windsurf
// artifact type. This is the headline correlation+exit-code proof.
func TestExtractWindsurfMapsShapesWithWindsurfIdentity(t *testing.T) {
	res := extractWindsurf(t, windsurfFixture)
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
		{model.EventCommandExec, model.ActorAssistant, "go test ./..."},
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
	// Windsurf agent identity, the Windsurf artifact type, and the case id.
	for _, ev := range res.Events {
		if ev.SourceAgent != model.AgentWindsurf {
			t.Errorf("event %q source_agent = %q, want %q", ev.EventID, ev.SourceAgent, model.AgentWindsurf)
		}
		if ev.SourceType != model.SourceArtifact {
			t.Errorf("event %q source_type = %q, want %q", ev.EventID, ev.SourceType, model.SourceArtifact)
		}
		if ev.Evidence.ArtifactType != artifactWindsurfTranscript {
			t.Errorf("event %q artifact_type = %q, want %q", ev.EventID, ev.Evidence.ArtifactType, artifactWindsurfTranscript)
		}
		if ev.CaseID != "case-ws" {
			t.Errorf("event %q case_id = %q, want case-ws", ev.EventID, ev.CaseID)
		}
	}

	// The command.exec and its same-record correlated command.result share the
	// tool call id, the result is ordered AFTER the exec, and the structured exit
	// code rides on the result — proving same-record correlation runs.
	exec := acts[2]
	result := acts[3]
	if exec.ToolCallID != "t1" || result.ToolCallID != "t1" {
		t.Errorf("tool call correlation = exec %q / result %q, want both t1", exec.ToolCallID, result.ToolCallID)
	}
	if result.ExitCode == nil || *result.ExitCode != 1 {
		t.Errorf("command.result exit_code = %v, want 1 (structured exit code must survive same-record correlation)", result.ExitCode)
	}
	if !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("errored command.result tags = %v, want to include %q", result.Tags, model.TagToolError)
	}

	// Source-faithful RFC-6901 pointers into the array-content blocks.
	wantPtr := []string{"/content", "/content/0", "/content/1", "/content/2"}
	for i, want := range wantPtr {
		if acts[i].Evidence.JSONPointer != want {
			t.Errorf("event %d (%s) pointer = %q, want %q", i, acts[i].EventType, acts[i].Evidence.JSONPointer, want)
		}
	}

	assertUniqueEventIDs(t, res.Events)
}

// A tool result whose call id was never a shell command stays a generic
// tool.result (never a command.result), and a structurally-marked failure is
// tagged tool_error. This covers the non-command correlation branch.
func TestExtractWindsurfNonCommandResultAndError(t *testing.T) {
	const body = `{"type":"assistant","id":"a","trajectoryId":"c","content":[{"type":"tool_call","name":"read_code","callId":"r1","input":{"file_path":"/etc/hosts"}}]}
{"type":"tool","id":"b","trajectoryId":"c","toolResult":{"callId":"r1","isError":true}}`
	res := extractWindsurf(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
	if acts[0].EventType != model.EventFileRead || acts[0].FilePath != "/etc/hosts" {
		t.Errorf("first = {%s file=%q}, want {file.read /etc/hosts}", acts[0].EventType, acts[0].FilePath)
	}
	if acts[1].EventType != model.EventToolResult {
		t.Errorf("result event = %s, want tool.result (a read_code result is not a command.result)", acts[1].EventType)
	}
	if !hasTag(acts[1].Tags, model.TagToolError) {
		t.Errorf("errored tool.result tags = %v, want to include %q", acts[1].Tags, model.TagToolError)
	}
}

// A read_url_content tool call surfaces as a network.indicator carrying the url
// and the network tag, mirroring the Cursor/Claude classifiers.
func TestExtractWindsurfReadURLNetworkIndicator(t *testing.T) {
	const body = `{"type":"assistant","id":"a","trajectoryId":"c","content":[{"type":"tool_call","name":"read_url_content","callId":"w1","input":{"url":"https://example.com/x"}}]}`
	res := extractWindsurf(t, body)
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

// Regression: a read_url_content arg that is not an absolute http(s)
// URL must NOT be promoted into Event.URL. file:///etc/passwd leaves URL empty
// (kept in ContentPreview); the event stays a network.indicator tagged network.
func TestExtractWindsurfReadURLRejectsNonHTTPScheme(t *testing.T) {
	const bad = "file:///etc/passwd"
	const body = `{"type":"assistant","id":"a","trajectoryId":"c","content":[{"type":"tool_call","name":"read_url_content","callId":"w1","input":{"url":"file:///etc/passwd"}}]}`
	acts := activityEvents(extractWindsurf(t, body).Events)
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
func TestExtractWindsurfToleratesMalformedLine(t *testing.T) {
	const body = `{"type":"user","id":"u","trajectoryId":"c","content":"hello"}
{not json}
{"type":"assistant","id":"a","trajectoryId":"c","content":"hi"}`
	res := extractWindsurf(t, body)
	if len(res.Diagnostics) != 1 {
		t.Fatalf("got %d diagnostics, want 1: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
}

// A shell command.exec and its result framed in SEPARATE records (the result
// arriving in a later, standalone tool record) must still correlate to a
// command.result carrying the structured exit code. This covers the
// cross-record correlation branch (the pre-indexed shell-call id outlives the
// record that issued it).
func TestExtractWindsurfCrossRecordCommandCorrelation(t *testing.T) {
	const body = `{"type":"assistant","id":"a","trajectoryId":"c","content":[{"type":"tool_call","name":"run_command","callId":"s1","input":{"command":"ls -la"}}]}
{"type":"tool","id":"t","trajectoryId":"c","toolResult":{"callId":"s1","exitCode":0}}`
	res := extractWindsurf(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
	exec, result := acts[0], acts[1]
	if exec.EventType != model.EventCommandExec || exec.Command != "ls -la" {
		t.Errorf("event 0 = {%s cmd=%q}, want {command.exec ls -la}", exec.EventType, exec.Command)
	}
	if result.EventType != model.EventCommandResult {
		t.Fatalf("event 1 = %s, want command.result (cross-record correlation must promote it)", result.EventType)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Errorf("command.result exit_code = %v, want 0", result.ExitCode)
	}
}

// A record carrying BOTH a top-level call and its correlated top-level result
// must still emit command.exec BEFORE command.result. The pre-indexer notes the
// shell call id from any carrier (including top-level), so the result correlates;
// the regression here is purely ordering — the top-level result must trail its
// same-record command.exec, not lead the whole record. Both top-level encodings
// are pinned: toolCall+toolResult and toolCalls[0]+output.
func TestExtractWindsurfSameRecordTopLevelCorrelationOrdering(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			"toolCall+toolResult",
			`{"type":"assistant","id":"a","trajectoryId":"c","toolCall":{"name":"run_command","callId":"x1","input":{"command":"make build"}},"toolResult":{"callId":"x1","exitCode":1,"isError":true}}`,
		},
		{
			"toolCalls[0]+output",
			`{"type":"assistant","id":"a","trajectoryId":"c","toolCalls":[{"name":"run_command","callId":"x1","input":{"command":"make build"}}],"output":{"callId":"x1","exitCode":1,"isError":true}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := extractWindsurf(t, tc.body)
			acts := activityEvents(res.Events)
			if len(acts) != 2 {
				t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
			}
			exec, result := acts[0], acts[1]
			if exec.EventType != model.EventCommandExec || exec.Command != "make build" {
				t.Errorf("event 0 = {%s cmd=%q}, want {command.exec make build} — exec must lead", exec.EventType, exec.Command)
			}
			if result.EventType != model.EventCommandResult {
				t.Fatalf("event 1 = %s, want command.result emitted AFTER its exec", result.EventType)
			}
			if exec.ToolCallID != "x1" || result.ToolCallID != "x1" {
				t.Errorf("correlation = exec %q / result %q, want both x1", exec.ToolCallID, result.ToolCallID)
			}
			if result.ExitCode == nil || *result.ExitCode != 1 {
				t.Errorf("command.result exit_code = %v, want 1", result.ExitCode)
			}
			if !hasTag(result.Tags, model.TagToolError) {
				t.Errorf("errored command.result tags = %v, want to include %q", result.Tags, model.TagToolError)
			}
		})
	}
}

// Evidence.JSONPointer is an RFC 6901 locator back into the SOURCE record, so each
// emitted event must point at the field it was actually read from — never a
// synthetic normalized bucket. This pins the pointer for every source shape:
// a plain-string content, a flat text body, and the top-level toolCall /
// toolResult / output encodings (the array-block case is covered by the headline
// test above).
func TestExtractWindsurfJSONPointersAreSourceFaithful(t *testing.T) {
	t.Run("plain_string_content", func(t *testing.T) {
		const body = `{"type":"user","id":"u","trajectoryId":"c","content":"hello"}`
		acts := activityEvents(extractWindsurf(t, body).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/content" {
			t.Fatalf("plain-string content pointer = %q, want /content:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("flat_text_body", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","trajectoryId":"c","text":"just text"}`
		acts := activityEvents(extractWindsurf(t, body).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/text" {
			t.Fatalf("flat text pointer = %q, want /text:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_toolCall", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","trajectoryId":"c","toolCall":{"name":"read_code","callId":"r1","input":{"file_path":"/x"}}}`
		acts := activityEvents(extractWindsurf(t, body).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/toolCall" {
			t.Fatalf("top-level toolCall pointer = %q, want /toolCall:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_toolCalls_list", func(t *testing.T) {
		const body = `{"type":"assistant","id":"a","trajectoryId":"c","toolCalls":[{"name":"read_code","callId":"r1","input":{"file_path":"/x"}}]}`
		acts := activityEvents(extractWindsurf(t, body).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/toolCalls/0" {
			t.Fatalf("top-level toolCalls[0] pointer = %q, want /toolCalls/0:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_toolResult", func(t *testing.T) {
		const body = `{"type":"tool","id":"t","trajectoryId":"c","toolResult":{"callId":"r1","isError":true}}`
		acts := activityEvents(extractWindsurf(t, body).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/toolResult" {
			t.Fatalf("top-level toolResult pointer = %q, want /toolResult:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})

	t.Run("top_level_output", func(t *testing.T) {
		const body = `{"type":"tool","id":"t","trajectoryId":"c","output":{"callId":"r1","status":"ok"}}`
		acts := activityEvents(extractWindsurf(t, body).Events)
		if len(acts) != 1 || acts[0].Evidence.JSONPointer != "/output" {
			t.Fatalf("top-level output pointer = %q, want /output:\n%s", ptrOf(acts), dumpEvents(acts))
		}
	})
}

func TestExtractWindsurfAgent(t *testing.T) {
	if got := (WindsurfExtractor{}).Agent(); got != model.AgentWindsurf {
		t.Errorf("Agent() = %q, want %q", got, model.AgentWindsurf)
	}
}

package extract

import (
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// Field names and shapes below are sanitized from real ~/.local/share/muse
// session.jsonl files captured against Muse Code 1.3.0 (build 3c572bc734),
// cross-checked against github.com/specstoryai/getspecstory's independent
// reverse-engineering (Apache-2.0), which verified the same envelope and
// payload catalog against Muse Code 0.1.0. IDs, paths, and prompt text are
// synthetic; the record shapes are not.
const museSessionFixture = `{"schema_version":1,"id":"r1","stream":{"kind":"session","id":"sess-1"},"sequence":1,"recorded_at":1789752886281112,"record_type":"event","payload_type":"runtime.session.metadata","payload_schema_version":1,"payload":{"kind":"metadata","record":{"workspace_root":"/work/repo","provider_id":"meta","model_id":"muse-spark-1.3","build":{"semver":"1.3.0"}}}}
{"schema_version":1,"id":"r2","stream":{"kind":"session","id":"sess-1"},"sequence":2,"recorded_at":1789752886300000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"started","prompt":"read the readme then run the build"}}}
{"schema_version":1,"id":"r3","stream":{"kind":"session","id":"sess-1"},"sequence":3,"recorded_at":1789752886310000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"reasoning_committed","message_id":"m0","text":"thinking about the plan"}}}
{"schema_version":1,"id":"r4","stream":{"kind":"session","id":"sess-1"},"sequence":4,"recorded_at":1789752886320000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"assistant_message_committed","message_id":"m1","text":"On it."}}}
{"schema_version":1,"id":"r5","stream":{"kind":"session","id":"sess-1"},"sequence":5,"recorded_at":1789752886330000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"assistant_tool_calls_committed","message_id":"m1","tool_calls":[{"id":"fc1","call_id":"call-read","name":"read_file","args":"{\"path\":\"README.md\"}"},{"id":"fc2","call_id":"call-bash","name":"bash","args":"{\"command\":\"make build\"}"},{"id":"fc3","call_id":"call-write","name":"write_file","args":"{\"path\":\"out.txt\",\"content\":\"x\"}"},{"id":"fc4","call_id":"call-spawn","name":"subagent_spawn","args":"{\"objective\":\"help\"}"}]}}}
{"schema_version":1,"id":"r5b","stream":{"kind":"task","id":"task-1"},"sequence":6,"recorded_at":1789752886335000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"task-1","event":{"kind":"started","prompt":"Role: helper Objective: fake"}}}
{"schema_version":1,"id":"r6","stream":{"kind":"session","id":"sess-1"},"sequence":7,"recorded_at":1789752886340000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"tool_result_batch_committed","batch_id":"m1","results":[{"tool_call_index":0,"tool_call_id":"call-read","text":"1|hello"},{"tool_call_index":1,"tool_call_id":"call-bash","text":"{\"exit_code\":0,\"terminal_status\":\"completed\",\"output\":\"ok\"}"},{"tool_call_index":2,"tool_call_id":"call-write","text":"wrote 1 bytes to out.txt"},{"tool_call_index":3,"tool_call_id":"call-spawn","text":"{\"status\":\"accepted\"}"}]}}}
{"schema_version":1,"id":"r7","stream":{"kind":"session","id":"sess-1"},"sequence":8,"recorded_at":1789752886350000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-2","event":{"kind":"assistant_tool_calls_committed","message_id":"m2","tool_calls":[{"id":"fc5","call_id":"call-fail","name":"bash","args":"{\"command\":\"false\"}"}]}}}
{"schema_version":1,"id":"r8","stream":{"kind":"session","id":"sess-1"},"sequence":9,"recorded_at":1789752886360000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-2","event":{"kind":"tool_result_batch_committed","batch_id":"m2","results":[{"tool_call_index":0,"tool_call_id":"call-fail","text":"{\"exit_code\":1,\"terminal_status\":\"failed\"}"}]}}}
{"retained_frame":"session_permission_transaction","frame_schema_version":1,"transaction_id":"tx-1","children":[{"child_index":0,"record_json":"{\"schema_version\":1,\"id\":\"r9\",\"stream\":{\"kind\":\"session\",\"id\":\"sess-1\"},\"sequence\":10,\"recorded_at\":1789752886370000,\"record_type\":\"event\",\"payload_type\":\"runtime.session.permission_format_declared\",\"payload_schema_version\":1,\"payload\":{}}"}]}
{"schema_version":1,"id":"r10","stream":{"kind":"session","id":"sess-1"},"sequence":11,"recorded_at":1789752886380000,"record_type":"event","payload_type":"session.end","payload_schema_version":1,"payload":{"kind":"session_end","record":{"exit_reason":"clean"}}}
`

func museExtractFixture(t *testing.T, path, body string, includeReasoning bool) *Result {
	t.Helper()
	res, err := MuseCodeExtractor{}.Extract(strings.NewReader(body), Source{Path: path, CaseID: "case-1", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

func TestMuseCodeExtractMapsAllShapes(t *testing.T) {
	path := "/home/u/.local/share/muse/sessions/2026/09/18/sess-1/session.jsonl"
	res := museExtractFixture(t, path, museSessionFixture, false)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}

	wantTypes := []model.EventType{
		model.EventSessionStart,
		model.EventPromptUser,
		// reasoning_committed skipped: IncludeReasoning is false
		model.EventMessageAssistant,
		model.EventFileRead,    // read_file call
		model.EventCommandExec, // bash call
		model.EventFileWrite,   // write_file call
		model.EventToolCall,    // subagent_spawn call (unmapped, generic)
		// the interleaved task-stream "started" is filtered by stream id
		model.EventToolResult,    // read_file result
		model.EventCommandResult, // bash result (clean)
		model.EventToolResult,    // write_file result
		model.EventToolResult,    // subagent_spawn result
		model.EventCommandExec,   // second run: failing bash call
		model.EventCommandResult, // failing bash result
		// the retained-frame-wrapped permission_format_declared record maps to nothing
		model.EventSessionEnd,
	}
	if len(res.Events) != len(wantTypes) {
		t.Fatalf("events = %d, want %d: %+v", len(res.Events), len(wantTypes), res.Events)
	}
	seenIDs := map[string]bool{}
	for i, ev := range res.Events {
		if ev.EventType != wantTypes[i] {
			t.Errorf("event %d type = %q, want %q", i, ev.EventType, wantTypes[i])
		}
		if ev.SourceAgent != model.AgentMuseCode || ev.SourceType != model.SourceArtifact {
			t.Errorf("event %d source = %q/%q", i, ev.SourceAgent, ev.SourceType)
		}
		if ev.SessionID != "sess-1" || ev.ProjectPath != "/work/repo" || ev.SubAgent != "" {
			t.Errorf("event %d context = session %q project %q subagent %q", i, ev.SessionID, ev.ProjectPath, ev.SubAgent)
		}
		if ev.Model != "muse-spark-1.3" || ev.ModelProvider != "meta" {
			t.Errorf("event %d model context = %q/%q", i, ev.Model, ev.ModelProvider)
		}
		if ev.CaseID != "case-1" || ev.Evidence.ArtifactType != artifactMuseSessionJSONL || ev.Evidence.SHA256 == "" {
			t.Errorf("event %d provenance = case %q evidence %+v", i, ev.CaseID, ev.Evidence)
		}
		if seenIDs[ev.EventID] {
			t.Errorf("duplicate event id %q", ev.EventID)
		}
		seenIDs[ev.EventID] = true
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d invalid: %v\n%+v", i, err, ev)
		}
	}

	if got := res.Events[3]; got.ToolName != "read_file" || got.FilePath != "README.md" {
		t.Errorf("read_file call = %+v", got)
	}
	if got := res.Events[4]; got.ToolName != "bash" || got.Command != "make build" {
		t.Errorf("bash call = %+v", got)
	}
	if got := res.Events[5]; got.ToolName != "write_file" || got.FilePath != "out.txt" {
		t.Errorf("write_file call = %+v", got)
	}
	if got := res.Events[6]; got.ToolName != "subagent_spawn" || got.ToolCallID != "call-spawn" {
		t.Errorf("subagent_spawn call = %+v", got)
	}
	if got := res.Events[8]; got.ToolName != "bash" || got.ExitCode == nil || *got.ExitCode != 0 || len(got.Tags) != 0 {
		t.Errorf("clean bash result = %+v", got)
	}
	if got := res.Events[11]; got.ToolName != "bash" || got.Command != "false" {
		t.Errorf("failing bash call = %+v", got)
	}
	if got := res.Events[12]; got.ExitCode == nil || *got.ExitCode != 1 || len(got.Tags) != 1 || got.Tags[0] != model.TagToolError {
		t.Errorf("failing bash result = %+v", got)
	}
}

func TestMuseCodeExtractIncludesReasoningWhenRequested(t *testing.T) {
	path := "/home/u/.local/share/muse/sessions/2026/09/18/sess-1/session.jsonl"
	res := museExtractFixture(t, path, museSessionFixture, true)
	var reasoning []model.Event
	for _, ev := range res.Events {
		if ev.EventType == model.EventMessageReasoning {
			reasoning = append(reasoning, ev)
		}
	}
	if len(reasoning) != 1 || reasoning[0].ContentPreview != "thinking about the plan" {
		t.Fatalf("reasoning = %+v", reasoning)
	}
}

func TestMuseCodeExtractSkipsEmptyReasoningText(t *testing.T) {
	// Reasoning is usually empty because it is encrypted for the Meta
	// provider; an empty text field must never be treated as content.
	fixture := `{"schema_version":1,"id":"r1","stream":{"kind":"session","id":"sess-1"},"sequence":1,"recorded_at":1,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"reasoning_committed","message_id":"m0","text":""}}}
`
	res := museExtractFixture(t, "/x/sessions/2026/01/01/sess-1/session.jsonl", fixture, true)
	if len(res.Events) != 0 {
		t.Fatalf("events = %+v, want none for empty encrypted reasoning", res.Events)
	}
}

func TestMuseCodeExtractCarriesSubAgentFromNestedPath(t *testing.T) {
	fixture := `{"schema_version":1,"id":"r1","stream":{"kind":"session","id":"sub-1"},"sequence":1,"recorded_at":1,"record_type":"event","payload_type":"runtime.session.metadata","payload_schema_version":1,"payload":{"kind":"metadata","record":{"workspace_root":"/work/repo"}}}
{"schema_version":1,"id":"r2","stream":{"kind":"session","id":"sub-1"},"sequence":2,"recorded_at":2,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"started","prompt":"subtask"}}}
`
	path := "/home/u/.local/share/muse/sessions/2026/09/18/sess-1/subagent/sub-1/session.jsonl"
	res := museExtractFixture(t, path, fixture, false)
	if len(res.Events) != 2 {
		t.Fatalf("events = %+v", res.Events)
	}
	for _, ev := range res.Events {
		// SessionID stays anchored to the root session (matching Kimi Code's
		// own convention); SubAgent names which nested transcript authored it.
		if ev.SessionID != "sess-1" || ev.SubAgent != "sub-1" {
			t.Errorf("event context = session %q subagent %q, want sess-1/sub-1", ev.SessionID, ev.SubAgent)
		}
	}
}

func TestMuseCodeExtractToleratesMalformedAndUnknownRecords(t *testing.T) {
	fixture := "{bad\n" +
		`{"record_type":"event"}` + "\n" +
		`{"schema_version":1,"stream":{"kind":"session","id":"sess-1"},"payload_type":"runtime.session.metadata","payload":{"secret":"do not leak"}}` + "\n"
	res := museExtractFixture(t, "/x/sessions/2026/01/01/sess-1/session.jsonl", fixture, false)
	// The third line has a payload_type but a payload shape that still
	// unmarshals (unknown fields are ignored by encoding/json), so it succeeds
	// as an empty-workspace-root metadata record rather than diagnosing.
	if len(res.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "secret") {
			t.Errorf("diagnostic leaks content: %+v", d)
		}
	}
}

func TestMuseCodeExtractSkipsOmittedRecordMarkerWithoutDiagnostic(t *testing.T) {
	// Sanitized from a real tombstone found on disk for an ephemeral task-delta
	// status update the runtime chose not to retain durably. Not malformed —
	// must not produce a diagnostic — and carries nothing to map.
	fixture := `{"retained_marker":"omitted_live_only","schema_version":1,"stream":{"kind":"session","id":"sess-1"},"position":{"id":"p1","sequence":75},"omitted_record":{"record_type":"status","durability":"ephemeral","payload_type":"runtime.session","payload_schema_version":1,"payload_kind":"task","omission_class":"task_tool_delta_v1"}}
`
	res := museExtractFixture(t, "/x/sessions/2026/01/01/sess-1/session.jsonl", fixture, false)
	if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
		t.Fatalf("events = %+v, diagnostics = %+v; want neither", res.Events, res.Diagnostics)
	}
}

func TestMuseCodeExtractRejectsOversizeArtifact(t *testing.T) {
	_, err := (MuseCodeExtractor{maxBytes: 8}).Extract(strings.NewReader(strings.Repeat("x", 9)), Source{Path: "/x/session.jsonl"})
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("error = %v", err)
	}
}

func TestMuseFileContext(t *testing.T) {
	cases := []struct {
		path     string
		wantRoot string
		wantSub  string
		wantSID  string
	}{
		{"/home/u/.local/share/muse/sessions/2026/09/18/sess-1/session.jsonl", "sess-1", "", "sess-1"},
		{"/home/u/.local/share/muse/sessions/2026/09/18/sess-1/subagent/sub-1/session.jsonl", "sess-1", "sub-1", "sub-1"},
		{"/home/u/.local/share/muse/sessions/2026/09/18/sess-1/subagent/sub-1/subagent/sub-2/session.jsonl", "sess-1", "sub-2", "sub-2"},
		{"/unrelated/path.jsonl", "", "", ""},
	}
	for _, tc := range cases {
		root, sub, stream := museFileContext(tc.path)
		if root != tc.wantRoot || sub != tc.wantSub || stream != tc.wantSID {
			t.Errorf("museFileContext(%q) = %q/%q/%q, want %q/%q/%q", tc.path, root, sub, stream, tc.wantRoot, tc.wantSub, tc.wantSID)
		}
	}
}

// TestMuseCodeExtractSplitsMCPToolName proves at-rest MCP calls and results
// carry mcp_server/mcp_tool. The name shape (mcp__<server>__<tool>, hyphens in
// the server name become underscores) was captured from a live run against a
// real streamable-HTTP MCP server; native tools must stay unsplit.
func TestMuseCodeExtractSplitsMCPToolName(t *testing.T) {
	const body = `{"schema_version":1,"id":"m1","stream":{"kind":"session","id":"sess-mcp"},"sequence":1,"recorded_at":1789752886300000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"assistant_tool_calls_committed","message_id":"m1","tool_calls":[{"id":"fc1","call_id":"call-mcp","name":"mcp__complex_demo__analyze_data","args":"{\"dataSource\":\"numbat-mcp-test\"}"},{"id":"fc2","call_id":"call-bash","name":"bash","args":"{\"command\":\"ls\"}"}]}}}
{"schema_version":1,"id":"m2","stream":{"kind":"session","id":"sess-mcp"},"sequence":2,"recorded_at":1789752886310000,"record_type":"event","payload_type":"runtime.session","payload_schema_version":1,"payload":{"kind":"run","run_id":"run-1","event":{"kind":"tool_result_batch_committed","batch_id":"m1","results":[{"tool_call_index":0,"tool_call_id":"call-mcp","text":"{\"summary\":{\"totalRecords\":3}}"},{"tool_call_index":1,"tool_call_id":"call-bash","text":"{\"exit_code\":0,\"terminal_status\":\"completed\"}"}]}}}
`
	res := museExtractFixture(t, "/home/u/.local/share/muse/sessions/2026/09/30/sess-mcp/session.jsonl", body, false)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	if len(res.Events) != 4 {
		t.Fatalf("events = %d, want 4: %+v", len(res.Events), res.Events)
	}
	call, bashCall, result, bashResult := res.Events[0], res.Events[1], res.Events[2], res.Events[3]
	if call.EventType != model.EventToolCall || call.MCPServer != "complex_demo" || call.MCPTool != "analyze_data" {
		t.Errorf("mcp call = type %q server %q tool %q", call.EventType, call.MCPServer, call.MCPTool)
	}
	if result.EventType != model.EventToolResult || result.MCPServer != "complex_demo" || result.MCPTool != "analyze_data" {
		t.Errorf("mcp result = type %q server %q tool %q", result.EventType, result.MCPServer, result.MCPTool)
	}
	for _, ev := range []model.Event{bashCall, bashResult} {
		if ev.MCPServer != "" || ev.MCPTool != "" {
			t.Errorf("native bash event leaked mcp fields: %+v", ev)
		}
	}
	for i, ev := range res.Events {
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d invalid: %v", i, err)
		}
	}
}

// TestMuseCodeExtractStampsRecordedAt proves events carry the record's own
// recorded_at (microseconds since the epoch) as UTC RFC3339, including for a
// record inside a retained-frame wrapper, and that a record with no
// recorded_at stays empty rather than inheriting the previous record's time.
func TestMuseCodeExtractStampsRecordedAt(t *testing.T) {
	path := "/home/u/.local/share/muse/sessions/2026/09/18/sess-1/session.jsonl"
	res := museExtractFixture(t, path, museSessionFixture, false)
	if got := res.Events[0].Timestamp; got != "2026-09-18T17:34:46.281112Z" {
		t.Errorf("session.start timestamp = %q", got)
	}
	if got := res.Events[1].Timestamp; got != "2026-09-18T17:34:46.3Z" {
		t.Errorf("prompt.user timestamp = %q", got)
	}
	if got := res.Events[len(res.Events)-1].Timestamp; got != "2026-09-18T17:34:46.38Z" {
		t.Errorf("session.end timestamp = %q", got)
	}
	var prev time.Time
	for i, ev := range res.Events {
		ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if err != nil {
			t.Fatalf("event %d timestamp %q: %v", i, ev.Timestamp, err)
		}
		if ts.Before(prev) {
			t.Errorf("event %d timestamp %s goes backwards from %s", i, ts, prev)
		}
		prev = ts
	}

	const body = `{"schema_version":1,"id":"a","stream":{"kind":"session","id":"sess-t"},"sequence":1,"recorded_at":1789752886281112,"record_type":"event","payload_type":"runtime.session.metadata","payload_schema_version":1,"payload":{"kind":"metadata","record":{"workspace_root":"/w"}}}
{"retained_frame":"session_permission_transaction","frame_schema_version":1,"transaction_id":"tx","children":[{"child_index":0,"record_json":"{\"schema_version\":1,\"id\":\"b\",\"stream\":{\"kind\":\"session\",\"id\":\"sess-t\"},\"sequence\":2,\"recorded_at\":1789752886370000,\"record_type\":\"event\",\"payload_type\":\"session.end\",\"payload_schema_version\":1,\"payload\":{\"kind\":\"session_end\",\"record\":{}}}"}]}
{"schema_version":1,"id":"c","stream":{"kind":"session","id":"sess-t"},"sequence":3,"record_type":"event","payload_type":"session.end","payload_schema_version":1,"payload":{"kind":"session_end","record":{}}}
`
	res = museExtractFixture(t, "/home/u/.local/share/muse/sessions/2026/09/18/sess-t/session.jsonl", body, false)
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3: %+v", len(res.Events), res.Events)
	}
	if got := res.Events[1].Timestamp; got != "2026-09-18T17:34:46.37Z" {
		t.Errorf("retained-frame child timestamp = %q", got)
	}
	if got := res.Events[2].Timestamp; got != "" {
		t.Errorf("record without recorded_at inherited timestamp %q", got)
	}
}

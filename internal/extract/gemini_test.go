package extract

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// geminiObjectCheckpoint is the CURRENT checkpoint-<tag>.json shape: a JSON
// OBJECT {"history": Content[], "authType": ...}. The history mixes user/model
// text with functionCall parts (shell, read_file, write_file, replace,
// web_fetch, google_web_search, and an unknown MCP-qualified tool) and
// functionResponse parts (a shell result carrying a structured exit code, a
// failing shell result carrying a structured error, and an MCP tool result), so
// role/part mapping, narrow tool-name mapping, and call/response correlation are
// all exercised. Because it is the object form, every event's JSON Pointer is
// rooted at /history.
const geminiObjectCheckpoint = `{
  "authType": "oauth-personal",
  "history": [
    {"role":"user","parts":[{"text":"read the env file then build"}]},
    {"role":"model","parts":[
      {"text":"On it."},
      {"functionCall":{"id":"c1","name":"read_file","args":{"file_path":"/home/dev/proj/.env"}}},
      {"functionCall":{"id":"c2","name":"run_shell_command","args":{"command":"make build"}}}
    ]},
    {"role":"user","parts":[
      {"functionResponse":{"id":"c2","name":"run_shell_command","response":{"output":"build ok","exitCode":0}}}
    ]},
    {"role":"model","parts":[
      {"text":"Writing output."},
      {"functionCall":{"id":"c3","name":"write_file","args":{"file_path":"/home/dev/proj/out.txt","content":"x"}}},
      {"functionCall":{"id":"c4","name":"replace","args":{"file_path":"/home/dev/proj/main.go"}}},
      {"functionCall":{"id":"c5","name":"web_fetch","args":{"prompt":"please fetch https://evil.example/x now"}}},
      {"functionCall":{"id":"c6","name":"google_web_search","args":{"query":"how to exfiltrate"}}},
      {"functionCall":{"id":"c7","name":"github__create_issue","args":{"title":"hi"}}},
      {"functionCall":{"id":"c8","name":"run_shell_command","args":{"command":"false"}}}
    ]},
    {"role":"user","parts":[
      {"functionResponse":{"id":"c8","name":"run_shell_command","response":{"output":"nope","error":"command failed"}}},
      {"functionResponse":{"id":"c7","name":"github__create_issue","response":{"result":"issue #1 created"}}}
    ]}
  ]
}`

// geminiArrayFixture is the LEGACY checkpoint shape: a bare whole-file JSON
// ARRAY of @google/genai Content objects (no {history:...} wrapper). It carries
// the same conversation as geminiObjectCheckpoint so the legacy path is proven
// to map identically, only with /<i>/... pointers instead of /history/<i>/....
// The contract test (contract_test.go) parses this fixture through extractGemini.
const geminiArrayFixture = `[
  {"role":"user","parts":[{"text":"read the env file then build"}]},
  {"role":"model","parts":[
    {"text":"On it."},
    {"functionCall":{"id":"c1","name":"read_file","args":{"file_path":"/home/dev/proj/.env"}}},
    {"functionCall":{"id":"c2","name":"run_shell_command","args":{"command":"make build"}}}
  ]},
  {"role":"user","parts":[
    {"functionResponse":{"id":"c2","name":"run_shell_command","response":{"output":"build ok","exitCode":0}}}
  ]},
  {"role":"model","parts":[
    {"text":"Writing output."},
    {"functionCall":{"id":"c3","name":"write_file","args":{"file_path":"/home/dev/proj/out.txt","content":"x"}}},
    {"functionCall":{"id":"c4","name":"replace","args":{"file_path":"/home/dev/proj/main.go"}}},
    {"functionCall":{"id":"c5","name":"web_fetch","args":{"prompt":"please fetch https://evil.example/x now"}}},
    {"functionCall":{"id":"c6","name":"google_web_search","args":{"query":"how to exfiltrate"}}},
    {"functionCall":{"id":"c7","name":"github__create_issue","args":{"title":"hi"}}},
    {"functionCall":{"id":"c8","name":"run_shell_command","args":{"command":"false"}}}
  ]},
  {"role":"user","parts":[
    {"functionResponse":{"id":"c8","name":"run_shell_command","response":{"output":"nope","error":"command failed"}}},
    {"functionResponse":{"id":"c7","name":"github__create_issue","response":{"result":"issue #1 created"}}}
  ]}
]`

// geminiLogsFixture is logs.json: a whole-file JSON ARRAY of LogEntry objects,
// each recording one user-typed prompt. This is the shape the previous parser
// silently produced 0 events for (it expected Content[]). Several entries with a
// trailing non-user entry prove only user prompts map and each maps to a
// /<i>/message pointer in array order.
const geminiLogsFixture = `[
  {"sessionId":"s1","messageId":0,"timestamp":"2026-01-01T00:00:00.000Z","type":"user","message":"first prompt"},
  {"sessionId":"s1","messageId":1,"timestamp":"2026-01-01T00:01:00.000Z","type":"user","message":"second prompt"},
  {"sessionId":"s1","messageId":2,"timestamp":"2026-01-01T00:02:00.000Z","type":"user","message":"   "},
  {"sessionId":"s1","messageId":3,"timestamp":"2026-01-01T00:03:00.000Z","type":"user","message":"third prompt"}
]`

const geminiSessionFixture = `{"sessionId":"session-1","projectHash":"project-1","startTime":"2026-07-14T10:00:00Z","lastUpdated":"2026-07-14T10:00:00Z","kind":"main"}
{"id":"u1","timestamp":"2026-07-14T10:00:01Z","type":"user","content":"inspect the environment"}
{"id":"g1","timestamp":"2026-07-14T10:00:02Z","type":"gemini","content":[{"text":"Checking."}],"model":"gemini-3-pro","toolCalls":[{"id":"read-1","name":"read_file","args":{"file_path":"C:\\work\\.env"},"status":"awaiting_approval","timestamp":"2026-07-14T10:00:03Z"}]}
{"id":"g1","timestamp":"2026-07-14T10:00:02Z","type":"gemini","content":[{"text":"Checking."}],"model":"gemini-3-pro","thoughts":[{"subject":"Plan","description":"Inspect safely","timestamp":"2026-07-14T10:00:02.5Z"}],"toolCalls":[{"id":"read-1","name":"read_file","args":{"file_path":"C:\\work\\.env"},"result":[{"functionResponse":{"id":"read-1","name":"read_file","response":{"content":"SECRET=value"}}}],"status":"success","timestamp":"2026-07-14T10:00:03Z"},{"id":"shell-1","name":"run_shell_command","args":{"command":"Get-Content .env"},"result":[{"functionResponse":{"id":"shell-1","name":"run_shell_command","response":{"output":"failed","exitCode":7,"error":"denied"}}}],"status":"error","timestamp":"2026-07-14T10:00:04Z","agentId":"security-reviewer"}]}
{"$rewindTo":"g1"}`

// extractGeminiPath parses body as a Gemini artifact at the given basename,
// which selects the decoder (logs.json -> LogEntry, checkpoint-*.json ->
// Content). The path uses filepath.Join so the basename test is macOS-symlink
// safe (it relies on filepath.Base, not a full-path compare).
func extractGeminiPath(t *testing.T, base, body string) *Result {
	t.Helper()
	path := filepath.Join("/cases", base)
	res, err := GeminiExtractor{}.Extract(strings.NewReader(body), Source{Path: path, CaseID: "case-g"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// extractGemini parses body as a checkpoint transcript (the @google/genai
// Content shape). The contract test relies on this helper, so it routes through
// a checkpoint-*.json basename to exercise the Content decoder.
func extractGemini(t *testing.T, body string) *Result {
	t.Helper()
	return extractGeminiPath(t, "checkpoint-work.json", body)
}

func extractGeminiSession(t *testing.T, body string, includeReasoning bool) *Result {
	t.Helper()
	path := filepath.Join("/cases", ".gemini", "tmp", "project", "chats", "session-1.jsonl")
	res, err := GeminiExtractor{}.Extract(strings.NewReader(body), Source{Path: path, CaseID: "case-g", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

func TestExtractGeminiCurrentSessionJournal(t *testing.T) {
	res := extractGeminiSession(t, geminiSessionFixture, true)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
	if len(res.Events) != 9 {
		t.Fatalf("events = %d, want session start plus 8 activity events:\n%s", len(res.Events), dumpEvents(res.Events))
	}
	start := res.Events[0]
	if start.EventType != model.EventSessionStart || start.Timestamp != "2026-07-14T10:00:00Z" || start.Evidence.Line != 1 {
		t.Errorf("session start = %+v", start)
	}
	acts := activityEvents(res.Events)
	if acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != "inspect the environment" {
		t.Errorf("prompt = %+v", acts[0])
	}
	if acts[1].EventType != model.EventMessageAssistant || acts[2].EventType != model.EventMessageReasoning {
		t.Fatalf("assistant/reasoning events = %s, %s", acts[1].EventType, acts[2].EventType)
	}
	if acts[3].EventType != model.EventFileRead || acts[3].FilePath != `C:\work\.env` {
		t.Errorf("read call = %+v", acts[3])
	}
	if acts[3].Evidence.Line != 3 {
		t.Errorf("read call evidence line = %d, want first-seen line 3", acts[3].Evidence.Line)
	}
	if acts[4].EventType != model.EventPermissionRequested || acts[4].Evidence.Line != 3 || acts[4].ApprovalDecision != model.DecisionAsked {
		t.Errorf("transient approval request was not preserved: %+v", acts[4])
	}
	if acts[5].EventType != model.EventToolResult || acts[5].ContentPreview != "" {
		t.Errorf("read result leaked content or has wrong type: %+v", acts[5])
	}
	command := acts[6]
	result := acts[7]
	if command.EventType != model.EventCommandExec || command.Command != "Get-Content .env" || command.SubAgent != "security-reviewer" {
		t.Errorf("command = %+v", command)
	}
	if result.EventType != model.EventCommandResult || result.ExitCode == nil || *result.ExitCode != 7 ||
		result.ContentPreview != "failed" || !equalTags(result.Tags, []string{model.TagToolError}) {
		t.Errorf("command result = %+v", result)
	}
	for i, ev := range res.Events {
		if ev.SessionID != "session-1" {
			t.Errorf("event %d session_id = %q", i, ev.SessionID)
		}
		if i > 1 && ev.Model != "gemini-3-pro" {
			t.Errorf("event %d model = %q", i, ev.Model)
		}
		if i > 1 && ev.EventType != model.EventPermissionRequested && ev.EventType != model.EventFileRead && ev.Evidence.Line != 4 {
			t.Errorf("event %d line = %d, want latest message snapshot line 4", i, ev.Evidence.Line)
		}
	}
	assertUniqueEventIDs(t, res.Events)
}

func TestExtractGeminiSessionDefaultIncludesModelButDropsReasoning(t *testing.T) {
	res := extractGeminiSession(t, geminiSessionFixture, false)
	modelSeen := false
	for _, ev := range res.Events {
		if ev.EventType == model.EventMessageReasoning {
			t.Errorf("default extraction surfaced reasoning: %+v", ev)
		}
		if ev.Model == "gemini-3-pro" {
			modelSeen = true
		}
	}
	if !modelSeen {
		t.Fatal("default extraction omitted source-recorded model identity")
	}
}

func TestExtractGeminiLegacySessionObject(t *testing.T) {
	body := `{
  "sessionId":"legacy-session",
  "projectHash":"project-1",
  "startTime":"2026-07-14T09:00:00Z",
  "messages":[{"id":"u1","timestamp":"2026-07-14T09:00:01Z","type":"user","content":[{"text":"hello"}]}]
}`
	res := extractGeminiSession(t, body, false)
	acts := activityEvents(res.Events)
	if len(acts) != 1 || acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != "hello" {
		t.Fatalf("legacy session events = %s", dumpEvents(res.Events))
	}
	if acts[0].Evidence.Line != 1 || acts[0].Evidence.JSONPointer != "/messages/0/content/0/text" {
		t.Errorf("legacy evidence = %+v", acts[0].Evidence)
	}
}

func TestExtractGeminiSessionMetadataUpdateDoesNotInventStart(t *testing.T) {
	res := extractGeminiSession(t, `{"$set":{"lastUpdated":"2026-07-14T09:00:00Z"}}`, false)
	if len(res.Events) != 0 {
		t.Fatalf("events = %s, want none", dumpEvents(res.Events))
	}
}

func TestExtractGeminiSessionPreservesJournalLineNumbers(t *testing.T) {
	res := extractGeminiSession(t, "\n"+geminiSessionFixture, false)
	if len(res.Events) == 0 || res.Events[0].Evidence.Line != 2 {
		t.Fatalf("first event evidence = %+v, want line 2", res.Events[0].Evidence)
	}
}

func TestExtractGeminiSessionSuppressesReadManyResult(t *testing.T) {
	body := `{"sessionId":"s1","startTime":"2026-07-14T09:00:00Z"}
{"id":"g1","timestamp":"2026-07-14T09:00:01Z","type":"gemini","content":[],"toolCalls":[{"id":"r1","name":"read_many_files","args":{"include":["**/*.env"]},"result":[{"functionResponse":{"id":"r1","name":"read_many_files","response":{"output":"SECRET=value"}}}],"status":"success","timestamp":"2026-07-14T09:00:02Z"}]}`
	res := extractGeminiSession(t, body, false)
	acts := activityEvents(res.Events)
	if len(acts) != 2 || acts[1].EventType != model.EventToolResult || acts[1].ContentPreview != "" {
		t.Fatalf("read_many_files events = %s", dumpEvents(acts))
	}
}

// Regression: a web_fetch prompt whose lifted URL token is not a valid
// absolute http(s) URL with a host (here a hostless http:///etc/passwd) must NOT
// be promoted into Event.URL. The prompt stays visible in ContentPreview; the
// event is still a network.indicator tagged network.
func TestExtractGeminiWebFetchRejectsHostlessURL(t *testing.T) {
	const prompt = "please fetch http:///etc/passwd now"
	body := `{"history":[{"role":"model","parts":[{"functionCall":{"id":"c1","name":"web_fetch","args":{"prompt":"please fetch http:///etc/passwd now"}}}]}]}`
	acts := activityEvents(extractGemini(t, body).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventNetworkIndicator {
		t.Errorf("event_type = %s, want network.indicator", ev.EventType)
	}
	if ev.URL != "" {
		t.Errorf("url = %q, want empty (hostless URL must not be promoted)", ev.URL)
	}
	if ev.ContentPreview != prompt {
		t.Errorf("ContentPreview = %q, want the raw prompt preserved", ev.ContentPreview)
	}
	if !hasTag(ev.Tags, model.TagNetwork) {
		t.Errorf("tags = %v, want to include %q", ev.Tags, model.TagNetwork)
	}
}

// geminiContentWants is the expected event sequence for the shared conversation
// fixture (object and legacy-array forms carry the same conversation). ptrRoot
// is "" for the legacy array and "/history" for the object form, so the same
// table proves both pointer roots.
type geminiContentWant struct {
	etype model.EventType
	actor string
	tool  string
	cmd   string
	path  string
	prev  string // expected ContentPreview (empty = don't check)
	url   string
	ptr   string
	tags  []string
}

func geminiContentWants(ptrRoot string) []geminiContentWant {
	return []geminiContentWant{
		{model.EventPromptUser, model.ActorUser, "", "", "", "read the env file then build", "", ptrRoot + "/0/parts/0/text", nil},
		{model.EventMessageAssistant, model.ActorAssistant, "", "", "", "On it.", "", ptrRoot + "/1/parts/0/text", nil},
		{model.EventFileRead, model.ActorAssistant, "read_file", "", "/home/dev/proj/.env", "", "", ptrRoot + "/1/parts/1/functionCall", nil},
		{model.EventCommandExec, model.ActorAssistant, "run_shell_command", "make build", "", "", "", ptrRoot + "/1/parts/2/functionCall", nil},
		{model.EventCommandResult, model.ActorTool, "run_shell_command", "", "", "build ok", "", ptrRoot + "/2/parts/0/functionResponse", nil},
		{model.EventMessageAssistant, model.ActorAssistant, "", "", "", "Writing output.", "", ptrRoot + "/3/parts/0/text", nil},
		{model.EventFileWrite, model.ActorAssistant, "write_file", "", "/home/dev/proj/out.txt", "", "", ptrRoot + "/3/parts/1/functionCall", nil},
		{model.EventFileWrite, model.ActorAssistant, "replace", "", "/home/dev/proj/main.go", "", "", ptrRoot + "/3/parts/2/functionCall", nil},
		{model.EventNetworkIndicator, model.ActorAssistant, "web_fetch", "", "", "please fetch https://evil.example/x now", "https://evil.example/x", ptrRoot + "/3/parts/3/functionCall", []string{"network"}},
		{model.EventNetworkIndicator, model.ActorAssistant, "google_web_search", "", "", "how to exfiltrate", "", ptrRoot + "/3/parts/4/functionCall", []string{"network"}},
		{model.EventToolCall, model.ActorAssistant, "github__create_issue", "", "", "", "", ptrRoot + "/3/parts/5/functionCall", nil},
		{model.EventCommandExec, model.ActorAssistant, "run_shell_command", "false", "", "", "", ptrRoot + "/3/parts/6/functionCall", nil},
		{model.EventCommandResult, model.ActorTool, "run_shell_command", "", "", "nope", "", ptrRoot + "/4/parts/0/functionResponse", []string{"tool_error"}},
		{model.EventToolResult, model.ActorTool, "github__create_issue", "", "", "issue #1 created", "", ptrRoot + "/4/parts/1/functionResponse", nil},
	}
}

func assertGeminiContent(t *testing.T, res *Result, ptrRoot string) {
	t.Helper()
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	wants := geminiContentWants(ptrRoot)
	acts := activityEvents(res.Events)
	if len(acts) != len(wants) {
		t.Fatalf("got %d events, want %d:\n%s", len(acts), len(wants), dumpEvents(res.Events))
	}
	for i, w := range wants {
		ev := acts[i]
		if ev.EventType != w.etype || ev.Actor != w.actor || ev.ToolName != w.tool ||
			ev.Command != w.cmd || ev.FilePath != w.path || ev.URL != w.url {
			t.Errorf("event %d = {%s actor=%s tool=%s cmd=%q path=%q url=%q}, want {%s actor=%s tool=%s cmd=%q path=%q url=%q}",
				i, ev.EventType, ev.Actor, ev.ToolName, ev.Command, ev.FilePath, ev.URL,
				w.etype, w.actor, w.tool, w.cmd, w.path, w.url)
		}
		if w.prev != "" && ev.ContentPreview != w.prev {
			t.Errorf("event %d content_preview = %q, want %q", i, ev.ContentPreview, w.prev)
		}
		if ev.Evidence.JSONPointer != w.ptr {
			t.Errorf("event %d json_pointer = %q, want %q", i, ev.Evidence.JSONPointer, w.ptr)
		}
		if !equalTags(ev.Tags, w.tags) {
			t.Errorf("event %d tags = %v, want %v", i, ev.Tags, w.tags)
		}
	}

	// The structured exitCode:0 on the first shell result is surfaced (it is a
	// real structured field, not an inferred "success").
	if acts[4].ExitCode == nil || *acts[4].ExitCode != 0 {
		t.Errorf("first command.result exit_code = %v, want 0 (structured)", acts[4].ExitCode)
	}

	// Every event carries the agent, case id, artifact type, and a content hash.
	for i, ev := range res.Events {
		if ev.SourceAgent != model.AgentGeminiCLI {
			t.Errorf("event %d source_agent = %q, want %q", i, ev.SourceAgent, model.AgentGeminiCLI)
		}
		if ev.CaseID != "case-g" {
			t.Errorf("event %d case_id = %q, want case-g", i, ev.CaseID)
		}
		if ev.Evidence.ArtifactType != artifactGeminiChat {
			t.Errorf("event %d artifact_type = %q, want %q", i, ev.Evidence.ArtifactType, artifactGeminiChat)
		}
		if ev.Evidence.SHA256 == "" {
			t.Errorf("event %d missing evidence sha256", i)
		}
	}

	assertUniqueEventIDs(t, res.Events)
}

// The current checkpoint object {"history": Content[]} maps every shape — text,
// functionCall, functionResponse — in order, with /history-rooted JSON Pointers
// and correct call/response correlation. A first-byte=='[' gate would silently
// reject this shape, producing 0 events.
func TestExtractGeminiObjectCheckpoint(t *testing.T) {
	res := extractGeminiPath(t, "checkpoint-work.json", geminiObjectCheckpoint)
	assertGeminiContent(t, res, "/history")

	// Determinism: a second parse of the same bytes yields identical ids.
	res2 := extractGeminiPath(t, "checkpoint-work.json", geminiObjectCheckpoint)
	if len(res2.Events) != len(res.Events) {
		t.Fatalf("nondeterministic event count: %d vs %d", len(res2.Events), len(res.Events))
	}
	for i := range res.Events {
		if res.Events[i].EventID != res2.Events[i].EventID {
			t.Errorf("event %d id nondeterministic: %q vs %q", i, res.Events[i].EventID, res2.Events[i].EventID)
		}
	}
}

// The legacy bare Content[] array checkpoint still maps identically, only with
// /<i>/... JSON Pointers (no /history root). This is a known Gemini save shape,
// not a parser guess.
func TestExtractGeminiLegacyArrayCheckpoint(t *testing.T) {
	res := extractGeminiPath(t, "checkpoint-old.json", geminiArrayFixture)
	assertGeminiContent(t, res, "")
}

// logs.json — the previously-SILENT case — is a JSON array of LogEntry objects,
// each a single user prompt. Each user entry maps to one prompt.user event with
// a /<i>/message pointer in array order; a blank message is skipped. This is the
// regression target: the old parser expected Content[] and produced 0 events / 0
// diagnostics on this real shape.
func TestExtractGeminiLogsUserPrompts(t *testing.T) {
	res := extractGeminiPath(t, "logs.json", geminiLogsFixture)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}
	acts := activityEvents(res.Events)
	type want struct {
		prev string
		ptr  string
	}
	// messageId 2 is whitespace-only and skipped; the rest map in array order.
	wants := []want{
		{"first prompt", "/0/message"},
		{"second prompt", "/1/message"},
		{"third prompt", "/3/message"},
	}
	if len(acts) != len(wants) {
		t.Fatalf("got %d events, want %d:\n%s", len(acts), len(wants), dumpEvents(res.Events))
	}
	for i, w := range wants {
		ev := acts[i]
		if ev.EventType != model.EventPromptUser || ev.Actor != model.ActorUser {
			t.Errorf("event %d = {%s actor=%s}, want prompt.user/user", i, ev.EventType, ev.Actor)
		}
		if ev.ContentPreview != w.prev {
			t.Errorf("event %d content_preview = %q, want %q", i, ev.ContentPreview, w.prev)
		}
		if ev.Evidence.JSONPointer != w.ptr {
			t.Errorf("event %d json_pointer = %q, want %q", i, ev.Evidence.JSONPointer, w.ptr)
		}
		if ev.SourceAgent != model.AgentGeminiCLI || ev.Evidence.ArtifactType != artifactGeminiChat || ev.Evidence.SHA256 == "" {
			t.Errorf("event %d missing identity/evidence: agent=%q artifact=%q sha=%q", i, ev.SourceAgent, ev.Evidence.ArtifactType, ev.Evidence.SHA256)
		}
	}
	assertUniqueEventIDs(t, res.Events)
}

// A functionCall and its later functionResponse correlate by array order and by
// name, and the result is emitted AFTER the call (the call part precedes the
// response part in the array), so a shell command.result always follows its
// command.exec in the timeline.
func TestExtractGeminiCorrelatesCallAndResultInOrder(t *testing.T) {
	body := `[
	  {"role":"model","parts":[{"functionCall":{"id":"c1","name":"run_shell_command","args":{"command":"ls"}}}]},
	  {"role":"user","parts":[{"functionResponse":{"id":"c1","name":"run_shell_command","response":{"output":"a b c","exitCode":0}}}]}
	]`
	acts := activityEvents(extractGemini(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d events, want 2:\n%s", len(acts), dumpEvents(acts))
	}
	if acts[0].EventType != model.EventCommandExec || acts[0].Command != "ls" {
		t.Errorf("event 0 = %s cmd=%q, want command.exec cmd=ls", acts[0].EventType, acts[0].Command)
	}
	if acts[1].EventType != model.EventCommandResult {
		t.Errorf("event 1 = %s, want command.result (ordered after command.exec)", acts[1].EventType)
	}
	// Both sides share the correlation id.
	if acts[0].ToolCallID != "c1" || acts[1].ToolCallID != "c1" {
		t.Errorf("correlation ids = %q/%q, want c1/c1", acts[0].ToolCallID, acts[1].ToolCallID)
	}
}

// Exit code and tool_error come ONLY from structured response fields. A shell
// result whose body merely contains the text "exit code: 1" but no structured
// field carries neither an ExitCode nor a tool_error tag — numbat never scrapes
// prose.
func TestExtractGeminiResultStructuredFieldsOnly(t *testing.T) {
	body := `[
	  {"role":"model","parts":[{"functionCall":{"id":"c1","name":"run_shell_command","args":{"command":"x"}}}]},
	  {"role":"user","parts":[{"functionResponse":{"id":"c1","name":"run_shell_command","response":{"output":"failure: exit code: 1\nerror: boom"}}}]}
	]`
	acts := activityEvents(extractGemini(t, body).Events)
	res := acts[len(acts)-1]
	if res.EventType != model.EventCommandResult {
		t.Fatalf("last event = %s, want command.result", res.EventType)
	}
	if res.ExitCode != nil {
		t.Errorf("exit_code = %v, want nil (no structured field; prose must not be scraped)", *res.ExitCode)
	}
	if len(res.Tags) != 0 {
		t.Errorf("tags = %v, want none (no structured error field)", res.Tags)
	}
}

// An unknown / non-built-in tool maps to a generic tool.call with NO alias
// promotion: its name is preserved verbatim and it is never reclassified into a
// command/file/network event.
func TestExtractGeminiUnknownToolNoAliasPromotion(t *testing.T) {
	body := `[
	  {"role":"model","parts":[{"functionCall":{"id":"c1","name":"some_unknown_tool","args":{"foo":"bar"}}}]}
	]`
	acts := activityEvents(extractGemini(t, body).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d events, want 1:\n%s", len(acts), dumpEvents(acts))
	}
	ev := acts[0]
	if ev.EventType != model.EventToolCall {
		t.Errorf("event type = %s, want tool.call (no alias promotion)", ev.EventType)
	}
	if ev.ToolName != "some_unknown_tool" {
		t.Errorf("tool_name = %q, want some_unknown_tool (preserved verbatim)", ev.ToolName)
	}
	if ev.Command != "" || ev.FilePath != "" || ev.URL != "" {
		t.Errorf("unknown tool leaked into a typed field: cmd=%q path=%q url=%q", ev.Command, ev.FilePath, ev.URL)
	}
}

// A read_file functionCall yields a file.read; its functionResponse yields a
// tool/command result whose preview is EMPTY — a read result body is file
// content and must never be stored.
func TestExtractGeminiReadResultNeverStoresContent(t *testing.T) {
	body := `[
	  {"role":"model","parts":[{"functionCall":{"id":"c1","name":"read_file","args":{"file_path":"/secret.txt"}}}]},
	  {"role":"user","parts":[{"functionResponse":{"id":"c1","name":"read_file","response":{"output":"TOP SECRET CONTENTS"}}}]}
	]`
	acts := activityEvents(extractGemini(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d events, want 2:\n%s", len(acts), dumpEvents(acts))
	}
	if acts[0].EventType != model.EventFileRead || acts[0].FilePath != "/secret.txt" {
		t.Errorf("event 0 = %s path=%q, want file.read /secret.txt", acts[0].EventType, acts[0].FilePath)
	}
	if acts[1].ContentPreview != "" {
		t.Errorf("read result content_preview = %q, want empty (file content must never be stored)", acts[1].ContentPreview)
	}
	if strings.Contains(acts[1].ContentPreview, "SECRET") {
		t.Error("read result leaked file content into the preview")
	}
}

// A logs.json that is not a JSON array (an object, JSONL, a scalar) fails safe:
// a single diagnostic, no fabricated events. logs.json is always an array.
func TestExtractGeminiLogsMalformedFailsSafe(t *testing.T) {
	for _, body := range []string{
		`{"type":"user","message":"x"}`, // an object, not an array
		`[ {"type":"user"`,              // truncated array
		`not json at all`,               // not JSON
		`42`,                            // a scalar, not an array
	} {
		res := extractGeminiPath(t, "logs.json", body)
		if len(res.Events) != 0 {
			t.Errorf("body %q produced %d events, want 0", body, len(res.Events))
		}
		if len(res.Diagnostics) != 1 {
			t.Errorf("body %q produced %d diagnostics, want 1", body, len(res.Diagnostics))
		}
	}
}

// A checkpoint that is neither object nor array, or is malformed, fails safe: a
// single diagnostic, no fabricated events, no panic.
func TestExtractGeminiCheckpointMalformedFailsSafe(t *testing.T) {
	for _, body := range []string{
		`[ {"role":"user"`,      // truncated array
		`{"history": [ {"role"`, // truncated object
		`not json at all`,       // not JSON
		`42`,                    // a scalar
		`"just a string"`,       // a JSON string scalar
	} {
		res := extractGeminiPath(t, "checkpoint-x.json", body)
		if len(res.Events) != 0 {
			t.Errorf("body %q produced %d events, want 0", body, len(res.Events))
		}
		if len(res.Diagnostics) != 1 {
			t.Errorf("body %q produced %d diagnostics, want 1:\n%+v", body, len(res.Diagnostics), res.Diagnostics)
		}
	}
}

// A file that DECODES cleanly but yields NO recognized content must still emit a
// diagnostic (a visible coverage gap), never a silent 0 events / 0 diagnostics.
// Covers: empty logs array, logs array with only non-user entries, empty
// checkpoint object history, empty legacy array, and a checkpoint whose only
// parts are unmodeled kinds.
func TestExtractGeminiDecodableButEmptyEmitsDiagnostic(t *testing.T) {
	cases := []struct {
		name string
		base string
		body string
	}{
		{"empty logs array", "logs.json", `[]`},
		{"logs non-user only", "logs.json", `[{"type":"info","message":"started"}]`},
		{"empty object history", "checkpoint-a.json", `{"history":[]}`},
		{"object no history key", "checkpoint-a.json", `{"authType":"oauth"}`},
		{"empty legacy array", "checkpoint-a.json", `[]`},
		{"only unmodeled parts", "checkpoint-a.json", `[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"AAAA"}}]}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := extractGeminiPath(t, c.base, c.body)
			if len(res.Events) != 0 {
				t.Errorf("produced %d events, want 0:\n%s", len(res.Events), dumpEvents(res.Events))
			}
			if len(res.Diagnostics) != 1 {
				t.Errorf("produced %d diagnostics, want 1 (decodable-but-empty must not be silent):\n%+v", len(res.Diagnostics), res.Diagnostics)
			}
		})
	}
}

// An empty file is a clean no-op: no events, no diagnostics, no error. An
// artifact past the size cap is a hard error (cannot be trusted), matching the
// other extractors' contract.
func TestExtractGeminiEmptyAndCaps(t *testing.T) {
	res, err := GeminiExtractor{}.Extract(strings.NewReader(""), Source{Path: "/cases/logs.json"})
	if err != nil {
		t.Fatalf("empty Extract error: %v", err)
	}
	if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
		t.Fatalf("empty input produced events=%d diags=%d", len(res.Events), len(res.Diagnostics))
	}

	big := "[" + strings.Repeat("a", 100) + "]"
	if _, err := (GeminiExtractor{maxBytes: 10}).Extract(strings.NewReader(big), Source{Path: "/cases/checkpoint-big.json"}); err == nil {
		t.Fatalf("expected size-cap error, got nil")
	}
}

// A functionResponse with no correlatable functionCall still emits a tool.result
// keyed by its own name/id — coverage is never silently dropped.
func TestExtractGeminiOrphanResponseStillEmits(t *testing.T) {
	body := `[
	  {"role":"user","parts":[{"functionResponse":{"id":"x9","name":"mystery_tool","response":{"result":"hi"}}}]}
	]`
	acts := activityEvents(extractGemini(t, body).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d events, want 1:\n%s", len(acts), dumpEvents(acts))
	}
	if acts[0].EventType != model.EventToolResult || acts[0].ToolName != "mystery_tool" || acts[0].ToolCallID != "x9" {
		t.Errorf("orphan response = {%s tool=%q id=%q}, want tool.result/mystery_tool/x9",
			acts[0].EventType, acts[0].ToolName, acts[0].ToolCallID)
	}
}

// A part kind numbat does not model (inlineData, etc.) is skipped without
// emitting a phantom event, while sibling text/functionCall parts still surface.
func TestExtractGeminiUnmodeledPartSkipped(t *testing.T) {
	body := `[
	  {"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"AAAA"}},{"text":"see attached"}]}
	]`
	acts := activityEvents(extractGemini(t, body).Events)
	if len(acts) != 1 {
		t.Fatalf("got %d events, want 1 (only the text part):\n%s", len(acts), dumpEvents(acts))
	}
	if acts[0].EventType != model.EventPromptUser || acts[0].ContentPreview != "see attached" {
		t.Errorf("event 0 = %s prev=%q, want prompt.user 'see attached'", acts[0].EventType, acts[0].ContentPreview)
	}
}

// equalTags compares two tag slices for exact equality (order-sensitive,
// nil == empty). Tags are emitted in a fixed order per status/tool.
func equalTags(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

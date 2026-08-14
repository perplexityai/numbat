package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// copilotFixture is a small Copilot CLI events.jsonl: a user prompt, an assistant
// message, a PreToolUse shell invocation (toolArgs as a JSON-ENCODED STRING, the
// worst-realistic Copilot shape), and the matching PostToolUse result IN A
// SEPARATE record carrying a structured exit code and an explicit error. The
// shapes exercise the tolerant decoder (string content, encoded-string toolArgs)
// and the cross-record command-result correlation.
const copilotFixture = `{"type":"UserPromptSubmitted","id":"cu1","sessionId":"sess-1","timestamp":"2026-06-03T10:00:00Z","cwd":"/home/dev/proj","prompt":"why is the auth middleware failing?"}
{"type":"assistant","id":"ca1","sessionId":"sess-1","timestamp":"2026-06-03T10:00:01Z","cwd":"/home/dev/proj","content":"Let me run the tests."}
{"hookEventName":"PreToolUse","id":"ct1","sessionId":"sess-1","timestamp":"2026-06-03T10:00:02Z","cwd":"/home/dev/proj","toolName":"ShellCommand","toolCallId":"t1","toolArgs":"{\"command\":\"go test ./...\"}"}
{"hookEventName":"PostToolUse","id":"ct1r","sessionId":"sess-1","timestamp":"2026-06-03T10:00:03Z","cwd":"/home/dev/proj","toolName":"ShellCommand","toolCallId":"t1","exitCode":1,"error":"tests failed"}`

func extractCopilot(t *testing.T, body string) *Result {
	t.Helper()
	res, err := CopilotExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/copilot.jsonl", CaseID: "case-cp"})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// The Copilot parser maps a prompt, an assistant message, a shell command.exec,
// and the CROSS-RECORD correlated command.result carrying the structured exit
// code — every event stamped with the copilot source identity and the copilot
// artifact type. This is the headline correlation+exit-code proof.
func TestExtractCopilotMapsShapesWithCopilotIdentity(t *testing.T) {
	res := extractCopilot(t, copilotFixture)
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
	// Copilot agent identity, the Copilot artifact type, and the case id.
	for _, ev := range res.Events {
		if ev.SourceAgent != model.AgentCopilot {
			t.Errorf("event %q source_agent = %q, want %q", ev.EventID, ev.SourceAgent, model.AgentCopilot)
		}
		if ev.SourceType != model.SourceArtifact {
			t.Errorf("event %q source_type = %q, want %q", ev.EventID, ev.SourceType, model.SourceArtifact)
		}
		if ev.Evidence.ArtifactType != artifactCopilotEvents {
			t.Errorf("event %q artifact_type = %q, want %q", ev.EventID, ev.Evidence.ArtifactType, artifactCopilotEvents)
		}
		if ev.CaseID != "case-cp" {
			t.Errorf("event %q case_id = %q, want case-cp", ev.EventID, ev.CaseID)
		}
	}

	// The command.exec and its CROSS-RECORD correlated command.result share the
	// tool call id, the result is ordered AFTER the exec, and the structured exit
	// code rides on the result — proving cross-record correlation runs.
	exec := acts[2]
	result := acts[3]
	if exec.ToolCallID != "t1" || result.ToolCallID != "t1" {
		t.Errorf("tool call correlation = exec %q / result %q, want both t1", exec.ToolCallID, result.ToolCallID)
	}
	if result.ExitCode == nil || *result.ExitCode != 1 {
		t.Errorf("command.result exit_code = %v, want 1 (structured exit code must survive correlation)", result.ExitCode)
	}
	if !hasTag(result.Tags, model.TagToolError) {
		t.Errorf("errored command.result tags = %v, want to include %q", result.Tags, model.TagToolError)
	}

	// Source-faithful RFC-6901 pointers: the prompt body, the assistant content,
	// and the tool-argument blob each point at the exact source key they were read
	// from.
	wantPtr := []string{"/prompt", "/content", "/toolArgs", ""}
	for i, want := range wantPtr {
		if acts[i].Evidence.JSONPointer != want {
			t.Errorf("event %d (%s) pointer = %q, want %q", i, acts[i].EventType, acts[i].Evidence.JSONPointer, want)
		}
	}

	assertUniqueEventIDs(t, res.Events)
}

// A lone PostToolUse whose call id was NEVER a recorded command.exec must NOT
// become a command.result — it stays a generic tool.result and carries no exit
// code. This is the guard that a result can never leak ahead of, or without, its
// exec. In Copilot's model each events.jsonl line carries exactly ONE tool moment
// (kind() is a single pre/post discriminator; emitTool emits one tool event), so a
// single record can never frame both a call and its result — correlation is purely
// CROSS-record, and the cross-record correlation+ordering proof (exec before
// result, shared call id, structured exit code) lives in the headline test
// TestExtractCopilotMapsShapesWithCopilotIdentity.
func TestExtractCopilotOrphanResultStaysToolResult(t *testing.T) {
	const body = `{"hookEventName":"PostToolUse","id":"x","sessionId":"c","toolName":"ShellCommand","toolCallId":"orphan","exitCode":0}`
	res := extractCopilot(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(res.Events))
	}
	if acts[0].EventType != model.EventToolResult {
		t.Errorf("orphan shell result = %s, want tool.result (no prior exec to correlate)", acts[0].EventType)
	}
	if acts[0].ExitCode != nil {
		t.Errorf("a generic tool.result must not carry a command exit_code: %v", acts[0].ExitCode)
	}
}

// A PostToolUse whose call id was never a shell command stays a generic
// tool.result (never a command.result), and a structurally-marked failure is
// tagged tool_error. This covers the non-command correlation branch.
func TestExtractCopilotNonCommandResultAndError(t *testing.T) {
	const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ReadFile","toolCallId":"r1","toolArgs":"{\"path\":\"/etc/hosts\"}"}
{"hookEventName":"PostToolUse","id":"b","sessionId":"c","toolName":"ReadFile","toolCallId":"r1","isError":true}`
	res := extractCopilot(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
	if acts[0].EventType != model.EventFileRead || acts[0].FilePath != "/etc/hosts" {
		t.Errorf("first = {%s file=%q}, want {file.read /etc/hosts}", acts[0].EventType, acts[0].FilePath)
	}
	if acts[1].EventType != model.EventToolResult {
		t.Errorf("result event = %s, want tool.result (a ReadFile result is not a command.result)", acts[1].EventType)
	}
	if !hasTag(acts[1].Tags, model.TagToolError) {
		t.Errorf("errored tool.result tags = %v, want to include %q", acts[1].Tags, model.TagToolError)
	}
}

// A read never stores content even when the record carries it — the no-secrets
// policy mirrored from the live hook.
func TestExtractCopilotReadNeverStoresContent(t *testing.T) {
	const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ReadFile","toolArgs":"{\"path\":\"/proj/.env\",\"content\":\"SECRET=abc\"}"}`
	res := extractCopilot(t, body)
	acts := activityEvents(res.Events)
	if len(acts) != 1 {
		t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(res.Events))
	}
	if acts[0].EventType != model.EventFileRead || acts[0].FilePath != "/proj/.env" {
		t.Errorf("event = {%s file=%q}, want {file.read /proj/.env}", acts[0].EventType, acts[0].FilePath)
	}
	if acts[0].ContentPreview != "" {
		t.Errorf("content_preview = %q, want empty (read content never stored)", acts[0].ContentPreview)
	}
}

// A WebFetch tool call surfaces as a network.indicator carrying the url and the
// network tag; a WebSearch carries the query as the preview and no url.
func TestExtractCopilotNetworkIndicator(t *testing.T) {
	t.Run("web_fetch", func(t *testing.T) {
		const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"WebFetch","toolArgs":"{\"url\":\"https://example.com/x\"}"}`
		acts := activityEvents(extractCopilot(t, body).Events)
		if len(acts) != 1 {
			t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(acts))
		}
		ev := acts[0]
		if ev.EventType != model.EventNetworkIndicator || ev.URL != "https://example.com/x" {
			t.Errorf("event = {%s url=%q}, want {network.indicator https://example.com/x}", ev.EventType, ev.URL)
		}
		if !hasTag(ev.Tags, model.TagNetwork) {
			t.Errorf("tags = %v, want to include %q", ev.Tags, model.TagNetwork)
		}
	})
	t.Run("web_search", func(t *testing.T) {
		const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"WebSearch","toolArgs":"{\"query\":\"how to exfiltrate\"}"}`
		acts := activityEvents(extractCopilot(t, body).Events)
		if len(acts) != 1 {
			t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(acts))
		}
		ev := acts[0]
		if ev.EventType != model.EventNetworkIndicator || ev.URL != "" {
			t.Errorf("event = {%s url=%q}, want {network.indicator <empty url>}", ev.EventType, ev.URL)
		}
		if ev.ContentPreview != "how to exfiltrate" {
			t.Errorf("content_preview = %q, want the query text", ev.ContentPreview)
		}
		if !hasTag(ev.Tags, model.TagNetwork) {
			t.Errorf("tags = %v, want to include %q", ev.Tags, model.TagNetwork)
		}
	})
	// Regression: a WebFetch url that is not an absolute http(s) URL must
	// NOT be promoted into Event.URL. file:///etc/passwd leaves URL empty (kept in
	// ContentPreview); the event stays a network.indicator tagged network.
	t.Run("web_fetch_rejects_non_http", func(t *testing.T) {
		const bad = "file:///etc/passwd"
		const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"WebFetch","toolArgs":"{\"url\":\"file:///etc/passwd\"}"}`
		acts := activityEvents(extractCopilot(t, body).Events)
		if len(acts) != 1 {
			t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(acts))
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
	})
}

// An MCP-named tool splits into typed server/tool fields. This covers the MCP
// branch of the classifier's tool.call fallback.
func TestExtractCopilotMCPSplit(t *testing.T) {
	const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"mcp__github__create_issue","toolArgs":"{\"title\":\"x\"}"}`
	acts := activityEvents(extractCopilot(t, body).Events)
	if len(acts) != 1 || acts[0].EventType != model.EventToolCall {
		t.Fatalf("got %d events / type %s, want one tool.call:\n%s", len(acts), acts[0].EventType, dumpEvents(acts))
	}
	if acts[0].MCPServer != "github" || acts[0].MCPTool != "create_issue" {
		t.Errorf("mcp split = %q/%q, want github/create_issue", acts[0].MCPServer, acts[0].MCPTool)
	}
}

// The classifier vocabulary is LOCKED to the verified live Copilot tool set; any
// name outside it — an unknown/custom verb OR a generic alias that is NOT part of
// the live mapper (e.g. the old over-broad "shell"/"search"/"DeleteFile"/
// "apply_patch" aliases) — MUST fall back to a generic tool.call and MUST NOT be
// promoted into command.exec, file.*, or network.indicator. Promoting an
// unrecognized verb is the false-positive direction the locked precision rules
// forbid; a documented false negative (the verb staying tool.call) is preferred.
func TestExtractCopilotUnknownToolFallsBackToToolCall(t *testing.T) {
	for _, name := range []string{
		"frobnicate",  // a wholly unknown/custom tool
		"shell",       // removed generic shell alias
		"RunCommand",  // removed generic shell alias
		"search",      // removed generic web alias
		"fetch",       // removed generic web alias
		"ViewFile",    // removed generic read alias
		"MultiEdit",   // removed generic write alias
		"apply_patch", // removed generic write alias
		"create_file", // removed generic write alias
		"DeleteFile",  // delete has no verified live family — must NOT become file.delete
		"delete_file", // ditto
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"` + name + `","toolArgs":"{\"command\":\"x\",\"path\":\"/p\",\"url\":\"https://e/x\"}"}`
			acts := activityEvents(extractCopilot(t, body).Events)
			if len(acts) != 1 {
				t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(acts))
			}
			ev := acts[0]
			if ev.EventType != model.EventToolCall {
				t.Fatalf("tool %q classified as %s, want tool.call (unverified verb must not be promoted)", name, ev.EventType)
			}
			if ev.Command != "" || ev.FilePath != "" || ev.URL != "" {
				t.Errorf("tool %q leaked promoted fields cmd=%q file=%q url=%q, want all empty", name, ev.Command, ev.FilePath, ev.URL)
			}
			if len(ev.Tags) != 0 {
				t.Errorf("tool %q carried tags %v, want none (no network promotion)", name, ev.Tags)
			}
		})
	}
}

// A tool argument that lives ONLY under a generic input/args/toolInput key (NOT
// toolArgs/tool_args) must NOT be read: Copilot's contract is that arguments come
// exclusively from toolArgs, so a verified tool name with no real toolArgs but a
// stray generic object stays an empty action — a command.exec with an empty
// command — never a fabricated value pulled from the wrong key. This mirrors the
// live resolver.copilotToolArgs trust list and holds the locked "absent -> empty"
// rule.
func TestExtractCopilotIgnoresGenericArgKeys(t *testing.T) {
	for _, key := range []string{"input", "args", "toolInput"} {
		t.Run(key, func(t *testing.T) {
			body := `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","` + key + `":{"command":"cat .env"}}`
			acts := activityEvents(extractCopilot(t, body).Events)
			if len(acts) != 1 || acts[0].EventType != model.EventCommandExec {
				t.Fatalf("got %+v, want one command.exec", acts)
			}
			if acts[0].Command != "" {
				t.Errorf("command = %q, want empty (a generic %q key must not be read)", acts[0].Command, key)
			}
			if acts[0].Evidence.JSONPointer != "" {
				t.Errorf("pointer = %q, want empty (no toolArgs/tool_args present)", acts[0].Evidence.JSONPointer)
			}
		})
	}
}

// A PostToolUse shell result that reports NO exit code must not fabricate one: a
// clean absence stays nil, distinct from an explicit exit 0.
func TestExtractCopilotNoFabricatedExitCode(t *testing.T) {
	const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolCallId":"s1","toolArgs":"{\"command\":\"echo hi\"}"}
{"hookEventName":"PostToolUse","id":"b","sessionId":"c","toolName":"ShellCommand","toolCallId":"s1"}`
	acts := activityEvents(extractCopilot(t, body).Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(acts))
	}
	if acts[1].EventType != model.EventCommandResult {
		t.Fatalf("result = %s, want command.result", acts[1].EventType)
	}
	if acts[1].ExitCode != nil {
		t.Errorf("exit_code = %v, want nil (none reported, none fabricated)", acts[1].ExitCode)
	}
}

// A malformed line is skipped with a diagnostic, and the surrounding good records
// still parse — the tolerant-parse contract.
func TestExtractCopilotToleratesMalformedLine(t *testing.T) {
	const body = `{"type":"UserPromptSubmitted","id":"u","sessionId":"c","prompt":"hello"}
{not json}
{"type":"assistant","id":"a","sessionId":"c","content":"hi"}`
	res := extractCopilot(t, body)
	if len(res.Diagnostics) != 1 {
		t.Fatalf("got %d diagnostics, want 1: %+v", len(res.Diagnostics), res.Diagnostics)
	}
	acts := activityEvents(res.Events)
	if len(acts) != 2 {
		t.Fatalf("got %d activity events, want 2:\n%s", len(acts), dumpEvents(res.Events))
	}
}

// Evidence.JSONPointer is an RFC 6901 locator back into the SOURCE record, so each
// emitted event points at the field it was actually read from — never a synthetic
// normalized bucket. This pins the pointer for every body spelling and the
// trusted tool-argument keys (toolArgs object/encoded-string, tool_args), and
// proves a generic toolInput/input/args key is NOT a source (empty pointer).
func TestExtractCopilotJSONPointersAreSourceFaithful(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"content_body", `{"type":"assistant","id":"a","sessionId":"c","content":"hi"}`, "/content"},
		{"text_body", `{"type":"assistant","id":"a","sessionId":"c","text":"hi"}`, "/text"},
		{"message_body", `{"type":"assistant","id":"a","sessionId":"c","message":"hi"}`, "/message"},
		{"prompt_body", `{"type":"UserPromptSubmitted","id":"a","sessionId":"c","prompt":"hi"}`, "/prompt"},
		{"toolArgs_object", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolArgs":{"command":"ls"}}`, "/toolArgs"},
		{"toolArgs_encoded_string", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolArgs":"{\"command\":\"ls\"}"}`, "/toolArgs"},
		{"tool_args_snake", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","tool_args":{"command":"ls"}}`, "/tool_args"},
		// A generic toolInput/input/args key is NOT a Copilot argument source, so it
		// is never read: the record stays an empty action with no source pointer.
		{"toolInput_ignored", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolInput":{"command":"ls"}}`, ""},
		{"input_ignored", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","input":{"command":"ls"}}`, ""},
		{"args_ignored", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","args":{"command":"ls"}}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acts := activityEvents(extractCopilot(t, c.body).Events)
			if len(acts) != 1 {
				t.Fatalf("got %d activity events, want 1:\n%s", len(acts), dumpEvents(acts))
			}
			if acts[0].Evidence.JSONPointer != c.want {
				t.Fatalf("pointer = %q, want %q:\n%s", acts[0].Evidence.JSONPointer, c.want, ptrOf(acts))
			}
		})
	}
}

// Both the JSON-encoded-string and the direct-object toolArgs encodings must
// decode to the same command — the worst-realistic Copilot shape and the
// plain-object variant are equivalent to the parser.
func TestExtractCopilotToolArgsEncodingEquivalence(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"encoded_string", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolArgs":"{\"command\":\"cat .env\"}"}`},
		{"direct_object", `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolArgs":{"command":"cat .env"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acts := activityEvents(extractCopilot(t, c.body).Events)
			if len(acts) != 1 || acts[0].EventType != model.EventCommandExec || acts[0].Command != "cat .env" {
				t.Fatalf("got %+v, want one command.exec 'cat .env'", acts)
			}
		})
	}
}

// A malformed toolArgs string decodes to no object, leaving the command field
// empty rather than panicking or fabricating a value.
func TestExtractCopilotMalformedToolArgsDegradesSafely(t *testing.T) {
	const body = `{"hookEventName":"PreToolUse","id":"a","sessionId":"c","toolName":"ShellCommand","toolArgs":"not json at all"}`
	acts := activityEvents(extractCopilot(t, body).Events)
	if len(acts) != 1 || acts[0].EventType != model.EventCommandExec {
		t.Fatalf("got %+v, want one command.exec", acts)
	}
	if acts[0].Command != "" {
		t.Errorf("command = %q, want empty (malformed toolArgs must not fabricate)", acts[0].Command)
	}
}

func TestExtractCopilotAgent(t *testing.T) {
	if got := (CopilotExtractor{}).Agent(); got != model.AgentCopilot {
		t.Errorf("Agent() = %q, want %q", got, model.AgentCopilot)
	}
}

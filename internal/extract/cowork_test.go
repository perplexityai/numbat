package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// coworkFixture is a small Claude Cowork audit.jsonl: a user prompt, an
// assistant turn mixing reasoning (thinking) with a Bash tool_use, and the
// command's result fed back as a user entry. The schema is Claude-Code-style,
// which is exactly why CoworkExtractor reuses the Claude parsing core.
const coworkFixture = `{"type":"user","uuid":"cu1","sessionId":"cw-1","timestamp":"2026-06-03T09:00:00Z","cwd":"/home/dev/proj","message":{"role":"user","content":"run the test suite"}}
{"type":"assistant","uuid":"ca1","sessionId":"cw-1","timestamp":"2026-06-03T09:00:01Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"thinking","thinking":"I should run go test."},{"type":"tool_use","id":"ct1","name":"Bash","input":{"command":"go test ./..."}}]}}
{"type":"user","uuid":"cu2","sessionId":"cw-1","timestamp":"2026-06-03T09:00:05Z","cwd":"/home/dev/proj","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"ct1","content":"ok"}]},"toolUseResult":{"stdout":"ok","exit_code":0}}`

func extractCowork(t *testing.T, body string, includeReasoning bool) *Result {
	t.Helper()
	res, err := CoworkExtractor{}.Extract(strings.NewReader(body), Source{Path: "/cases/audit.jsonl", CaseID: "case-cw", IncludeReasoning: includeReasoning})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	return res
}

// The Cowork parser produces the same normalized event shapes as the Claude
// parser, but every event must carry the cowork source identity and the
// cowork artifact type — never claude-code.
func TestExtractCoworkMapsShapesWithCoworkIdentity(t *testing.T) {
	res := extractCowork(t, coworkFixture, true)
	if len(res.Diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", res.Diagnostics)
	}

	type want struct {
		etype model.EventType
		actor string
		cmd   string
	}
	// Full profile, so the assistant's thinking block surfaces as reasoning.
	wants := []want{
		{model.EventPromptUser, model.ActorUser, ""},
		{model.EventMessageReasoning, model.ActorAssistant, ""},
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

	// Every event — activity and the synthetic session.start/end — must be
	// stamped with the Cowork agent and the Cowork artifact type.
	for _, ev := range res.Events {
		if ev.SourceAgent != model.AgentCowork {
			t.Errorf("event %q source_agent = %q, want %q", ev.EventID, ev.SourceAgent, model.AgentCowork)
		}
		if ev.SourceType != model.SourceArtifact {
			t.Errorf("event %q source_type = %q, want %q", ev.EventID, ev.SourceType, model.SourceArtifact)
		}
		if ev.Evidence.ArtifactType != artifactCoworkJSONL {
			t.Errorf("event %q artifact_type = %q, want %q", ev.EventID, ev.Evidence.ArtifactType, artifactCoworkJSONL)
		}
		if ev.CaseID != "case-cw" {
			t.Errorf("event %q case_id = %q, want case-cw", ev.EventID, ev.CaseID)
		}
	}

	// The exit code rides on the single command.result, proving the shared
	// toolUseResult correlation runs for Cowork too.
	last := acts[len(acts)-1]
	if last.ExitCode == nil || *last.ExitCode != 0 {
		t.Errorf("command.result exit_code = %v, want 0", last.ExitCode)
	}

	assertUniqueEventIDs(t, res.Events)
}

// Reasoning is omitted by default, exactly as in the Claude core.
func TestExtractCoworkDefaultDropsReasoning(t *testing.T) {
	res := extractCowork(t, coworkFixture, false)
	for _, ev := range res.Events {
		if ev.EventType == model.EventMessageReasoning {
			t.Fatalf("reasoning event leaked by default: %+v", ev)
		}
	}
}

func TestExtractCoworkAgent(t *testing.T) {
	if got := (CoworkExtractor{}).Agent(); got != model.AgentCowork {
		t.Errorf("Agent() = %q, want %q", got, model.AgentCowork)
	}
}

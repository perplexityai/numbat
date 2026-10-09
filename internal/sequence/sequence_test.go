package sequence

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

// compile builds the SequenceRules for one test rule set.
func compile(t *testing.T, rules ...rule.Rule) []*rule.SequenceRule {
	t.Helper()
	for i := range rules {
		if rules[i].Version == "" {
			rules[i].Version = "test"
		}
		if rules[i].Title == "" {
			rules[i].Title = rules[i].ID
		}
	}
	eng, err := rule.NewEngine([]rule.Source{{Name: "t", Rules: rules}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng.SequenceRules()
}

// secretThenEgress is the canonical two-step test rule: a .env read followed
// by a curl exec.
func secretThenEgress(mut func(*rule.SequenceSpec)) rule.Rule {
	spec := &rule.SequenceSpec{
		Within: "30m",
		Steps: []rule.SequenceStep{
			{Expr: `event.event_type == "file.read" && event.file_path.contains(".env")`},
			{Expr: `event.event_type == "command.exec" && shell_commands.exists(command, command.name == "curl")`},
		},
	}
	if mut != nil {
		mut(spec)
	}
	return rule.Rule{ID: "seq.secret_egress", Title: "secret then egress", Severity: model.SeverityHigh, Sequence: spec}
}

// ev builds a session-keyed test event. ts may be empty.
func ev(id, ts string, et model.EventType, mut func(*model.Event)) model.Event {
	e := model.Event{
		EventID:     id,
		SourceAgent: model.AgentClaudeCode,
		SourceType:  model.SourceArtifact,
		SessionID:   "sess-1",
		ProjectPath: "/repo/a",
		Timestamp:   ts,
		EventType:   et,
		Confidence:  model.ConfidenceHigh,
		Evidence:    model.Evidence{ArtifactType: "claude_jsonl", LocalPath: "/a/t.jsonl"},
	}
	if mut != nil {
		mut(&e)
	}
	return e
}

func secretRead(id, ts string, mut func(*model.Event)) model.Event {
	return ev(id, ts, model.EventFileRead, func(e *model.Event) {
		e.FilePath = "/repo/a/.env"
		if mut != nil {
			mut(e)
		}
	})
}

func egress(id, ts string, mut func(*model.Event)) model.Event {
	return ev(id, ts, model.EventCommandExec, func(e *model.Event) {
		e.Command = "curl http://example.invalid"
		if mut != nil {
			mut(e)
		}
	})
}

func observeAll(t *testing.T, tr *Tracker, events ...model.Event) []Match {
	t.Helper()
	var all []Match
	for _, e := range events {
		observation, err := tr.Observe(e)
		if err != nil {
			t.Fatalf("Observe(%s): %v", e.EventID, err)
		}
		all = append(all, observation.Findings...)
	}
	return all
}

func TestChainMatchesInOrder(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		egress("e2", "2026-06-01T10:05:00Z", nil),
	)
	if len(ms) != 1 {
		t.Fatalf("matches = %d, want 1", len(ms))
	}
	m := ms[0]
	if m.Rule.ID != "seq.secret_egress" || m.Final.EventID != "e2" {
		t.Fatalf("match = rule %q final %q", m.Rule.ID, m.Final.EventID)
	}
	if len(m.Links) != 2 || m.Links[0].EventID != "e1" || m.Links[1].EventID != "e2" {
		t.Fatalf("links = %+v", m.Links)
	}
}

func TestSequenceStepUsesShellCommands(t *testing.T) {
	r := secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.Steps[1].Expr = `shell_commands.exists(command, command.executable == "crontab")`
	})
	tr := NewTracker(compile(t, r), DefaultConfig())
	if _, err := tr.Observe(secretRead("e1", "2026-06-01T10:00:00Z", nil)); err != nil {
		t.Fatalf("first step: %v", err)
	}
	quoted := ev("e2", "2026-06-01T10:01:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = `echo "crontab /tmp/job"`
	})
	if observation, err := tr.Observe(quoted); err != nil || len(observation.Findings) != 0 {
		t.Fatalf("quoted prose = %+v, %v; want no match", observation, err)
	}
	direct := ev("e3", "2026-06-01T10:02:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = "crontab /tmp/job"
	})
	if observation, err := tr.Observe(direct); err != nil || len(observation.Findings) != 1 {
		t.Fatalf("direct scheduler command = %+v, %v; want one match", observation, err)
	}
}

func TestSequenceFinalStepCanMatchOneCompoundCandidate(t *testing.T) {
	enforce := true
	r := secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.Steps[0].Expr = `shell_commands.exists(command, command.name == "prep")`
		spec.Steps[1].Expr = `shell_commands.filter(command, command.name == "cat").size() == 1 &&
			shell_commands[0].argv[1] == ".env"`
	})
	r.Enforce = &enforce
	tr := NewTracker(compile(t, r), DefaultConfig())

	prep := ev("e1", "2026-06-01T10:00:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = "prep"
	})
	if observation, err := tr.Observe(prep); err != nil || len(observation.Findings) != 0 {
		t.Fatalf("prep observation = %+v, %v", observation, err)
	}
	compound := ev("e2", "2026-06-01T10:01:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = "true; cat .env"
	})
	observation, err := tr.Observe(compound)
	if err == nil {
		t.Fatal("compound observation returned no aggregate evaluation error")
	}
	if len(observation.Findings) != 1 || len(observation.EnforcementRules) != 1 {
		t.Fatalf("compound observation = %+v, want one finding and one enforcement rule", observation)
	}
}

func TestSequenceShellAnalysisErrorIsReported(t *testing.T) {
	r := secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.Steps[0].Expr = `shell_commands.size() == 0`
		spec.Steps[1].Expr = `shell_commands.exists(command, command.name == "finish")`
	})
	tr := NewTracker(compile(t, r), DefaultConfig())
	malformed := ev("e1", "", model.EventCommandExec, func(e *model.Event) {
		e.Command = `echo "unterminated`
	})
	if _, err := tr.Observe(malformed); err == nil || !strings.Contains(err.Error(), "shell command analysis") {
		t.Fatalf("Observe error = %v, want shell analysis error", err)
	}
	finish := ev("e2", "", model.EventCommandExec, func(e *model.Event) {
		e.Command = "finish"
	})
	if observation, err := tr.Observe(finish); err != nil || len(observation.Findings) != 0 || len(observation.EnforcementRules) != 0 {
		t.Fatalf("uncertain helper step seeded a chain: %+v, %v", observation, err)
	}
}

func TestFatalSequenceLinkCannotAuthorizeEnforcement(t *testing.T) {
	enforce := true
	r := secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.Steps[0].Expr = `shell_commands.exists(command, command.name == "write-output")`
		spec.Steps[1].Expr = `shell_commands.exists(command, command.name == "finish")`
	})
	r.Severity = model.SeverityCritical
	r.Enforce = &enforce
	tr := NewTracker(compile(t, r), DefaultConfig())

	partial := ev("e1", "2026-06-01T10:00:00Z", model.EventCommandExec, func(e *model.Event) {
		e.ToolName = "PowerShell"
		e.Command = `Write-Output ready; "unterminated`
	})
	if observation, err := tr.Observe(partial); err == nil || len(observation.Findings) != 0 {
		t.Fatalf("partial observation = %+v, %v; want a diagnostic and no finding", observation, err)
	}
	finish := ev("e2", "2026-06-01T10:01:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = "finish"
	})
	observation, err := tr.Observe(finish)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 1 {
		t.Fatalf("findings = %d, want detection retained", len(observation.Findings))
	}
	if len(observation.EnforcementRules) != 0 {
		t.Fatalf("fatal link authorized enforcement: %+v", observation.EnforcementRules)
	}
}

func TestComplexSequenceLinkCannotAuthorizeEnforcement(t *testing.T) {
	enforce := true
	r := secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.Steps[0].Expr = `shell_commands.exists(command, command.name == "write-output")`
		spec.Steps[1].Expr = `shell_commands.exists(command, command.name == "finish")`
	})
	r.Severity = model.SeverityCritical
	r.Enforce = &enforce
	tr := NewTracker(compile(t, r), DefaultConfig())

	first := ev("e1", "2026-06-01T10:00:00Z", model.EventCommandExec, func(e *model.Event) {
		e.ToolName = "PowerShell"
		e.Command = `Write-Output ready; Write-Output done`
	})
	if observation, err := tr.Observe(first); err != nil || len(observation.Findings) != 0 {
		t.Fatalf("first observation = %+v, %v", observation, err)
	}
	finish := ev("e2", "2026-06-01T10:01:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = "finish"
	})
	observation, err := tr.Observe(finish)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 1 {
		t.Fatalf("findings = %d, want detection retained", len(observation.Findings))
	}
	if len(observation.EnforcementRules) != 0 {
		t.Fatalf("complex link authorized enforcement: %+v", observation.EnforcementRules)
	}
}

func TestEnforcementUsesCertainSequenceWhenOneExists(t *testing.T) {
	enforce := true
	r := secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.Steps[0].Expr = `shell_commands.exists(command, command.name == "write-output")`
		spec.Steps[1].Expr = `shell_commands.exists(command, command.name == "finish")`
	})
	r.Severity = model.SeverityCritical
	r.Enforce = &enforce
	tr := NewTracker(compile(t, r), DefaultConfig())

	partial := ev("e1", "2026-06-01T10:00:00Z", model.EventCommandExec, func(e *model.Event) {
		e.ToolName = "PowerShell"
		e.Command = `Write-Output ready; "unterminated`
	})
	if _, err := tr.Observe(partial); err == nil {
		t.Fatal("partial analysis succeeded, want diagnostic")
	}
	certain := ev("e2", "2026-06-01T10:01:00Z", model.EventCommandExec, func(e *model.Event) {
		e.ToolName = "PowerShell"
		e.Command = "Write-Output ready"
	})
	if _, err := tr.Observe(certain); err != nil {
		t.Fatal(err)
	}
	finish := ev("e3", "2026-06-01T10:02:00Z", model.EventCommandExec, func(e *model.Event) {
		e.Command = "finish"
	})
	observation, err := tr.Observe(finish)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 1 || observation.Findings[0].Links[0].EventID != "e2" {
		t.Fatalf("finding did not cite the certain chain: %+v", observation.Findings)
	}
	if len(observation.EnforcementRules) != 1 {
		t.Fatalf("certain chain did not authorize enforcement: %+v", observation.EnforcementRules)
	}
}

func TestEnforcementIsIndependentOfFindingCap(t *testing.T) {
	enforce := true
	r := secretThenEgress(nil)
	r.Severity = model.SeverityCritical
	r.Enforce = &enforce
	tr := NewTracker(compile(t, r), DefaultConfig())

	if observation, err := tr.Observe(secretRead("e1", "2026-06-01T10:00:00Z", nil)); err != nil || len(observation.Findings) != 0 || len(observation.EnforcementRules) != 0 {
		t.Fatalf("first step = %+v, %v", observation, err)
	}
	first, err := tr.Observe(egress("e2", "2026-06-01T10:01:00Z", nil))
	if err != nil || len(first.Findings) != 1 || len(first.EnforcementRules) != 1 {
		t.Fatalf("first completion = %+v, %v", first, err)
	}
	second, err := tr.Observe(egress("e3", "2026-06-01T10:02:00Z", nil))
	if err != nil || len(second.Findings) != 0 || len(second.EnforcementRules) != 1 {
		t.Fatalf("completion after max_matches = %+v, %v", second, err)
	}
}

func TestSequencePowerShellPreviewsDetectWithoutEnforcement(t *testing.T) {
	enforce := true
	r := rule.Rule{
		ID:       "seq.preview",
		Title:    "preview sequence",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  &enforce,
		Sequence: &rule.SequenceSpec{
			WithinEvents: 4,
			Steps: []rule.SequenceStep{
				{Expr: `shell_commands.exists(command, command.name == "stop-process")`},
				{Expr: `shell_commands.exists(command, command.name == "remove-item")`},
			},
		},
	}
	tests := []struct {
		name  string
		first string
		final string
		block bool
	}{
		{"preview precursor", `Stop-Process -Name * -Force -WhatIf`, `Remove-Item C:\tmp\x -Force`, false},
		{"preview final", `Stop-Process -Name * -Force`, `Remove-Item C:\tmp\x -Force -WhatIf`, false},
		{"normal chain", `Stop-Process -Name * -Force`, `Remove-Item C:\tmp\x -Force`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := NewTracker(compile(t, r), DefaultConfig())
			first := ev("e1", "", model.EventCommandExec, func(event *model.Event) {
				event.ToolName = "PowerShell"
				event.Command = tt.first
			})
			if observation, err := tr.Observe(first); err != nil || len(observation.Findings) != 0 {
				t.Fatalf("first observation = %+v, %v", observation, err)
			}
			final := ev("e2", "", model.EventCommandExec, func(event *model.Event) {
				event.ToolName = "PowerShell"
				event.Command = tt.final
			})
			observation, err := tr.Observe(final)
			if err != nil {
				t.Fatal(err)
			}
			if len(observation.Findings) != 1 {
				t.Fatalf("findings = %+v, want one detection chain", observation.Findings)
			}
			if got := len(observation.EnforcementRules) == 1; got != tt.block {
				t.Fatalf("enforcement = %+v, want block %v", observation.EnforcementRules, tt.block)
			}
		})
	}
}

func TestNoMatchOutOfOrder(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		egress("e1", "2026-06-01T10:00:00Z", nil),
		secretRead("e2", "2026-06-01T10:05:00Z", nil),
	)
	if len(ms) != 0 {
		t.Fatalf("reversed steps must not match, got %+v", ms)
	}
}

func TestNoMatchOutsideWallClockWindow(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		egress("e2", "2026-06-01T10:31:00Z", nil), // 31m > within: 30m
	)
	if len(ms) != 0 {
		t.Fatalf("chain outside within must not match, got %+v", ms)
	}
}

func TestWallClockWindowBoundaryInclusive(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		egress("e2", "2026-06-01T10:30:00Z", nil), // exactly 30m
	)
	if len(ms) != 1 {
		t.Fatalf("boundary chain should match, got %d", len(ms))
	}
}

func TestNoMatchMissingTimestampWithWallClockWindow(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "", nil),
		egress("e2", "2026-06-01T10:05:00Z", nil),
	)
	if len(ms) != 0 {
		t.Fatalf("unverifiable window must not match, got %+v", ms)
	}
}

func TestNoMatchDisorderedTimestamps(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T11:00:00Z", nil), // later than the egress
		egress("e2", "2026-06-01T10:00:00Z", nil),
	)
	if len(ms) != 0 {
		t.Fatalf("disordered timestamps must fail closed, got %+v", ms)
	}
}

func TestEventCountWindow(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 3 // chain must fit in 3 consecutive events
	})
	noise := func(id string) model.Event { return ev(id, "", model.EventPromptUser, nil) }

	tr := NewTracker(compile(t, r), DefaultConfig())
	if ms := observeAll(t, tr, secretRead("e1", "", nil), noise("n1"), egress("e2", "", nil)); len(ms) != 1 {
		t.Fatalf("span-3 chain should match within_events=3, got %d", len(ms))
	}

	tr = NewTracker(compile(t, r), DefaultConfig())
	if ms := observeAll(t, tr, secretRead("e1", "", nil), noise("n1"), noise("n2"), egress("e2", "", nil)); len(ms) != 0 {
		t.Fatalf("span-4 chain must not match within_events=3, got %d", len(ms))
	}
}

func TestBothWindowsMustHold(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) { s.WithinEvents = 2 })
	tr := NewTracker(compile(t, r), DefaultConfig())
	// In wall-clock window but one noise event apart: event window (2) fails.
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		ev("n1", "2026-06-01T10:01:00Z", model.EventPromptUser, nil),
		egress("e2", "2026-06-01T10:02:00Z", nil),
	)
	if len(ms) != 0 {
		t.Fatalf("AND of windows must hold, got %+v", ms)
	}
}

func TestMaxMatchesDefaultOnePerRuleSession(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		egress("e2", "2026-06-01T10:01:00Z", nil),
		egress("e3", "2026-06-01T10:02:00Z", nil), // second trigger: quiet
	)
	if len(ms) != 1 {
		t.Fatalf("default max_matches=1 must emit once, got %d", len(ms))
	}
}

func TestMaxMatchesTwoEmitsTwoCanonicalChains(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) { s.MaxMatches = 2 })
	tr := NewTracker(compile(t, r), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		egress("e2", "2026-06-01T10:01:00Z", nil),
		egress("e3", "2026-06-01T10:02:00Z", nil),
		egress("e4", "2026-06-01T10:03:00Z", nil), // over the cap: quiet
	)
	if len(ms) != 2 {
		t.Fatalf("max_matches=2 should emit twice, got %d", len(ms))
	}
	if ms[0].Final.EventID != "e2" || ms[1].Final.EventID != "e3" {
		t.Fatalf("finals = %q, %q", ms[0].Final.EventID, ms[1].Final.EventID)
	}
	// Both canonical chains anchor on the earliest valid first step.
	if ms[0].Links[0].EventID != "e1" || ms[1].Links[0].EventID != "e1" {
		t.Fatalf("first links = %q, %q, want e1 both", ms[0].Links[0].EventID, ms[1].Links[0].EventID)
	}
}

func TestCanonicalChainUsesEarliestValidFirstStep(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("old", "2026-06-01T08:00:00Z", nil), // outside 30m of the egress
		secretRead("e1", "2026-06-01T10:00:00Z", nil),  // earliest VALID first step
		secretRead("e2", "2026-06-01T10:01:00Z", nil),
		egress("e3", "2026-06-01T10:05:00Z", nil),
	)
	if len(ms) != 1 {
		t.Fatalf("matches = %d, want 1", len(ms))
	}
	if got := ms[0].Links[0].EventID; got != "e1" {
		t.Fatalf("first link = %q, want the earliest in-window candidate e1", got)
	}
}

func TestThreeStepChainWithNoise(t *testing.T) {
	r := rule.Rule{ID: "seq.three", Severity: model.SeverityMedium, Sequence: &rule.SequenceSpec{
		WithinEvents: 16,
		Steps: []rule.SequenceStep{
			{Expr: `event.event_type == "config.mcp"`},
			{Expr: `event.event_type == "file.read"`},
			{Expr: `event.event_type == "command.exec"`},
		},
	}}
	tr := NewTracker(compile(t, r), DefaultConfig())
	ms := observeAll(t, tr,
		ev("e1", "", model.EventConfigMCP, nil),
		ev("n1", "", model.EventPromptUser, nil),
		ev("e2", "", model.EventFileRead, nil),
		ev("n2", "", model.EventMessageAssistant, nil),
		ev("e3", "", model.EventCommandExec, nil),
	)
	if len(ms) != 1 || len(ms[0].Links) != 3 {
		t.Fatalf("matches = %+v", ms)
	}
	want := []string{"e1", "e2", "e3"}
	for i, l := range ms[0].Links {
		if l.EventID != want[i] {
			t.Fatalf("link %d = %q, want %q", i, l.EventID, want[i])
		}
	}
}

// The §precision negative tests: a chain must never assemble across sessions,
// projects, artifacts, or sensor source types.
func TestNoCrossPartitionMerge(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*model.Event) // applied to the SECOND (egress) event
	}{
		{"different session id", func(e *model.Event) { e.SessionID = "sess-2" }},
		{"same session, different project", func(e *model.Event) { e.ProjectPath = "/repo/b" }},
		{"same session, different artifact", func(e *model.Event) { e.Evidence.LocalPath = "/b/other.jsonl" }},
		{"different source type", func(e *model.Event) { e.SourceType = model.SourceHook }},
		{"different agent", func(e *model.Event) { e.SourceAgent = model.AgentCodex }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
			ms := observeAll(t, tr,
				secretRead("e1", "2026-06-01T10:00:00Z", nil),
				egress("e2", "2026-06-01T10:05:00Z", tc.mut),
			)
			if len(ms) != 0 {
				t.Fatalf("cross-partition chain must not match, got %+v", ms)
			}
		})
	}
}

func TestNoMergeAcrossArtifactsWhenSessionEmpty(t *testing.T) {
	noSession := func(e *model.Event) { e.SessionID = "" }
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", noSession),
		egress("e2", "2026-06-01T10:05:00Z", func(e *model.Event) {
			noSession(e)
			e.Evidence.LocalPath = "/b/other.jsonl"
		}),
	)
	if len(ms) != 0 {
		t.Fatalf("empty-session events from two artifacts must not merge, got %+v", ms)
	}

	// Control: same artifact, still no session id — the chain is real.
	tr = NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	ms = observeAll(t, tr,
		secretRead("e1", "2026-06-01T10:00:00Z", noSession),
		egress("e2", "2026-06-01T10:05:00Z", noSession),
	)
	if len(ms) != 1 {
		t.Fatalf("same-artifact empty-session chain should match, got %d", len(ms))
	}
}

func TestHookEventsWithoutSessionIDDoNotChainByCWD(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 8
	})
	noSessionHook := func(e *model.Event) {
		e.SourceType = model.SourceHook
		e.SessionID = ""
		e.Evidence = model.Evidence{ArtifactType: "hook", LocalPath: "/home/dev/proj"}
		e.ProjectPath = "/home/dev/proj"
	}
	tr := NewTracker(compile(t, r), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "", noSessionHook),
		egress("e2", "", noSessionHook),
	)
	if len(ms) != 0 {
		t.Fatalf("hook events without session id must not chain by cwd, got %+v", ms)
	}
}

func TestHookEventsWithSessionIDStillChain(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 8
	})
	hookSession := func(id string) func(*model.Event) {
		return func(e *model.Event) {
			e.SourceType = model.SourceHook
			e.SessionID = id
			e.Evidence = model.Evidence{ArtifactType: "hook", LocalPath: "/home/dev/proj"}
			e.ProjectPath = "/home/dev/proj"
		}
	}
	tr := NewTracker(compile(t, r), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "", hookSession("sess-1")),
		egress("e2", "", hookSession("sess-1")),
	)
	if len(ms) != 1 {
		t.Fatalf("hook events with a real session id should chain, got %d", len(ms))
	}
}

func TestOTelEventsWithoutSessionIDDoNotChain(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 8
	})
	noSessionOTel := func(e *model.Event) {
		e.SourceType = model.SourceOTel
		e.SessionID = ""
		e.Evidence = model.Evidence{ArtifactType: "otel"}
		e.ProjectPath = ""
	}
	tr := NewTracker(compile(t, r), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "", noSessionOTel),
		egress("e2", "", noSessionOTel),
	)
	if len(ms) != 0 {
		t.Fatalf("otel events without session id must not chain on a shared empty key, got %+v", ms)
	}
}

func TestOTelEventsWithSessionIDStillChain(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 8
	})
	otelSession := func(id string) func(*model.Event) {
		return func(e *model.Event) {
			e.SourceType = model.SourceOTel
			e.SessionID = id
			e.Evidence = model.Evidence{ArtifactType: "otel"}
			e.ProjectPath = ""
		}
	}
	tr := NewTracker(compile(t, r), DefaultConfig())
	ms := observeAll(t, tr,
		secretRead("e1", "", otelSession("sess-1")),
		egress("e2", "", otelSession("sess-1")),
	)
	if len(ms) != 1 {
		t.Fatalf("otel events with a real session id should chain, got %d", len(ms))
	}
}

func TestRingEvictionIsDocumentedFalseNegative(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 4
	})
	tr := NewTracker(compile(t, r), Config{MaxEvents: 4, MaxSessions: 8})
	events := []model.Event{secretRead("e1", "", nil)}
	for i := 0; i < 4; i++ { // push the secret read out of the 4-slot ring
		events = append(events, ev(fmt.Sprintf("n%d", i), "", model.EventPromptUser, nil))
	}
	events = append(events, egress("e2", "", nil))
	if ms := observeAll(t, tr, events...); len(ms) != 0 {
		t.Fatalf("evicted first step must not match, got %+v", ms)
	}
}

func TestTrackerRaisesRingToDeclaredEventWindow(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 8
	})
	// Configured ring (4) is smaller than the declared window (8): NewTracker
	// must raise the ring so the rule's own window never silently truncates.
	tr := NewTracker(compile(t, r), Config{MaxEvents: 4, MaxSessions: 8})
	events := []model.Event{secretRead("e1", "", nil)}
	for i := 0; i < 6; i++ {
		events = append(events, ev(fmt.Sprintf("n%d", i), "", model.EventPromptUser, nil))
	}
	events = append(events, egress("e2", "", nil)) // span 8 == within_events
	if ms := observeAll(t, tr, events...); len(ms) != 1 {
		t.Fatalf("declared window must fit the ring, got %d matches", len(ms))
	}
}

func TestSessionLRUEviction(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), Config{MaxEvents: 16, MaxSessions: 2})
	inSession := func(e model.Event, sess string) model.Event {
		e.SessionID = sess
		return e
	}
	observeAll(t, tr,
		inSession(secretRead("a1", "2026-06-01T10:00:00Z", nil), "A"),
		inSession(secretRead("b1", "2026-06-01T10:00:30Z", nil), "B"),
		inSession(secretRead("c1", "2026-06-01T10:01:00Z", nil), "C"), // evicts A
	)
	// B is still tracked (check it BEFORE touching A — re-observing the
	// evicted A would re-create it and evict B in turn).
	msB := observeAll(t, tr, inSession(egress("b2", "2026-06-01T10:02:30Z", nil), "B"))
	if len(msB) != 1 {
		t.Fatalf("session B was evicted prematurely: %d matches", len(msB))
	}
	msA := observeAll(t, tr, inSession(egress("a2", "2026-06-01T10:03:00Z", nil), "A"))
	if len(msA) != 0 {
		t.Fatalf("evicted session A must have lost its window, got %+v", msA)
	}
}

func TestDuplicateChainSuppressedOnReobservation(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) { s.MaxMatches = 4 })
	tr := NewTracker(compile(t, r), DefaultConfig())
	stream := []model.Event{
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		egress("e2", "2026-06-01T10:01:00Z", nil),
	}
	first := observeAll(t, tr, stream...)
	again := observeAll(t, tr, stream...) // same events re-observed (e.g. re-delivery)
	if len(first) != 1 || len(again) != 0 {
		t.Fatalf("identical chain re-emitted: first=%d again=%d", len(first), len(again))
	}
}

func TestDuplicateEventCannotCompleteOverlappingSteps(t *testing.T) {
	r := rule.Rule{ID: "seq.same-shape", Severity: model.SeverityLow, Sequence: &rule.SequenceSpec{
		WithinEvents: 8,
		Steps: []rule.SequenceStep{
			{Expr: `event.event_type == "command.exec"`},
			{Expr: `event.event_type == "command.exec"`},
		},
	}}
	tr := NewTracker(compile(t, r), DefaultConfig())
	e := ev("e1", "2026-06-01T10:00:00Z", model.EventCommandExec, nil)
	if ms := observeAll(t, tr, e, e); len(ms) != 0 {
		t.Fatalf("duplicate event completed a sequence: %+v", ms)
	}
	if ms := observeAll(t, tr, ev("e2", "2026-06-01T10:00:01Z", model.EventCommandExec, nil)); len(ms) != 1 {
		t.Fatalf("distinct second event did not complete sequence: %+v", ms)
	}
}

func TestStepEvalErrorSuppressesNeverFabricates(t *testing.T) {
	r := rule.Rule{ID: "seq.err", Severity: model.SeverityLow, Sequence: &rule.SequenceSpec{
		WithinEvents: 8,
		Steps: []rule.SequenceStep{
			{Expr: `event.command[10] == "x"`}, // runtime error on short commands
			{Expr: `event.event_type == "command.exec"`},
		},
	}}
	tr := NewTracker(compile(t, r), DefaultConfig())
	_, err := tr.Observe(ev("e1", "", model.EventFileRead, func(e *model.Event) { e.Command = "x" }))
	if err == nil {
		t.Fatal("want joined step-eval error")
	}
	observation, err := tr.Observe(ev("e2", "", model.EventCommandExec, func(e *model.Event) { e.Command = "y" }))
	if err == nil {
		t.Fatal("want joined step-eval error on second event")
	}
	if len(observation.Findings) != 0 {
		t.Fatalf("erroring step must count as false, got %+v", observation.Findings)
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	r := secretThenEgress(func(s *rule.SequenceSpec) { s.MaxMatches = 3 })
	stream := []model.Event{
		secretRead("e1", "2026-06-01T10:00:00Z", nil),
		ev("n1", "2026-06-01T10:00:30Z", model.EventPromptUser, nil),
		egress("e2", "2026-06-01T10:01:00Z", nil),
		secretRead("e3", "2026-06-01T10:02:00Z", nil),
		egress("e4", "2026-06-01T10:03:00Z", nil),
	}
	run := func() []Match {
		tr := NewTracker(compile(t, r), DefaultConfig())
		return observeAll(t, tr, stream...)
	}
	a, b := run(), run()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("matches differ across identical runs:\n%+v\n%+v", a, b)
	}
	if len(a) != 2 {
		t.Fatalf("matches = %d, want 2", len(a))
	}
}

func TestObserveConcurrentSessions(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(nil)), DefaultConfig())
	const (
		workers    = 8
		iterations = 50
	)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total int
	)
	errs := make(chan error, workers*iterations*2)
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			sess := fmt.Sprintf("sess-%d", g)
			withSess := func(e *model.Event) { e.SessionID = sess }
			for i := 0; i < iterations; i++ {
				ms1, err := tr.Observe(secretRead(fmt.Sprintf("r-%d-%d", g, i), "2026-06-01T10:00:00Z", withSess))
				if err != nil {
					errs <- fmt.Errorf("session %s iteration %d first step: %w", sess, i, err)
				}
				ms2, err := tr.Observe(egress(fmt.Sprintf("c-%d-%d", g, i), "2026-06-01T10:01:00Z", withSess))
				if err != nil {
					errs <- fmt.Errorf("session %s iteration %d second step: %w", sess, i, err)
				}
				mu.Lock()
				total += len(ms1.Findings) + len(ms2.Findings)
				mu.Unlock()
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if total != workers { // one canonical match per session
		t.Fatalf("total matches = %d, want %d", total, workers)
	}
}

func TestKeyPartitions(t *testing.T) {
	base := secretRead("e", "", nil)
	same := secretRead("e2", "", nil)
	if sessionKey(base) != sessionKey(same) {
		t.Fatal("same partition must share a key")
	}
	variants := []func(*model.Event){
		func(e *model.Event) { e.SourceAgent = model.AgentCodex },
		func(e *model.Event) { e.SourceType = model.SourceHook },
		func(e *model.Event) { e.SessionID = "other" },
		func(e *model.Event) { e.ProjectPath = "/repo/b" },
		func(e *model.Event) { e.Evidence.LocalPath = "/b/other.jsonl" },
		func(e *model.Event) { e.Evidence.LocalPath = "/a/dir/../t.jsonl" },
	}
	for i, mut := range variants {
		v := secretRead("e3", "", mut)
		if sessionKey(v) == sessionKey(base) {
			t.Errorf("variant %d must not share the key", i)
		}
	}
	// Raw project and artifact paths never appear in the key.
	if k := sessionKey(base); strings.Contains(k, "/repo/a") || strings.Contains(k, "/a/t.jsonl") {
		t.Errorf("key leaks a raw path: %q", k)
	}
}

func TestLiveSessionKeyFormatStable(t *testing.T) {
	ev := secretRead("e", "", func(e *model.Event) {
		e.SourceType = model.SourceHook
		e.Evidence = model.Evidence{ArtifactType: "hook"}
	})
	want := model.AgentClaudeCode + "\x00" + model.SourceHook + "\x00sess-1\x00" + model.HashPath("/repo/a")
	if got := sessionKey(ev); got != want {
		t.Fatalf("live session key = %q, want legacy format %q", got, want)
	}
}

func TestHookEmptySessionSkipsCorrelationKey(t *testing.T) {
	ev := secretRead("e", "", func(e *model.Event) {
		e.SourceType = model.SourceHook
		e.SessionID = ""
		e.Evidence = model.Evidence{ArtifactType: "hook", LocalPath: "/home/dev/proj"}
		e.ProjectPath = "/home/dev/proj"
	})
	if got := sessionKey(ev); got != "" {
		t.Fatalf("hook empty-session key = %q, want empty", got)
	}
}

func TestOTelEmptySessionSkipsCorrelationKey(t *testing.T) {
	ev := secretRead("e", "", func(e *model.Event) {
		e.SourceType = model.SourceOTel
		e.SessionID = ""
		e.Evidence = model.Evidence{ArtifactType: "otel"}
		e.ProjectPath = ""
	})
	if got := sessionKey(ev); got != "" {
		t.Fatalf("otel empty-session key = %q, want empty", got)
	}
}

func TestPathlessArtifactSkipsCorrelationKey(t *testing.T) {
	for _, sessionID := range []string{"", "sess-1"} {
		ev := secretRead("e", "", func(e *model.Event) {
			e.SessionID = sessionID
			e.Evidence.LocalPath = ""
		})
		if got := sessionKey(ev); got != "" {
			t.Fatalf("pathless artifact with session %q key = %q, want empty", sessionID, got)
		}
	}
}

func TestTrackerCopiesBufferedTags(t *testing.T) {
	tr := NewTracker(compile(t, secretThenEgress(func(spec *rule.SequenceSpec) {
		spec.MaxMatches = 2
	})), DefaultConfig())
	first := secretRead("e1", "2026-06-01T10:00:00Z", nil)
	first.Tags = []string{"secret"}
	if _, err := tr.Observe(first); err != nil {
		t.Fatal(err)
	}
	first.Tags[0] = "mutated"
	observation, err := tr.Observe(egress("e2", "2026-06-01T10:01:00Z", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 1 || len(observation.Findings[0].Links) == 0 || observation.Findings[0].Links[0].Tags[0] != "secret" {
		t.Fatalf("buffered tags changed through caller slice: %+v", observation.Findings)
	}
	observation.Findings[0].Links[0].Tags[0] = "returned mutation"
	next, err := tr.Observe(egress("e3", "2026-06-01T10:02:00Z", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Findings) != 1 || next.Findings[0].Links[0].Tags[0] != "secret" {
		t.Fatalf("buffered tags changed through returned link: %+v", next.Findings)
	}
}

package rule

import (
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// seqSpec returns a minimal valid two-step sequence for mutation in tests.
func seqSpec() *SequenceSpec {
	return &SequenceSpec{
		Within: "30m",
		Steps: []SequenceStep{
			{Expr: `event.event_type == "file.read" && event.file_path.contains(".env")`},
			{Expr: `event.event_type == "command.exec" && shell_commands.exists(command, command.name == "curl")`},
		},
	}
}

func seqRule(mut func(*Rule)) Rule {
	r := Rule{ID: "seq.t", Title: "t", Severity: model.SeverityHigh, Version: "1.0", Sequence: seqSpec()}
	if mut != nil {
		mut(&r)
	}
	return r
}

func TestSequenceRuleCompiles(t *testing.T) {
	eng := mustEngine(t, seqRule(nil))
	seqs := eng.SequenceRules()
	if len(seqs) != 1 {
		t.Fatalf("SequenceRules = %d, want 1", len(seqs))
	}
	s := seqs[0]
	if s.Rule().ID != "seq.t" || s.StepCount() != 2 {
		t.Fatalf("compiled = id %q steps %d", s.Rule().ID, s.StepCount())
	}
	if s.Within() != 30*time.Minute || s.WithinEvents() != 0 {
		t.Fatalf("window = %v / %d", s.Within(), s.WithinEvents())
	}
	if s.MaxMatches() != defaultSequenceMatches {
		t.Fatalf("maxMatches = %d, want default %d", s.MaxMatches(), defaultSequenceMatches)
	}
	if eng.Len() != 1 || eng.RuleIDs()[0] != "seq.t" {
		t.Fatalf("sequence rule missing from Len/RuleIDs: %d %v", eng.Len(), eng.RuleIDs())
	}
}

func TestSequenceRuleContentUsageIsReported(t *testing.T) {
	eng := mustEngine(t, seqRule(func(r *Rule) {
		r.Sequence.Steps[0].Expr = `event.event_type == "prompt.user" && event.content.contains("needle")`
	}))
	if !eng.UsesContent() {
		t.Fatal("UsesContent = false for content sequence")
	}
}

func TestSequenceRuleCanBeEnforceEligible(t *testing.T) {
	eng := mustEngine(t, seqRule(func(r *Rule) {
		r.Severity = model.SeverityMedium
		r.Enforce = boolPtr(true)
	}))
	if got := eng.SequenceRules()[0].Rule(); !got.IsEnforceEligible() {
		t.Fatalf("medium sequence with enforce=true is not eligible: %+v", got)
	}
}

func TestSequenceRuleSkippedBySingleEventEval(t *testing.T) {
	eng := mustEngine(t, seqRule(nil))
	// An event matching the first step alone must not produce a single-event match.
	ev := model.Event{EventID: "e1", EventType: model.EventFileRead, FilePath: "/p/.env"}
	matches, err := eng.Eval(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("Eval must skip sequence rules, got %+v", matches)
	}
}

func TestSequenceShellAnalysisSkippedBySingleEventEval(t *testing.T) {
	eng := mustEngine(t, seqRule(func(r *Rule) {
		r.Sequence.Steps[0].Expr = `shell_commands.exists(command, command.executable == "danger")`
	}))
	matches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		Command:   `echo "unterminated`,
	})
	if err != nil {
		t.Fatalf("Eval parsed a sequence-only helper: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("Eval must skip sequence rules, got %+v", matches)
	}
}

func TestSequenceEvalStep(t *testing.T) {
	s := mustEngine(t, seqRule(nil)).SequenceRules()[0]
	readEvent := model.Event{EventType: model.EventFileRead, FilePath: "/p/.env"}
	execEvent := model.Event{EventType: model.EventCommandExec, Command: "curl http://x"}
	read := PrepareSequenceActivations(readEvent, []*SequenceRule{s}).Detection
	exec := PrepareSequenceActivations(execEvent, []*SequenceRule{s}).Detection
	for _, tc := range []struct {
		step int
		act  map[string]any
		want bool
	}{
		{0, read, true},
		{0, exec, false},
		{1, exec, true},
		{1, read, false},
	} {
		got, err := s.EvalStep(tc.step, tc.act)
		if err != nil {
			t.Fatalf("step %d: %v", tc.step, err)
		}
		if got != tc.want {
			t.Errorf("step %d = %v, want %v", tc.step, got, tc.want)
		}
	}
}

func TestSequenceStepBounds(t *testing.T) {
	s := mustEngine(t, seqRule(nil)).SequenceRules()[0]
	for _, step := range []int{-1, s.StepCount()} {
		if got, err := s.EvalStep(step, nil); err == nil || got {
			t.Fatalf("EvalStep(%d) = %v, %v; want false and error", step, got, err)
		}
		if s.StepUsesShellCommands(step) {
			t.Fatalf("StepUsesShellCommands(%d) = true, want false", step)
		}
	}
}

func TestSequenceValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Rule)
		want string
	}{
		{"both expr and sequence", func(r *Rule) { r.Expr = "true" }, "mutually exclusive"},
		{"one step", func(r *Rule) { r.Sequence.Steps = r.Sequence.Steps[:1] }, "steps"},
		{"nine steps", func(r *Rule) {
			r.Sequence.Steps = make([]SequenceStep, 9)
			for i := range r.Sequence.Steps {
				r.Sequence.Steps[i].Expr = "true"
			}
		}, "steps"},
		{"empty step expr", func(r *Rule) { r.Sequence.Steps[1].Expr = "" }, "step 2: empty expr"},
		{"no window", func(r *Rule) { r.Sequence.Within = "" }, "window"},
		{"bad within", func(r *Rule) { r.Sequence.Within = "soon" }, "invalid within"},
		{"negative within", func(r *Rule) { r.Sequence.Within = "-5m" }, "must be positive"},
		{"negative within_events", func(r *Rule) { r.Sequence.WithinEvents = -1 }, "cannot be negative"},
		{"within_events over cap", func(r *Rule) { r.Sequence.WithinEvents = maxWithinEvents + 1 }, "cap"},
		{"within_events under steps", func(r *Rule) {
			r.Sequence.Within = ""
			r.Sequence.WithinEvents = 1
		}, "cannot hold"},
		{"max_matches over cap", func(r *Rule) { r.Sequence.MaxMatches = maxSequenceMatches + 1 }, "max_matches"},
		{"non-boolean step", func(r *Rule) { r.Sequence.Steps[0].Expr = "event.command" }, "boolean"},
		{"unknown field in step", func(r *Rule) { r.Sequence.Steps[0].Expr = `event.file_pathh == "x"` }, "unknown event field"},
		{"unknown indexed field in step", func(r *Rule) { r.Sequence.Steps[0].Expr = `event["file_pathh"] == "x"` }, "unknown event field"},
		{"uncompilable step", func(r *Rule) { r.Sequence.Steps[0].Expr = "event.nope(" }, "step 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEngine([]Source{{Name: "t", Rules: []Rule{seqRule(tc.mut)}}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSequenceBothWindowsAccepted(t *testing.T) {
	eng := mustEngine(t, seqRule(func(r *Rule) {
		r.Sequence.WithinEvents = 64
		r.Sequence.MaxMatches = 3
	}))
	s := eng.SequenceRules()[0]
	if s.Within() != 30*time.Minute || s.WithinEvents() != 64 || s.MaxMatches() != 3 {
		t.Fatalf("compiled window = %v / %d / %d", s.Within(), s.WithinEvents(), s.MaxMatches())
	}
}

func TestLoadSourceSequenceYAML(t *testing.T) {
	const y = `
id: chain.secret_then_egress
version: "1.0"
title: Secret read then egress
severity: high
sequence:
  within: 30m
  within_events: 64
  steps:
    - expr: 'event.event_type == "file.read"'
    - expr: 'event.event_type == "command.exec"'
`
	p, err := LoadSource(strings.NewReader(y), "chains.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 || p.Rules[0].Sequence == nil || len(p.Rules[0].Sequence.Steps) != 2 {
		t.Fatalf("source = %+v", p)
	}
	if _, err := NewEngine([]Source{p}); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestLoadSourceSequenceUnknownStepFieldRejected(t *testing.T) {
	const y = `
id: chain.x
version: "1.0"
severity: high
sequence:
  within: 5m
  steps:
    - expr: 'true'
      match_kind: bogus
    - expr: 'true'
`
	_, err := LoadSource(strings.NewReader(y), "chains.yaml")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("want strict-decode error for unknown step field, got %v", err)
	}
}

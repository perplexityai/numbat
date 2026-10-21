package rule

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestDecisionRuleIsASeparateCatalogType(t *testing.T) {
	yaml := `id: local.decision
version: "1"
title: Synthetic classification
severity: high
enforce: true
decision:
  select: 'event.event_type == "tool.call"'
  instructions: Classify the visible input.
  options: {violation: Prohibited, unknown: Insufficient evidence}
  match_option: violation
  abstain_option: unknown
  match_threshold: 0.95
  deny_threshold: 0.99
`
	source, err := LoadSource(strings.NewReader(yaml), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := engine.Eval(model.Event{EventType: model.EventToolCall})
	if err != nil || len(matches) != 0 || engine.HasDeterministicEnforcement() {
		t.Fatalf("selector became a deterministic finding: %v %v", matches, err)
	}
	rules := engine.DecisionRules()
	if len(rules) != 1 || !rules[0].IsEnforceEligible() {
		t.Fatalf("catalog lost decision rule: %+v", rules)
	}
	rules[0].Decision.Options["violation"] = "changed"
	if engine.DecisionRules()[0].Decision.Options["violation"] == "changed" {
		t.Fatal("mutable catalog alias")
	}
	for _, suffix := range []string{"\nexpr: 'true'\n", "\nsequence:\n  steps: []\n"} {
		bad, err := LoadSource(strings.NewReader(yaml+suffix), "test.yaml")
		if err == nil {
			_, err = NewEngine([]Source{bad})
		}
		if err == nil {
			t.Fatal("mixed rule shapes accepted")
		}
	}
	for _, value := range []string{"0.5", "0.94", "1.01"} {
		bad, err := LoadSource(strings.NewReader(strings.Replace(yaml, "deny_threshold: 0.99", "deny_threshold: "+value, 1)), "test.yaml")
		if err == nil {
			_, err = NewEngine([]Source{bad})
		}
		if err == nil {
			t.Fatalf("bad enforcement threshold %s", value)
		}
	}
}

func TestDecisionShellAnalysisSkippedBySingleEventEval(t *testing.T) {
	r := Rule{
		ID: "local.shell_decision", Version: "1", Title: "Synthetic", Severity: "high",
		Decision: &DecisionSpec{
			Select:       `shell_commands.exists(command, command.executable == "danger")`,
			Instructions: "Classify the observed action.",
			Options:      map[string]string{"violation": "Prohibited", "unknown": "Insufficient evidence"},
			MatchOption:  "violation", AbstainOption: "unknown", MatchThreshold: .9,
		},
	}
	local := Rule{ID: "local.deterministic", Version: "1", Title: "Synthetic", Severity: "high", Expr: "true"}
	eng := mustEngine(t, r, local)
	ev := model.Event{EventType: model.EventCommandExec, Command: `echo "unterminated`}
	matches, err := eng.Eval(ev)
	if err != nil || len(matches) != 1 || matches[0].Rule.ID != local.ID {
		t.Fatalf("inactive decision selector affected local rules: matches=%v err=%v", matches, err)
	}
	local.Expr = r.Decision.Select
	if _, err := mustEngine(t, local).Eval(ev); err == nil {
		t.Fatal("active deterministic shell predicate skipped analysis")
	}
}

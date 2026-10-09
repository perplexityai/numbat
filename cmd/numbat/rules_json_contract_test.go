package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

func jsonTestEngine(t *testing.T, rules ...rule.Rule) *rule.Engine {
	t.Helper()
	for i := range rules {
		rules[i].Title = rules[i].ID
		rules[i].Version = "1.0"
		rules[i].Severity = model.SeverityHigh
	}
	eng, err := rule.NewEngine([]rule.Source{{Name: "synthetic", Rules: rules}})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func jsonTestFixture(t *testing.T, commands ...string) string {
	t.Helper()
	var fixture strings.Builder
	for i, command := range commands {
		ev := model.Event{
			SchemaVersion: model.SchemaVersion, EventID: fmt.Sprintf("e%d", i+1),
			SourceAgent: "claude-code", SourceType: model.SourceArtifact,
			EventType: model.EventCommandExec, Command: command, SessionID: "synthetic",
			Confidence: model.ConfidenceHigh,
			Evidence:   model.Evidence{ArtifactType: "claude_jsonl", LocalPath: "/synthetic", Line: i + 1},
		}
		if err := json.NewEncoder(&fixture).Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return fixture.String()
}

func TestRulesTestJSONSequenceResults(t *testing.T) {
	enforce := true
	for _, tc := range []struct {
		name       string
		broken     bool
		enforce    *bool
		wantCode   int
		wantEvents int
	}{
		{name: "enforcement after finding cap", enforce: &enforce, wantEvents: 3},
		{name: "independent sequence error", broken: true, enforce: &enforce, wantCode: 1, wantEvents: 2},
		{name: "advisory after finding cap", wantEvents: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []rule.Rule{{
				ID: "test.chain", Enforce: tc.enforce,
				Sequence: &rule.SequenceSpec{WithinEvents: 8, Steps: []rule.SequenceStep{
					{Expr: `event.command == "start"`},
					{Expr: `event.command == "finish"`},
				}},
			}}
			if tc.broken {
				rules = append(rules, rule.Rule{ID: "test.broken", Sequence: &rule.SequenceSpec{
					WithinEvents: 8, Steps: []rule.SequenceStep{
						{Expr: `event.command == "finish" && event.tags[99] == "x"`},
						{Expr: `false`},
					},
				}})
			}
			var out, stderr strings.Builder
			code := runRulesTestJSON(jsonTestEngine(t, rules...), strings.NewReader(jsonTestFixture(t, "start", "finish", "finish")), &out, &stderr, true, false, nil)
			events, summary := parseJSONStream(t, out.String())
			if code != tc.wantCode || len(events) != tc.wantEvents || summary.Matches != 1 || summary.EventsEvaluated != tc.wantEvents {
				t.Fatalf("exit=%d stderr=%s stream=%s", code, stderr.String(), out.String())
			}
			if len(events[0].Findings) != 0 || len(events[0].EnforcementRules) != 0 || len(events[1].Findings) != 1 {
				t.Fatalf("incorrect chain attribution: %+v", events)
			}
			for _, ev := range events[1:] {
				if tc.enforce == nil {
					if len(ev.EnforcementRules) != 0 {
						t.Fatalf("advisory rule became eligible: %+v", ev)
					}
					continue
				}
				if len(ev.EnforcementRules) != 1 || ev.EnforcementRules[0].RuleID != "test.chain" ||
					ev.EnforcementRules[0].RuleVersion != "1.0" || ev.EnforcementRules[0].Via != "sequence" ||
					!ev.EnforcementRules[0].EnforcementEligible {
					t.Fatalf("missing uncapped enforcement result: %+v", ev)
				}
			}
			if tc.broken {
				if events[1].Status != "evaluation_failure" || events[1].Error == nil || events[1].Error.Kind != "sequence" ||
					len(events[1].EvaluatorErrors) == 0 || summary.Status != "partial" || summary.AssertionOutcome != "unchecked" {
					t.Fatalf("lost partial error: %s", out.String())
				}
			} else if len(events[2].Findings) != 0 || summary.Status != "completed" || summary.AssertionOutcome != "passed" {
				t.Fatalf("finding cap/assertion changed: %s", out.String())
			}
		})
	}
}

func TestRulesTestJSONDirectEnforcement(t *testing.T) {
	enforce, disabled := true, false
	for _, tc := range []struct {
		name       string
		rules      []rule.Rule
		command    string
		wantCode   int
		findings   int
		eligible   int
		wantErrors int
	}{
		{"eligible", []rule.Rule{{ID: "test.clean", Expr: `true`, Enforce: &enforce}}, "benign", 0, 1, 1, 0},
		{"advisory", []rule.Rule{{ID: "test.clean", Expr: `true`}}, "benign", 0, 1, 0, 0},
		{"disabled", []rule.Rule{{ID: "test.clean", Expr: `true`, Enforce: &enforce, Enabled: &disabled}}, "benign", 0, 0, 0, 0},
		{"no match", []rule.Rule{{ID: "test.clean", Expr: `false`, Enforce: &enforce}}, "benign", 0, 0, 0, 0},
		{"independent error", []rule.Rule{
			{ID: "test.clean", Expr: `true`, Enforce: &enforce},
			{ID: "test.error", Expr: `"value".matches(event.command)`},
		}, "[synthetic-private-input", 1, 1, 1, 1},
		{"safe shell", []rule.Rule{{ID: "test.shell", Expr: `shell_commands.exists(c, c.executable == "cat")`, Enforce: &enforce}}, "cat .env", 0, 1, 1, 0},
		{"unsafe shell", []rule.Rule{{ID: "test.shell", Expr: `shell_commands.exists(c, c.executable == "cat")`, Enforce: &enforce}}, "cat $TARGET", 0, 1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr strings.Builder
			code := runRulesTestJSON(jsonTestEngine(t, tc.rules...), strings.NewReader(jsonTestFixture(t, tc.command)), &out, &stderr, false, false, nil)
			events, summary := parseJSONStream(t, out.String())
			if code != tc.wantCode || len(events) != 1 || len(events[0].Findings) != tc.findings ||
				len(events[0].EnforcementRules) != tc.eligible || len(events[0].EvaluatorErrors) != tc.wantErrors || summary.Matches != tc.findings {
				t.Fatalf("exit=%d stderr=%s stream=%s", code, stderr.String(), out.String())
			}
			for _, err := range events[0].EvaluatorErrors {
				if err.RuleID != "test.error" || err.Message != "evaluation failed" {
					t.Fatalf("unsafe diagnostic: %+v", err)
				}
			}
			for _, eligible := range events[0].EnforcementRules {
				if !eligible.EnforcementEligible || eligible.Via != "engine" || eligible.RuleVersion != "1.0" {
					t.Fatalf("invalid eligibility: %+v", eligible)
				}
			}
			if strings.Contains(out.String(), "synthetic-private-input") {
				t.Fatal("input content emitted through diagnostic")
			}
		})
	}
}

// Returning one fixture line per read makes it observable whether evaluation
// asks for another input after a failed result write.
type fixtureLineReader struct {
	line  string
	reads int
}

func (r *fixtureLineReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		return 0, io.EOF
	}
	return copy(p, r.line), nil
}

func TestRulesTestJSONWriteFailureStopsInput(t *testing.T) {
	for _, input := range []string{"{invalid\n", "{}\n", jsonTestFixture(t, "benign")} {
		reader := &fixtureLineReader{line: input}
		code := runRulesTestJSON(jsonTestEngine(t, rule.Rule{ID: "test.match", Expr: `true`}), reader, &failingWriter{}, io.Discard, false, false, nil)
		if code != rulesTestJSONDeliveryExitCode || reader.reads != 1 {
			t.Fatalf("exit=%d reads=%d", code, reader.reads)
		}
	}
}

func TestRulesTestJSONSetupExitCodes(t *testing.T) {
	fixture := writeTempFile(t, "empty.ndjson", "")
	for _, tc := range []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"--fixture", fixture + ".missing"}, 1},
		{[]string{"--fixture", fixture, "--no-builtin-rules"}, 1},
	} {
		args := append([]string{"rules", "test", "--json"}, tc.args...)
		out, stderr, code := runCLI(args...)
		if code != tc.code || out != "" || stderr == "" {
			t.Fatalf("args=%v exit=%d stdout=%q stderr=%q", args, code, out, stderr)
		}
	}
}

func TestRulesTestJSONAssertionMatrix(t *testing.T) {
	for _, tc := range []struct {
		name         string
		match        bool
		requireMatch bool
		expectNone   bool
		expect       multiFlag
		code         int
		outcome      string
	}{
		{name: "unchecked", match: true, outcome: "unchecked"},
		{name: "require passed", match: true, requireMatch: true, outcome: "passed"},
		{name: "require failed", requireMatch: true, code: 1, outcome: "failed"},
		{name: "none passed", expectNone: true, outcome: "passed"},
		{name: "none failed", match: true, expectNone: true, code: 1, outcome: "failed"},
		{name: "expect passed", match: true, expect: multiFlag{"test.match"}, outcome: "passed"},
		{name: "expect failed", match: true, expect: multiFlag{"test.missing"}, code: 1, outcome: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := jsonTestEngine(t, rule.Rule{ID: "test.match", Expr: fmt.Sprint(tc.match)})
			var out strings.Builder
			code := runRulesTestJSON(eng, strings.NewReader(jsonTestFixture(t, "benign")), &out, io.Discard, tc.requireMatch, tc.expectNone, tc.expect)
			_, summary := parseJSONStream(t, out.String())
			if code != tc.code || summary.AssertionOutcome != tc.outcome || summary.Status != "completed" {
				t.Fatalf("exit=%d summary=%+v", code, summary)
			}
		})
	}
}

func TestRulesTestJSONEnforcementWireTypes(t *testing.T) {
	enforce := true
	var out strings.Builder
	eng := jsonTestEngine(t, rule.Rule{ID: "test.match", Expr: `true`, Enforce: &enforce})
	if code := runRulesTestJSON(eng, strings.NewReader(jsonTestFixture(t, "benign")), &out, io.Discard, false, false, nil); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(strings.Split(out.String(), "\n")[0]), &event); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"findings", "enforcement_rules"} {
		entries, ok := event[key].([]any)
		if !ok || len(entries) != 1 {
			t.Fatalf("%s=%#v", key, event[key])
		}
		entry, ok := entries[0].(map[string]any)
		if !ok {
			t.Fatalf("%s entry=%#v", key, entries[0])
		}
		if entry["rule_id"] != "test.match" || entry["rule_version"] != "1.0" || entry["severity"] != "high" ||
			entry["via"] != "engine" || entry["enforcement_eligible"] != true {
			t.Fatalf("%s entry=%#v", key, entry)
		}
	}
}

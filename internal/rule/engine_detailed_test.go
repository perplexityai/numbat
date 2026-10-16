package rule

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestEvalDetailedMatchesEval(t *testing.T) {
	eng := mustEngine(t,
		Rule{ID: "test.shell", Severity: model.SeverityHigh, Expr: `shell_commands.exists(c, c.executable == "cat")`, Enforce: boolPtr(true)},
		Rule{ID: "test.advisory", Severity: model.SeverityHigh, Expr: `event.command == "cat .env"`},
		Rule{ID: "test.error", Severity: model.SeverityHigh, Expr: `event.tags[99] == "x"`},
	)
	for _, command := range []string{
		"cat .env", "echo harmless", "eval 'cat .env'", "cat $TARGET",
		"echo ready; cat .env", strings.Repeat("true; ", 100),
	} {
		t.Run(command[:min(len(command), 30)], func(t *testing.T) {
			ev := model.Event{EventID: "synthetic", EventType: model.EventCommandExec, Command: command}
			matches, err := eng.Eval(ev)
			detailed, evalErrs, diag := eng.EvalDetailed(ev)
			if !reflect.DeepEqual(matches, detailed) {
				t.Fatalf("Eval=%+v, EvalDetailed=%+v", matches, detailed)
			}
			var messages []string
			if diag.ShellParseError != nil {
				messages = append(messages, diag.ShellParseError.Error())
			}
			for _, e := range evalErrs {
				messages = append(messages, fmt.Sprintf("rule %q: %s", e.RuleID, e.Message))
			}
			if err == nil || err.Error() != strings.Join(messages, "\n") {
				t.Fatalf("legacy error=%v, detailed errors=%+v, diagnostics=%+v", err, evalErrs, diag)
			}
		})
	}
}

func TestEvalDetailedSafeErrorAndIndependentMatch(t *testing.T) {
	eng := mustEngine(t,
		Rule{ID: "test.regex", Severity: model.SeverityHigh, Expr: `"value".matches(event.command)`},
		Rule{ID: "test.clean", Severity: model.SeverityHigh, Expr: `true`, Enforce: boolPtr(true)},
	)
	const command = "[synthetic-private-input"
	ev := model.Event{EventType: model.EventCommandExec, Command: command}
	matches, errs, _ := eng.EvalDetailed(ev)
	if len(matches) != 1 || matches[0].Rule.ID != "test.clean" || !matches[0].EnforcementMatch {
		t.Fatalf("independent match lost: %+v", matches)
	}
	if len(errs) != 1 || errs[0] != (EvalError{RuleID: "test.regex", Message: "evaluation failed"}) {
		t.Fatalf("unsafe or unattributed error: %+v", errs)
	}
	_, err := eng.Eval(ev)
	if err == nil || err.Error() != `rule "test.regex": evaluation failed` {
		t.Fatalf("legacy diagnostic changed: %v", err)
	}
}

func TestEvalDetailedShellParity(t *testing.T) {
	for _, tc := range []struct {
		name, expr, command string
		enforce, parseError bool
	}{
		{"resolved", `shell_commands.exists(c, c.name == "gh")`, `GH=gh; $GH repo fork example/project`, true, false},
		{"static neighbor", `shell_commands.exists(c, c.name == "gh")`, `printf ready; gh repo fork example/project`, true, false},
		{"function", `shell_commands.exists(c, c.name == "gh")`, `f() { gh repo fork example/project; }; f`, false, false},
		{"interpreter", `shell_commands.exists(c, c.name == "gh")`, `bash -c 'gh repo fork example/project'`, false, false},
		{"dynamic argument", `shell_commands.exists(c, c.name == "cat")`, `cat .env; echo $TARGET`, false, false},
		{"complete absence", `!shell_commands.exists(c, c.name == "cat")`, `echo ready`, true, false},
		{"degraded absence", `!shell_commands.exists(c, c.name == "cat")`, `"$dynamic" .env; echo ready`, false, true},
		{"independent raw", `event.command.contains("echo ready")`, `"$dynamic" .env; echo ready`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := []Source{{Name: "synthetic", Rules: []Rule{{
				ID: "test.parity", Title: "shell parity", Version: "1",
				Severity: model.SeverityHigh, Enforce: boolPtr(true), Expr: tc.expr,
			}}}}
			checked, err := BuildCheckedExpressions(sources)
			if err != nil {
				t.Fatal(err)
			}
			for _, precompiled := range []CheckedExpressions{nil, checked} {
				engine, err := NewEngineWithCheckedExpressions(sources, precompiled)
				if err != nil {
					t.Fatal(err)
				}
				event := model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: tc.command}
				matches, legacyErr := engine.Eval(event)
				detailed, evalErrs, diag := engine.EvalDetailed(event)
				if !reflect.DeepEqual(matches, detailed) || len(evalErrs) != 0 {
					t.Fatalf("legacy=%+v detailed=%+v errors=%+v", matches, detailed, evalErrs)
				}
				if (legacyErr != nil) != tc.parseError || (diag.ShellParseError != nil) != tc.parseError {
					t.Fatalf("legacy error=%v diagnostics=%+v, want parse error=%v", legacyErr, diag, tc.parseError)
				}
				if len(matches) != 1 || matches[0].EnforcementMatch != tc.enforce {
					t.Fatalf("matches=%+v, want one match with enforcement=%v", matches, tc.enforce)
				}
			}
		})
	}
}

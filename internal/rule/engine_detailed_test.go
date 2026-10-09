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

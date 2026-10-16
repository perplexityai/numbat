package rule

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestExecutableParameterFlagsRemainDynamic(t *testing.T) {
	engine := mustEngine(t, Rule{
		ID: "test.parameter_flags", Severity: model.SeverityHigh, Enforce: boolPtr(true),
		Expr: `shell_commands.exists(c, c.name == "echo" && c.argv.size() == 2 && c.argv[1] == "marker")`,
	})
	for _, expansion := range []string{"${~g}", "${=g}", "${^g}", "${~~g}", "${==g}", "${^^g}", `"${~g}"`, `"${=g}"`, `"${^g}"`} {
		t.Run(expansion, func(t *testing.T) {
			matches, err := engine.Eval(model.Event{
				EventType: model.EventCommandExec, ToolName: "zsh",
				Command: `g='(a|b)/echo'; ` + expansion + ` marker`,
			})
			if len(matches) != 0 || err == nil {
				t.Fatalf("modified parameter resolved statically: matches=%+v err=%v", matches, err)
			}
		})
	}
	for _, command := range []string{`g=echo; $g marker`, `g=echo; "$g" marker`, `g=echo; ${g} marker`, `echo marker`} {
		t.Run(command, func(t *testing.T) {
			matches, err := engine.Eval(model.Event{
				EventType: model.EventCommandExec, ToolName: "zsh", Command: command,
			})
			if err != nil || len(matches) != 1 || !matches[0].EnforcementMatch {
				t.Fatalf("ordinary static command lost: matches=%+v err=%v", matches, err)
			}
		})
	}
}

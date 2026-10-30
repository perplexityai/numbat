package rule

import (
	"encoding/json"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestRedactedParameterExpansionKeepsShellRuleReplay(t *testing.T) {
	engine := mustEngine(t, Rule{
		ID: "test.replay", Severity: model.SeverityHigh,
		Expr: `shell_commands.exists(c, c.name == "cat" && c.argv == ["cat", ".env"])`,
	})
	for _, expansion := range []string{"${GH_TOKEN:-}", "${API_TOKEN:-fallback}", "${API_TOKEN:---??++==}"} {
		t.Run(expansion, func(t *testing.T) {
			ev := model.Event{
				EventType: model.EventCommandExec, ToolName: "Bash",
				Command: `[[ -n ` + expansion + ` ]] || exit 3; cat .env`,
			}
			raw, err := json.Marshal(redact.Event(ev))
			if err != nil {
				t.Fatal(err)
			}
			var replay model.Event
			if err := json.Unmarshal(raw, &replay); err != nil {
				t.Fatal(err)
			}
			for _, event := range []model.Event{ev, replay} {
				matches, failures, diag := engine.EvalDetailed(event)
				if diag.ShellParseError != nil || !diag.ShellUsable || len(failures) != 0 || len(matches) != 1 {
					t.Fatalf("command %q: matches=%d failures=%v diagnostics=%+v", event.Command, len(matches), failures, diag)
				}
			}
			if ev.Command != `[[ -n `+expansion+` ]] || exit 3; cat .env` {
				t.Fatal("output redaction mutated the original command")
			}
		})
	}
}

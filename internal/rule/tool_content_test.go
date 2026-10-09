package rule

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestRulesSeeOriginalToolBodies(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID: "test.payload", Severity: model.SeverityHigh,
		Expr: `event.tool_input.contains("PRIVATE_CANARY") && event.tool_result.contains("TAIL_CANARY")`,
	})
	var ev model.Event
	ev.SetToolInput(map[string]string{"password": "PRIVATE_CANARY"})
	ev.SetToolResult(strings.Repeat("x", model.ContentMaxBytes+1) + "TAIL_CANARY")
	matches, err := eng.Eval(ev)
	if err != nil || len(matches) != 1 || !eng.UsesContent() {
		t.Fatalf("matches=%d err=%v usesContent=%t", len(matches), err, eng.UsesContent())
	}
}

func TestIncompleteToolPayloadDoesNotBecomeCleanNegative(t *testing.T) {
	ev := model.Event{EventType: model.EventToolResult, ToolResult: `"prefix`, ToolResultBytes: 100, ToolResultTruncated: true}
	for _, tc := range []struct {
		expr        string
		wantError   bool
		wantMatches int
	}{
		{`!event.tool_result.contains("bad")`, true, 0},
		{`event.event_type == "command.exec" && !event.tool_result.contains("bad")`, false, 0},
		{`event.tool_result_truncated == true`, false, 1},
	} {
		eng := mustEngine(t, Rule{ID: "test.incomplete", Severity: model.SeverityHigh, Expr: tc.expr})
		matches, err := eng.Eval(ev)
		if (err != nil) != tc.wantError || len(matches) != tc.wantMatches {
			t.Fatalf("%s: matches=%d err=%v", tc.expr, len(matches), err)
		}
	}
}

func TestPreviewReplayCannotTreatOmittedBodyAsEmpty(t *testing.T) {
	eng := mustEngine(t, Rule{ID: "test.preview", Severity: model.SeverityHigh, Expr: `!event.tool_input.contains("bad")`})
	matches, err := eng.Eval(model.Event{ToolInputBytes: 123})
	if err == nil || len(matches) != 0 {
		t.Fatal("omitted preview body was treated as clean")
	}
}

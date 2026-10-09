package rule

import (
	"fmt"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestOmittedContentDoesNotBecomeCleanNegative(t *testing.T) {
	for _, field := range []string{"content", "tool_input", "tool_result"} {
		event := model.Event{EventType: model.EventToolResult, ContentOmitted: []string{field}}
		engine := mustEngine(t, Rule{
			ID: "test.omitted", Severity: model.SeverityHigh,
			Expr: fmt.Sprintf(`!event.%s.contains("bad")`, field),
		})
		matches, err := engine.Eval(event)
		if err == nil || len(matches) != 0 {
			t.Fatalf("%s treated as clean: matches=%d err=%v", field, len(matches), err)
		}
		engine = mustEngine(t, Rule{
			ID: "test.scoped", Severity: model.SeverityHigh,
			Expr: fmt.Sprintf(`event.event_type == "command.exec" && !event.%s.contains("bad")`, field),
		})
		if matches, err := engine.Eval(event); err != nil || len(matches) != 0 {
			t.Fatalf("%s error escaped its scope: %v", field, err)
		}
		engine = mustEngine(t, Rule{
			ID: "test.metadata", Severity: model.SeverityHigh,
			Expr: fmt.Sprintf(`"%s" in event.content_omitted`, field),
		})
		if matches, err := engine.Eval(event); err != nil || len(matches) != 1 {
			t.Fatalf("%s metadata unavailable: %v", field, err)
		}
	}
}

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

func TestMessageScopeReplayCannotTreatOmittedBodyAsEmpty(t *testing.T) {
	eng := mustEngine(t, Rule{ID: "test.scope", Severity: model.SeverityHigh, Expr: `!event.tool_input.contains("bad")`})
	var ev model.Event
	ev.SetToolInput(map[string]string{"data": "bad"})
	for _, raw := range []bool{false, true} {
		matches, err := eng.Eval(redact.EventWithMessageContent(ev, raw))
		if err == nil || len(matches) != 0 {
			t.Fatal("scope-filtered tool body was treated as clean")
		}
	}
}

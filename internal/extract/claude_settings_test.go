package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestExtractClaudeSettingsAllowRules(t *testing.T) {
	const input = `{
  "permissions": {
    "allow": [
      "Bash(npm run test *)",
      "WebSearch",
      "mcp__github__get_issue",
      "WebFetch(domain:docs.anthropic.com)",
      42,
      "   "
    ],
    "deny": ["Read(./.env)"],
    "ask": ["Bash(git push *)"]
  },
  "env": {"FOO": "bar"}
}`
	path := "/repo/.claude/settings.local.json"
	res, err := ClaudeExtractor{}.Extract(strings.NewReader(input), Source{Path: path, CaseID: "case-1"})
	if err != nil {
		t.Fatal(err)
	}
	type want struct{ tool, input, pointer string }
	wants := []want{
		{"Bash", `"Bash(npm run test *)"`, "/permissions/allow/0"},
		{"WebSearch", `"WebSearch"`, "/permissions/allow/1"},
		{"mcp__github__get_issue", `"mcp__github__get_issue"`, "/permissions/allow/2"},
		{"WebFetch", `"WebFetch(domain:docs.anthropic.com)"`, "/permissions/allow/3"},
	}
	if len(res.Events) != len(wants) {
		t.Fatalf("events = %d, want %d: %+v", len(res.Events), len(wants), res.Events)
	}
	ids := map[string]struct{}{}
	for i, ev := range res.Events {
		w := wants[i]
		if err := ev.Validate(); err != nil {
			t.Fatalf("event %d invalid: %v", i, err)
		}
		if ev.EventType != model.EventPermissionApproved || ev.SourceType != model.SourceArtifact ||
			ev.SourceAgent != model.AgentClaudeCode || ev.Decision != model.DecisionAllowed ||
			ev.ApprovalDecision != model.DecisionAllowed || ev.Confidence != model.ConfidenceHigh {
			t.Fatalf("event %d shape = %+v", i, ev)
		}
		if ev.ToolName != w.tool || ev.ToolInputForAnalysis() != w.input {
			t.Fatalf("event %d tool=%q input=%q, want %q %q", i, ev.ToolName, ev.ToolInputForAnalysis(), w.tool, w.input)
		}
		if ev.ToolInput != "" {
			t.Fatalf("event %d exposes tool input on the default wire: %q", i, ev.ToolInput)
		}
		if ev.Evidence.ArtifactType != artifactClaudeSettings || ev.Evidence.LocalPath != path ||
			ev.Evidence.JSONPointer != w.pointer || len(ev.Evidence.SHA256) != 64 {
			t.Fatalf("event %d evidence = %+v", i, ev.Evidence)
		}
		if ev.CaseID != "case-1" || ev.Timestamp != "" || ev.SessionID != "" || ev.Actor != "" {
			t.Fatalf("event %d synthesized context: %+v", i, ev)
		}
		ids[ev.EventID] = struct{}{}
	}
	if len(ids) != len(wants) {
		t.Fatalf("event ids are not unique: %v", ids)
	}
	if len(res.Diagnostics) != 1 || !strings.Contains(res.Diagnostics[0].Msg, "entry 4 is not a string") {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
}

func TestExtractClaudeSettingsMalformedDoesNotLeakContent(t *testing.T) {
	const secret = "hunter2hunter2"
	input := `{"permissions":{"allow":["Bash(PGPASSWORD=` + secret + ` psql)"` // truncated JSON
	res, err := ClaudeExtractor{}.Extract(strings.NewReader(input), Source{Path: "/repo/.claude/settings.json"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || len(res.Diagnostics) != 1 {
		t.Fatalf("events=%+v diagnostics=%+v", res.Events, res.Diagnostics)
	}
	if strings.Contains(res.Diagnostics[0].Msg, secret) {
		t.Fatalf("diagnostic leaked settings content: %q", res.Diagnostics[0].Msg)
	}
}

func TestExtractClaudeSettingsWithoutPermissions(t *testing.T) {
	for _, input := range []string{"", "  \n", `{}`, `{"model":"opus","permissions":{"deny":["Bash(rm *)"]}}`} {
		res, err := ClaudeExtractor{}.Extract(strings.NewReader(input), Source{Path: "/home/dev/.claude/settings.json"})
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if len(res.Events) != 0 || len(res.Diagnostics) != 0 {
			t.Fatalf("%q: events=%+v diagnostics=%+v", input, res.Events, res.Diagnostics)
		}
	}
}

func TestClaudePermissionRuleTool(t *testing.T) {
	for in, want := range map[string]string{
		"Bash(ls -la)":          "Bash",
		"Read(./src/**)":        "Read",
		"WebSearch":             "WebSearch",
		"mcp__server__tool":     "mcp__server__tool",
		"Bash(unterminated":     "",
		"free text with spaces": "",
		"(no tool)":             "",
	} {
		if got := claudePermissionRuleTool(in); got != want {
			t.Errorf("claudePermissionRuleTool(%q) = %q, want %q", in, got, want)
		}
	}
}

package otel

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/rules"
)

func TestOTLPResultPreservesTypedActivity(t *testing.T) {
	sources, err := rule.LoadSourcesFS(rules.FS, rules.Dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rule.NewEngine(sources)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		attrs [][]byte
		kind  model.EventType
		rule  string
	}{
		{"read", [][]byte{kv(attrGenAIToolName, "read_file"), kv(attrFilePath, "/repo/.env")}, model.EventFileRead, "secrets.agent_read_env"},
		{"write", [][]byte{kv(attrGenAIToolName, "write_file"), kv(attrFilePath, "/repo/a.go"), kvAny(attrDiffBytes, anyInt(42))}, model.EventFileWrite, ""},
		{"delete", [][]byte{kv(attrGenAIToolName, "remove_file"), kv(attrFilePath, "/repo/a.go")}, model.EventFileDelete, ""},
		{"network", [][]byte{kv(attrGenAIToolName, "WebFetch"), kv(attrURLFull, "http://169.254.169.254/latest/meta-data/")}, model.EventNetworkIndicator, "recon.cloud_metadata"},
		{"mcp fetch", [][]byte{kv(attrGenAIToolName, "mcp__fetch__fetch"), kv(attrGenAIToolCallArgs, `{"url":"http://169.254.169.254/latest/meta-data/"}`)}, model.EventNetworkIndicator, "recon.cloud_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := append([][]byte{kv(attrServiceName, "claude-code"), kv(attrGenAIToolCallID, "call")}, tc.attrs...)
			before := mapOne(t, nil, recBuilder{attrs: attrs, severityText: "ERROR"}.build()).Event
			beforeMatches, err := engine.Eval(before)
			if err != nil {
				t.Fatal(err)
			}
			if tc.rule != "" {
				found := false
				for _, match := range beforeMatches {
					found = found || match.Rule.ID == tc.rule
				}
				if !found {
					t.Fatalf("missing baseline finding %s", tc.rule)
				}
			}
			for _, body := range [][]byte{anyStr("RESULT_CANARY"), anyStr(""), nil} {
				withResult := append(append([][]byte(nil), attrs...), kvAny(attrGenAIToolCallResult, body))
				ev := mapOne(t, nil, recBuilder{attrs: withResult, severityText: "ERROR"}.build()).Event
				if ev.EventType != tc.kind || ev.FilePath != before.FilePath || ev.URL != before.URL ||
					ev.DiffBytes != before.DiffBytes || ev.MCPServer != before.MCPServer || !hasTag(ev, model.TagToolError) {
					t.Fatalf("result lost typed activity: %+v", ev)
				}
				if err := ev.Validate(); err != nil {
					t.Fatal(err)
				}
				if ev.ToolResultForAnalysis() == "" {
					t.Fatal("result presence lost")
				}
				matches, err := engine.Eval(ev)
				if err != nil || len(matches) != len(beforeMatches) {
					t.Fatalf("result changed finding count: got %d, want %d; err=%v", len(matches), len(beforeMatches), err)
				}
				for i, match := range matches {
					if match.Rule.ID != beforeMatches[i].Rule.ID || match.EnforcementMatch != beforeMatches[i].EnforcementMatch {
						t.Fatal("result changed a finding or its enforcement eligibility")
					}
				}
			}
		})
	}
}

func TestOTLPResultContentAndRecordScope(t *testing.T) {
	for _, body := range [][]byte{anyStr(""), anyStr(strings.Repeat("x", 70000) + "RESULT_TAIL"), anyKVList(kv("unknown", "RESULT_TAIL"))} {
		result := mapOne(t, nil, recBuilder{attrs: [][]byte{kv(attrGenAIToolName, "mcp__notes__save"), kvAny(attrGenAIToolCallResult, body)}}.build())
		if !result.Mapped || result.Event.EventType != model.EventToolResult || result.Event.ToolResultForAnalysis() == "" {
			t.Fatal("result was lost or classified as a call")
		}
	}
	result := mapOne(t, [][]byte{kv(attrGenAIToolCallResult, "RESOURCE_CANARY")}, recBuilder{attrs: [][]byte{kv(attrGenAIToolName, "mcp__notes__save")}}.build())
	if result.Event.ToolResultForAnalysis() != "" || result.Event.EventType != model.EventToolCall {
		t.Fatal("process metadata fabricated a tool result")
	}
}

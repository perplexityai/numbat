package otel

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// gen_ai.tool.call.arguments may be JSON text or an OTLP KeyValueList.
// https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/#gen-ai-tool-call-arguments
func TestToolArgumentPreviewWireForms(t *testing.T) {
	for _, key := range []string{attrGenAIToolCallArgs, attrToolCallArgs} {
		for name, value := range map[string][]byte{
			"string": anyStr(`{"url":"https://reference.example/","password":"private","action":"save"}`),
			"map":    anyKVList(kv("url", "https://reference.example/"), kv("password", "private"), kv("action", "save")),
		} {
			t.Run(key+"/"+name, func(t *testing.T) {
				result := mapOne(t, nil, recBuilder{attrs: [][]byte{
					kv(attrGenAIToolName, "mcp__notes__save"), kv(attrGenAIToolCallID, "c1"), kvAny(key, value),
				}}.build())
				ev := result.Event
				if !result.Mapped || ev.EventType != model.EventToolCall || ev.URL != "" || ev.MCPServer != "notes" || ev.MCPTool != "save" {
					t.Fatalf("event = %+v", ev)
				}
				if want := `{"action":"save","password":"[redacted]","url":"https://reference.example/"}`; ev.ContentPreview != want {
					t.Fatalf("preview = %q, want %q", ev.ContentPreview, want)
				}
				if err := ev.Validate(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCanonicalMCPFetchArgumentTarget(t *testing.T) {
	for _, value := range [][]byte{
		anyStr(`{"url":"https://target.example/"}`),
		anyKVList(kv("url", "https://target.example/")),
	} {
		result := mapOne(t, nil, recBuilder{attrs: [][]byte{
			kv(attrGenAIToolName, "mcp__fetch__fetch"),
			kv(attrURLFull, "https://mcp.example/"),
			kvAny(attrGenAIToolCallArgs, value),
		}}.build())
		ev := result.Event
		if !result.Mapped || ev.EventType != model.EventNetworkIndicator || ev.URL != "https://target.example/" || ev.MCPServer != "fetch" || ev.MCPTool != "fetch" {
			t.Fatalf("event = %+v", ev)
		}
	}
}

func TestGenericOTLPToolWithFileReference(t *testing.T) {
	result := mapOne(t, nil, recBuilder{attrs: [][]byte{
		kv(attrGenAIToolName, "mcp__notes__attach"), kv(attrFilePath, "/tmp/reference"),
		kv(attrGenAIToolCallArgs, `{"query":"release notes"}`),
	}}.build())
	ev := result.Event
	if !result.Mapped || ev.EventType != model.EventToolCall || ev.MCPServer != "notes" || ev.MCPTool != "attach" || ev.ContentPreview != `{"query":"release notes"}` {
		t.Fatalf("event = %+v", ev)
	}
}

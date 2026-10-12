package extract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// Codex CUA calls persist namespaced inputs and separately correlated results.
// Function calls accept both object and JSON-string arguments (codex_entry.go).
func TestCodexCUAInputAndResultIdentity(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		for _, custom := range []bool{false, true} {
			for _, failed := range []bool{false, true} {
				t.Run(fmt.Sprintf("encoded=%t/custom=%t/failed=%t", encoded, custom, failed), func(t *testing.T) {
					args := `{"title":"Navigate browser test","code":"await browser.setValue(11, \"https://example.com/\"); await browser.pressKey(\"Return\");"}`
					var input any = json.RawMessage(args)
					if encoded {
						input = args
					}
					kind, field, resultKind := "function_call", "arguments", "function_call_output"
					if custom {
						kind, field, resultKind = "custom_tool_call", "input", "custom_tool_call_output"
					}
					call, err := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
						"type": kind, "name": "js", "namespace": "mcp__cua_repl", "call_id": "cua1", field: input,
					}})
					if err != nil {
						t.Fatal(err)
					}
					body := string(call) + "\n" + `{"type":"response_item","payload":{"type":"` + resultKind + `","call_id":"cua1","output":"Example Domain"}}`
					if failed {
						body += "\n" + `{"type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"cua1","result":{"Err":"failed"}}}`
					}
					res := extractCodex(t, body)
					if len(res.Events) != 2 || len(res.Diagnostics) != 0 {
						t.Fatalf("result = %+v", res)
					}
					for i, ev := range res.Events {
						if ev.ToolName != "js" || ev.MCPServer != "cua_repl" || ev.MCPTool != "js" || ev.ToolCallID != "cua1" {
							t.Fatalf("identity on event %d: %+v", i, ev)
						}
						if err := ev.Validate(); err != nil {
							t.Fatal(err)
						}
					}
					callEv, result := res.Events[0], res.Events[1]
					if callEv.EventType != model.EventToolCall || callEv.URL != "" ||
						!strings.Contains(callEv.ContentPreview, "setValue") || !strings.Contains(callEv.ContentPreview, "https://example.com/") {
						t.Fatalf("call lost input or inferred navigation: %+v", callEv)
					}
					if result.EventType != model.EventToolResult || result.ContentPreview != "Example Domain" || hasTag(result.Tags, model.TagToolError) != failed {
						t.Fatalf("result = %+v", result)
					}
				})
			}
		}
	}
}

func TestCodexMCPNamesDoNotBecomeBuiltins(t *testing.T) {
	for _, name := range []string{"exec_command", "read_file", "create_file", "apply_patch"} {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(`{"type":"response_item","payload":{"type":"function_call","namespace":"mcp__custom","name":%q,"call_id":"c","arguments":{"command":"echo test","path":"/tmp/test"}}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"ok"}}`, name)
			res := extractCodex(t, body)
			if len(res.Events) != 2 || res.Events[0].EventType != model.EventToolCall || res.Events[1].EventType != model.EventToolResult {
				t.Fatalf("events = %+v", res.Events)
			}
			for _, ev := range res.Events {
				if ev.MCPServer != "custom" || ev.MCPTool != name || ev.Command != "" || ev.FilePath != "" {
					t.Fatalf("wrong MCP classification: %+v", ev)
				}
			}
		})
	}
}

func TestCodexPendingToolsCorrelateByID(t *testing.T) {
	res := extractCodex(t, `{"type":"response_item","payload":{"type":"function_call","name":"mcp__one__first","call_id":"a","arguments":{}}}
{"type":"response_item","payload":{"type":"function_call","name":"mcp__two__second","call_id":"b","arguments":{}}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"b","output":"ok"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"a","output":"ok"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"missing","output":"ok"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"","output":"ok"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"a","output":"duplicate"}}
{"type":"response_item","payload":{"type":"function_call","name":"mcp__three__next","call_id":"a","arguments":{}}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"a","output":"ok"}}`)
	var servers []string
	for _, ev := range res.Events {
		if ev.EventType == model.EventToolResult {
			servers = append(servers, ev.MCPServer)
		}
	}
	if got, want := strings.Join(servers, ","), "two,one,,,,three"; got != want {
		t.Fatalf("result servers = %q, want %q", got, want)
	}
}

func TestGenericArtifactInputPreviews(t *testing.T) {
	input := map[string]json.RawMessage{"url": json.RawMessage(`"https://example.com/"`), "query": json.RawMessage(`"browser docs"`), "password": json.RawMessage(`"private"`)}
	for name, classify := range map[string]func(*model.Event){
		"claude":   func(ev *model.Event) { classifyTool(ev, "mcp__notes__save", input) },
		"cursor":   func(ev *model.Event) { classifyCursorTool(ev, "mcp__notes__save", input) },
		"windsurf": func(ev *model.Event) { classifyWindsurfTool(ev, "mcp__notes__save", input) },
		"copilot":  func(ev *model.Event) { classifyCopilotTool(ev, "mcp__notes__save", input) },
		"gemini": func(ev *model.Event) {
			classifyGeminiTool(ev, &geminiFunctionCall{Name: "mcp__notes__save", Args: input})
		},
		"opencode": func(ev *model.Event) { classifyOpenCodeTool(ev, "mcp__notes__save", input) },
		"openclaw": func(ev *model.Event) { classifyOpenClawTool(ev, "mcp__notes__save", input) },
		"pi":       func(ev *model.Event) { classifyPiTool(ev, "plugin", input) },
		"kimi": func(ev *model.Event) {
			classifyKimiTool(ev, "plugin", json.RawMessage(`{"password":"private","query":"browser docs","url":"https://example.com/"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var ev model.Event
			classify(&ev)
			if ev.EventType != model.EventToolCall || ev.URL != "" || hasTag(ev.Tags, model.TagNetwork) {
				t.Fatalf("URL reference became network activity: %+v", ev)
			}
			if want := `{"password":"[redacted]","query":"browser docs","url":"https://example.com/"}`; ev.ContentPreview != want {
				t.Fatalf("preview = %q, want %q", ev.ContentPreview, want)
			}
		})
	}
}

func TestOpenClawBrowserActionTargets(t *testing.T) {
	for _, action := range []string{"open", "navigate", "screenshot", "tabs", "upload", "act", ""} {
		t.Run(action, func(t *testing.T) {
			res := extractOpenClaw(t, withHeader(fmt.Sprintf(`{"type":"message","message":{"role":"assistant","content":[{"type":"toolCall","id":"b","name":"browser","arguments":{"action":%q,"targetUrl":"https://example.com/"}}]}}`, action)))
			var call model.Event
			for _, ev := range res.Events {
				if ev.ToolCallID == "b" {
					call = ev
				}
			}
			want := model.EventToolCall
			if action == "open" || action == "navigate" {
				want = model.EventNetworkIndicator
			}
			if call.EventType != want || !hasTag(call.Tags, "browser") || !strings.Contains(call.ContentPreview, `"action":`) {
				t.Fatalf("call = %+v", call)
			}
			if want == model.EventToolCall && (call.URL != "" || hasTag(call.Tags, model.TagNetwork)) {
				t.Fatalf("non-navigation classified as network: %+v", call)
			}
		})
	}
}

func TestOpenClawEmbeddedCodexMCPInput(t *testing.T) {
	res := extractOpenClaw(t, strings.Join([]string{
		`{"type":"session_meta","payload":{"id":"embedded"}}`,
		`{"type":"response_item","payload":{"type":"function_call","namespace":"mcp__custom","name":"exec_command","call_id":"c","arguments":{"code":"await tab.goto(url)","password":"private"}}}`,
	}, "\n"))
	for _, ev := range res.Events {
		if ev.ToolCallID != "c" {
			continue
		}
		if ev.EventType != model.EventToolCall || ev.MCPServer != "custom" || ev.ContentPreview != `{"code":"await tab.goto(url)","password":"[redacted]"}` {
			t.Fatalf("event = %+v", ev)
		}
		return
	}
	t.Fatal("missing embedded tool call")
}

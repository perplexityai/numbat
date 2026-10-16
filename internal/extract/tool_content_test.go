package extract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestArtifactToolPayloads(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parser Extractor
		body   string
	}{
		{"Claude", ClaudeExtractor{}, `{"type":"assistant","sessionId":"s","message":{"content":[{"type":"tool_use","id":"c","name":"mcp__notes__save","input":{"text":"INPUT_CANARY","integer":9007199254740993}}]}}
{"type":"user","sessionId":"s","toolUseResult":{"native":"NATIVE_CANARY"},"message":{"content":[{"type":"tool_result","tool_use_id":"c","content":[{"type":"text","text":"RESULT_CANARY"},{"type":"image","data":"IMAGE_CANARY"}]}]}}`},
		{"Pi", PiExtractor{}, `{"type":"session","version":3,"id":"s","cwd":"/repo"}
{"type":"message","id":"m1","message":{"role":"assistant","content":[{"type":"toolCall","id":"c","name":"read","arguments":{"path":"/repo/file","text":"INPUT_CANARY"}}]}}
{"type":"message","id":"m2","message":{"role":"toolResult","toolCallId":"c","toolName":"read","content":[{"type":"text","text":"RESULT_CANARY"}],"details":{"unknown":"EXTRA_CANARY"}}}`},
		{"Cursor", CursorExtractor{}, `{"type":"assistant","conversationId":"s","content":[{"type":"tool_call","name":"Read","callId":"c","input":{"path":"/repo/file","text":"INPUT_CANARY"}}]}
{"type":"tool","conversationId":"s","toolResult":{"callId":"c","output":"RESULT_CANARY","unknown":9007199254740993}}`},
		{"Windsurf", WindsurfExtractor{}, `{"type":"assistant","cascadeId":"s","toolCall":{"name":"read_file","id":"c","input":{"path":"/repo/file","text":"INPUT_CANARY"}}}
{"type":"tool","cascadeId":"s","toolResult":{"id":"c","output":"RESULT_CANARY"}}`},
		{"Copilot", CopilotExtractor{}, `{"hookEventName":"PreToolUse","sessionId":"s","toolName":"Read","toolCallId":"c","toolArgs":{"path":"/repo/file","text":"INPUT_CANARY"}}
{"hookEventName":"PostToolUse","sessionId":"s","toolName":"Read","toolCallId":"c","toolResponse":{"body":"RESULT_CANARY"}}`},
		{"Gemini", GeminiExtractor{}, `{"history":[{"role":"model","parts":[{"functionCall":{"id":"c","name":"read_file","args":{"file_path":"/repo/file","text":"INPUT_CANARY"}}}]},{"role":"user","parts":[{"functionResponse":{"id":"c","name":"read_file","response":{"output":"RESULT_CANARY"}}}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.parser.Extract(strings.NewReader(tc.body), Source{Path: "/synthetic/session.jsonl"})
			if err != nil {
				t.Fatal(err)
			}
			input, result := false, false
			for _, ev := range res.Events {
				input = input || strings.Contains(ev.ToolInputForAnalysis(), "INPUT_CANARY")
				result = result || strings.Contains(ev.ToolResultForAnalysis(), "RESULT_CANARY")
				if tc.name == "Claude" && ev.EventType == model.EventToolResult {
					if ev.ToolName != "mcp__notes__save" || ev.MCPServer != "notes" || !strings.Contains(ev.ToolResultForAnalysis(), "NATIVE_CANARY") || !strings.Contains(ev.ToolResultForAnalysis(), "IMAGE_CANARY") {
						t.Fatal("Claude lost correlation or a result representation")
					}
				}
				if err := ev.Validate(); err != nil {
					t.Fatal(err)
				}
			}
			if !input || !result {
				t.Fatalf("input=%t result=%t diagnostics=%v", input, result, res.Diagnostics)
			}
		})
	}
}

func TestCodexKeepsNativeAndModelResults(t *testing.T) {
	call := `{"type":"response_item","payload":{"type":"function_call","name":"mcp__notes__save","call_id":"c","arguments":"{\"text\":\"INPUT_CANARY\"}"}}`
	output := `{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"MODEL_RESULT_CANARY"}}`
	native := `{"type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"c","result":{"Ok":{"content":[{"type":"text","text":"NATIVE_RESULT_CANARY"}],"structuredContent":{"n":9007199254740993}}}}}`
	for _, rows := range [][]string{{call, output, native}, {call, native, output}} {
		res, err := (CodexExtractor{}).Extract(strings.NewReader(strings.Join(rows, "\n")), Source{Path: "/synthetic/rollout.jsonl"})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, ev := range res.Events {
			if ev.EventType == model.EventToolResult {
				count++
				body := ev.ToolResultForAnalysis()
				if !json.Valid([]byte(body)) || !strings.Contains(body, "MODEL_RESULT_CANARY") || !strings.Contains(body, "NATIVE_RESULT_CANARY") || !strings.Contains(body, "9007199254740993") {
					t.Fatalf("lost result representation: %s", body)
				}
			}
		}
		if count != 1 {
			t.Fatalf("got %d results for one invocation", count)
		}
	}
}

func TestOpenCodeRetainsReadOutput(t *testing.T) {
	res := extractOpenCode(t, `{"type":"tool","id":"p","sessionID":"s","messageID":"m","callID":"c","tool":"read","state":{"status":"completed","input":{"filePath":"/repo/file"},"output":"RESULT_CANARY","unknown":"UNKNOWN_CANARY"}}`)
	for _, ev := range res.Events {
		if ev.EventType == model.EventToolResult {
			if !strings.Contains(ev.ToolResultForAnalysis(), "RESULT_CANARY") || !strings.Contains(ev.ToolResultForAnalysis(), "UNKNOWN_CANARY") {
				t.Fatal("read result or unknown result fields lost")
			}
			return
		}
	}
	t.Fatal("no result")
}

func TestArtifactNullAndEmptyArguments(t *testing.T) {
	for _, tc := range []struct {
		parser Extractor
		body   string
	}{
		{ClaudeExtractor{}, `{"type":"assistant","sessionId":"s","message":{"content":[{"type":"tool_use","id":"c","name":"mcp__notes__save","input":VALUE}]}}`},
		{PiExtractor{}, `{"type":"message","id":"m","message":{"role":"assistant","content":[{"type":"toolCall","id":"c","name":"custom","arguments":VALUE}]}}`},
		{CursorExtractor{}, `{"type":"assistant","conversationId":"s","toolCall":{"name":"custom","callId":"c","input":VALUE}}`},
		{WindsurfExtractor{}, `{"type":"assistant","cascadeId":"s","toolCall":{"name":"custom","id":"c","input":VALUE}}`},
	} {
		for _, value := range []string{"null", "{}"} {
			res, err := tc.parser.Extract(strings.NewReader(strings.ReplaceAll(tc.body, "VALUE", value)), Source{Path: "/synthetic/session.jsonl"})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ev := range res.Events {
				if ev.EventType == model.EventToolCall {
					found = true
					if ev.ToolInputForAnalysis() != value {
						t.Fatalf("%T: lost %s argument presence", tc.parser, value)
					}
				}
			}
			if !found {
				t.Fatalf("%T: no tool call: %v", tc.parser, res.Diagnostics)
			}
		}
	}
}

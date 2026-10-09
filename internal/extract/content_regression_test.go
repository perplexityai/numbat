package extract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestToolSearchArgumentsRetained(t *testing.T) {
	for _, ex := range []Extractor{CodexExtractor{}, OpenClawExtractor{}} {
		t.Run(fmt.Sprintf("%T", ex), func(t *testing.T) {
			for _, args := range []string{`{"query":"QUERY_CANARY","limit":8,"unknown":9007199254740993}`, `null`, `{}`, `[]`, `""`, `false`, ``} {
				payload := `{"type":"tool_search_call","call_id":"x","status":"completed","execution":"client"`
				if args != "" {
					payload += `,"arguments":` + args
				}
				body := `{"type":"response_item","payload":` + payload + `}}`
				res, err := SafeExtract(ex, strings.NewReader(body), Source{Path: "/synthetic/rollout.jsonl"})
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				for _, ev := range res.Events {
					if ev.EventType != model.EventToolCall {
						continue
					}
					calls++
					if ev.ToolName != "tool_search" || ev.ToolCallID != "x" || ev.Evidence.JSONPointer != "/payload/arguments" || ev.Evidence.Line != 1 {
						t.Fatal("tool search identity or evidence changed")
					}
					if ev.ToolInputForAnalysis() != args || ev.ToolInputBytesForAnalysis() != len(args) || ev.ToolInputTruncatedForAnalysis() {
						t.Errorf("arguments=%q, want %q", ev.ToolInputForAnalysis(), args)
					}
					if err := ev.Validate(); err != nil {
						t.Fatal(err)
					}
				}
				if calls != 1 {
					t.Fatalf("tool calls=%d", calls)
				}
			}
		})
	}
}

// Source shapes: openai/codex protocol/src/models.rs at
// 47b80571f0d6587060a580c47f6af0cfaefb0d5c, ResponseItem.
func TestCodexToolVariantContent(t *testing.T) {
	for _, ex := range []Extractor{CodexExtractor{}, OpenClawExtractor{}} {
		for _, tc := range []struct {
			kind, fields, input, result string
		}{
			{"function_call", `"name":"custom","arguments":{"unknown":9007199254740993}`, `{"unknown":9007199254740993}`, ""},
			{"custom_tool_call", `"name":"custom","input":"CUSTOM_CANARY"`, `"CUSTOM_CANARY"`, ""},
			{"local_shell_call", `"action":{"type":"exec","command":["echo","SHELL_CANARY"],"unknown":false}`, `{"type":"exec","command":["echo","SHELL_CANARY"],"unknown":false}`, ""},
			{"web_search_call", `"action":{"type":"search","query":"SEARCH_CANARY","unknown":8}`, `{"type":"search","query":"SEARCH_CANARY","unknown":8}`, ""},
			{"function_call_output", `"output":[{"type":"text","text":"RESULT_CANARY","unknown":9007199254740993}]`, "", `[{"type":"text","text":"RESULT_CANARY","unknown":9007199254740993}]`},
			{"custom_tool_call_output", `"output":"CUSTOM_RESULT_CANARY"`, "", `"CUSTOM_RESULT_CANARY"`},
			{"tool_search_output", `"tools":[{"type":"function","name":"custom","unknown":9007199254740993}]`, "", `[{"type":"function","name":"custom","unknown":9007199254740993}]`},
			{"image_generation_call", `"status":"completed","revised_prompt":"PROMPT_CANARY","result":"Zm9v","unknown":9007199254740993`, "", "envelope"},
			{"image_generation_call", `"status":"in_progress"`, "", ""},
		} {
			t.Run(fmt.Sprintf("%T/%s", ex, tc.kind), func(t *testing.T) {
				identity := `"call_id":"c"`
				if tc.kind == "image_generation_call" {
					identity = `"id":"ig_synthetic"`
				}
				payload := `{"type":"` + tc.kind + `",` + identity + `,` + tc.fields + `}`
				wantResult := tc.result
				if wantResult == "envelope" {
					wantResult = payload
				}
				res, err := SafeExtract(ex, strings.NewReader(`{"type":"response_item","payload":`+payload+`}`), Source{Path: "/synthetic/rollout.jsonl"})
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, ev := range res.Events {
					if ev.EventType == model.EventSessionStart || ev.EventType == model.EventSessionEnd {
						continue
					}
					count++
					if ev.ToolInputForAnalysis() != tc.input || ev.ToolResultForAnalysis() != wantResult {
						t.Errorf("input=%q result=%q; want input=%q result=%q", ev.ToolInputForAnalysis(), ev.ToolResultForAnalysis(), tc.input, wantResult)
					}
				}
				if count != 1 {
					t.Fatalf("mapped events=%d", count)
				}
			})
		}
	}
}

const promptRetractionHistory = `{"type":"response_item","payload":{"type":"message","role":"user","content":"older prompt one"}}
{"type":"response_item","payload":{"type":"function_call","name":"shell_command","call_id":"call-1","arguments":"{\"command\":\"echo SAFE_CANARY\"}"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":"older prompt two"}}
{"type":"event_msg","payload":{"type":"user_message","message":"explicit prompt"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"call-1","output":"RESULT_CANARY"}}`

func TestCodexCaptureWithPromptRetraction(t *testing.T) {
	for _, ex := range []Extractor{CodexExtractor{}, OpenClawExtractor{}} {
		for _, safe := range []bool{true, false} {
			t.Run(map[bool]string{true: "safe", false: "direct"}[safe], func(t *testing.T) {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("unexpected panic: %v", p)
					}
				}()
				src := Source{Path: "/synthetic/rollout.jsonl"}
				var result *Result
				var err error
				if safe {
					result, err = SafeExtract(ex, strings.NewReader(promptRetractionHistory), src)
				} else {
					result, err = ex.Extract(strings.NewReader(promptRetractionHistory), src)
				}
				if err != nil {
					t.Fatal(err)
				}
				calls, results, prompts := 0, 0, 0
				for _, ev := range result.Events {
					switch ev.EventType {
					case model.EventCommandExec:
						calls++
						if !strings.Contains(ev.ToolInputForAnalysis(), "SAFE_CANARY") || ev.Evidence.Line != 2 {
							t.Fatal("command input or provenance lost")
						}
					case model.EventCommandResult:
						results++
						if !strings.Contains(ev.ToolResultForAnalysis(), "RESULT_CANARY") || ev.Evidence.Line != 5 {
							t.Fatal("result input or provenance lost")
						}
					case model.EventPromptUser:
						prompts++
						if ev.ContentPreview != "explicit prompt" {
							t.Fatal("fallback prompt survived")
						}
					}
				}
				if calls != 1 || results != 1 || prompts != 1 {
					t.Fatalf("calls=%d results=%d prompts=%d", calls, results, prompts)
				}
			})
		}
	}
}

func TestOpenClawNativePatchRetainsPayload(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\n+PATCH_CANARY\n*** Add File: b.txt\n+SECOND_CANARY\n*** End Patch"
	args, _ := json.Marshal(map[string]string{"input": patch, "unknown": "UNKNOWN_CANARY"})
	body := `{"type":"session","version":3,"id":"s","cwd":"/repo"}` + "\n" + `{"type":"message","id":"m","message":{"role":"assistant","content":[{"type":"toolCall","id":"c","name":"apply_patch","arguments":` + string(args) + `}]}}`
	result, err := (OpenClawExtractor{}).Extract(strings.NewReader(body), Source{Path: "/synthetic/session.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, ev := range result.Events {
		if ev.EventType == model.EventFileWrite {
			count++
			if !strings.Contains(ev.ToolInputForAnalysis(), "PATCH_CANARY") || !strings.Contains(ev.ToolInputForAnalysis(), "UNKNOWN_CANARY") {
				t.Error("patch input lost")
			}
		}
	}
	if count != 2 {
		t.Fatalf("file events=%d", count)
	}
}

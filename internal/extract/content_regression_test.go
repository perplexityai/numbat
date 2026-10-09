package extract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

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

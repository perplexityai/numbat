package extract

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestPatchContentExportedOnce(t *testing.T) {
	for _, files := range []int{1, 3, 500} {
		var patch strings.Builder
		patch.WriteString("*** Begin Patch\n")
		for i := range files {
			fmt.Fprintf(&patch, "*** Add File: file-%d.txt\n+PATCH_CANARY_%d\n", i, i)
		}
		patch.WriteString("*** End Patch")
		quoted, err := json.Marshal(patch.String())
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name   string
			parser Extractor
			body   string
		}{
			{"codex custom", CodexExtractor{}, `{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","call_id":"patch","input":` + string(quoted) + `}}`},
			{"codex function", CodexExtractor{}, `{"type":"response_item","payload":{"type":"function_call","name":"apply_patch","call_id":"patch","arguments":` + string(quoted) + `}}`},
			{"openclaw embedded", OpenClawExtractor{}, `{"type":"response_item","payload":{"type":"function_call","name":"apply_patch","call_id":"patch","arguments":` + string(quoted) + `}}`},
			{"openclaw native", OpenClawExtractor{}, `{"type":"message","id":"m","message":{"role":"assistant","content":[{"type":"toolCall","id":"patch","name":"apply_patch","arguments":{"input":` + string(quoted) + `}}]}}`},
		} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, files), func(t *testing.T) {
				res, err := tc.parser.Extract(strings.NewReader(tc.body), Source{Path: "/synthetic/rollout.jsonl"})
				if err != nil || len(res.Diagnostics) != 0 {
					t.Fatalf("extract: %v, diagnostics: %v", err, res.Diagnostics)
				}
				var events []model.Event
				for _, ev := range res.Events {
					if ev.ToolCallID == "patch" {
						events = append(events, ev)
					}
				}
				if len(events) != files {
					t.Fatalf("got %d file events, want %d", len(events), files)
				}
				for _, project := range []func(model.Event) model.Event{redact.EventWithContent, redact.EventWithRawContent} {
					bodies, size := 0, 0
					for i, ev := range events {
						if !strings.Contains(ev.ToolInputForAnalysis(), fmt.Sprintf("PATCH_CANARY_%d", files-1)) {
							t.Fatal("local analysis lost shared input")
						}
						out := project(ev)
						if out.ToolInput != "" {
							bodies++
						}
						if out.EventID != ev.EventID || out.FilePath != ev.FilePath || out.Evidence != ev.Evidence ||
							out.ToolInputBytes != ev.ToolInputBytesForAnalysis() || out.ToolInputTruncated {
							t.Fatal("projection changed identity, evidence or capture metadata")
						}
						if (i > 0) != slices.Contains(out.ContentOmitted, "tool_input") {
							t.Fatalf("event %d: unexpected omissions %v", i, out.ContentOmitted)
						}
						if err := out.Validate(); err != nil {
							t.Fatal(err)
						}
						encoded, err := json.Marshal(out)
						if err != nil {
							t.Fatal(err)
						}
						size += len(encoded) + 1
					}
					if bodies != 1 {
						t.Fatalf("exported %d copies of one patch, want 1", bodies)
					}
					// Even a large patch grows with its body plus file metadata,
					// not with the product of body size and touched-file count.
					if size > 4*len(quoted)+2000*files {
						t.Fatalf("output amplification: %d bytes", size)
					}
					t.Logf("%d files: %d source bytes, %d output bytes", files, len(tc.body), size)
				}
			})
		}
	}
}

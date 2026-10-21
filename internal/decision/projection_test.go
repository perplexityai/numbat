package decision

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestOriginalCallInputSurvivesPhaseAndBatchNormalization(t *testing.T) {
	for _, content := range []string{"raw", "redacted"} {
		t.Run(content, func(t *testing.T) {
			first := model.Event{
				EventType: model.EventFileWrite, ToolName: "apply_patch",
				ToolCallID: "patch", SessionID: "session", FilePath: "/synthetic/first.txt",
			}
			first.SetToolInput(json.RawMessage(`{"patch":"*** Begin Patch\n*** Add File: /synthetic/first.txt\n+first\n*** Add File: /synthetic/second.txt\n+second\n*** End Patch"}`))
			second := first
			second.FilePath = "/synthetic/second.txt"
			result := first
			result.EventType, result.FilePath = model.EventToolResult, ""
			result.SetToolResult(json.RawMessage(`{"ok":true}`))
			pre := ProjectBatch([]model.Event{first, second}, "pre", content)
			post := Project(result, "result", content)
			if !pre.Complete || !post.Complete || !bytes.Equal(pre.Action, post.Action) ||
				!bytes.Contains(pre.Action, []byte("first.txt")) || !bytes.Contains(pre.Action, []byte("second.txt")) {
				t.Fatalf("source action changed or lost a file: pre=%s post=%s", pre.Action, post.Action)
			}
			result.SetToolInput(json.RawMessage(`{"patch":"different source input"}`))
			if bytes.Equal(pre.Action, Project(result, "result", content).Action) {
				t.Fatal("genuinely changed source input became indistinguishable")
			}
		})
	}
}

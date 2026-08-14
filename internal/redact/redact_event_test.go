package redact

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/perplexityai/numbat/internal/model"
)

// canaries are self-describing secret shapes that String must mask. Each is
// planted into an Event field to prove Event routes that field through String.
const (
	canaryAWS   = "AKIAIOSFODNN7EXAMPLE"
	canaryOpen  = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	canaryPEM   = "-----BEGIN RSA PRIVATE KEY-----"
	canaryQuery = "https://s3.example/obj?X-Amz-Signature=deadbeefcafefeed1234567890"
	canarySig   = "deadbeefcafefeed1234567890"
)

// TestEventRedactsObservedFields plants a distinct secret in each of the four
// fields Event must scrub and confirms none survives, while a non-secret field
// is left untouched and detection-only fields are unchanged.
func TestEventRedactsObservedFields(t *testing.T) {
	in := model.Event{
		EventID:          "e1",
		EventType:        model.EventCommandExec,
		ToolName:         "Bash",
		Command:          "aws configure set aws_access_key_id " + canaryAWS,
		FilePath:         "/home/u/keys/" + canaryOpen,
		URL:              canaryQuery,
		ContentPreview:   "leaked key " + canaryPEM + " tail",
		MCPServer:        "server_api_key=" + canaryOpen,
		MCPTool:          "tool_password=" + canaryAWS,
		ProjectPath:      "/home/u/project",
		ApprovalReason:   "credential " + canaryOpen,
		Content:          "full body " + canaryOpen,
		ContentBytes:     64,
		ContentTruncated: true,
	}
	got := Event(in)

	for _, c := range []string{canaryAWS, canaryOpen, canaryPEM, canarySig} {
		if strings.Contains(got.Command, c) || strings.Contains(got.FilePath, c) ||
			strings.Contains(got.URL, c) || strings.Contains(got.ContentPreview, c) ||
			strings.Contains(got.MCPServer, c) || strings.Contains(got.MCPTool, c) ||
			strings.Contains(got.ApprovalReason, c) {
			t.Errorf("canary %q survived redaction in %+v", c, got)
		}
	}
	if !strings.Contains(got.Command, Mask) {
		t.Errorf("Command not masked: %q", got.Command)
	}
	if got.ProjectPath != "/home/u/project" {
		t.Errorf("ProjectPath = %q, want readable path", got.ProjectPath)
	}
	if got.Content != "" || got.ContentBytes != 0 || got.ContentTruncated {
		t.Errorf("default projection retained full content: %+v", got)
	}
	if got.ContentForAnalysis() != "" {
		t.Error("default projection retained hidden analysis content")
	}
	// Closed-vocabulary / non-secret fields are copied verbatim.
	if got.ToolName != "Bash" || got.EventType != model.EventCommandExec || got.EventID != "e1" {
		t.Errorf("non-observed fields altered: %+v", got)
	}
	// The input must not be mutated (Event returns a copy).
	if !strings.Contains(in.URL, canarySig) {
		t.Errorf("Event mutated its input: %q", in.URL)
	}
}

func TestEventBoundsPreviewAfterRedactionExpansion(t *testing.T) {
	in := model.Event{ContentPreview: strings.Repeat("Authorization: Bearer x ", 8)}
	got := Event(in)
	if utf8.RuneCountInString(got.ContentPreview) > model.ContentPreviewMaxRunes || !got.ContentPreviewTruncated {
		t.Fatalf("preview = %d runes, truncated=%t", utf8.RuneCountInString(got.ContentPreview), got.ContentPreviewTruncated)
	}
}

func TestEventRedactsSecretInProjectPath(t *testing.T) {
	got := Event(model.Event{ProjectPath: "/repo/" + canaryOpen})
	if strings.Contains(got.ProjectPath, canaryOpen) || !strings.Contains(got.ProjectPath, Mask) {
		t.Errorf("project path was not redacted: %q", got.ProjectPath)
	}
}

func TestEventWithContentRedactsRetainedBody(t *testing.T) {
	raw := strings.Repeat("context ", 30) + canaryOpen + "\nsecond line"
	in := model.Event{EventID: "e-content", EventType: model.EventPromptUser}
	in.SetContent(raw, true)

	got := EventWithContent(in)
	if got.Content == "" || strings.Contains(got.Content, canaryOpen) || !strings.Contains(got.Content, Mask) {
		t.Fatalf("full content was not redacted: %q", got.Content)
	}
	if got.ContentBytes != len(raw) || got.ContentTruncated {
		t.Fatalf("content metadata = %d/%v, want %d/false", got.ContentBytes, got.ContentTruncated, len(raw))
	}
	if !strings.Contains(got.Content, "\nsecond line") {
		t.Errorf("full content lost message formatting: %q", got.Content)
	}
	if got.ContentForAnalysis() != got.Content {
		t.Error("full projection retained an unredacted analysis copy")
	}
	if in.Content != "" || !strings.Contains(in.ContentForAnalysis(), canaryOpen) {
		t.Fatal("full-content projection mutated its input")
	}
}

func TestEventWithContentBoundsRedactionExpansion(t *testing.T) {
	raw := strings.Repeat("Authorization: Bearer x\n", model.ContentMaxBytes/24)
	in := model.Event{EventID: "e-expanded", EventType: model.EventPromptUser}
	in.SetContent(raw, true)

	got := EventWithContent(in)
	if len(got.Content) > model.ContentMaxBytes || !got.ContentTruncated {
		t.Fatalf("expanded content = %d bytes, truncated=%t", len(got.Content), got.ContentTruncated)
	}
}

func TestEventWithContentPreservesSourceSizeWhenBounded(t *testing.T) {
	raw := strings.Repeat("x", model.ContentMaxBytes+1)
	in := model.Event{EventID: "e-bounded", EventType: model.EventPromptUser}
	in.SetContent(raw, true)

	got := EventWithContent(in)
	if len(got.Content) != model.ContentMaxBytes || got.ContentBytes != len(raw) || !got.ContentTruncated {
		t.Fatalf("content metadata = %d/%d/%t", len(got.Content), got.ContentBytes, got.ContentTruncated)
	}
}

// TestEventEmptyFieldsStayEmpty confirms Event is nil/empty-safe: an empty field
// in yields an empty field out, so omitempty still drops it on emission.
func TestEventEmptyFieldsStayEmpty(t *testing.T) {
	got := Event(model.Event{EventID: "e2", EventType: model.EventPromptUser})
	if got.Command != "" || got.FilePath != "" || got.URL != "" || got.ContentPreview != "" ||
		got.ProjectPath != "" || got.ApprovalReason != "" {
		t.Errorf("empty fields became non-empty: %+v", got)
	}
}

// TestEventsSliceRedactsEachAndPreservesNil confirms the slice helper redacts
// every element and maps nil to nil (so a session with no events stays nil).
func TestEventsSliceRedactsEachAndPreservesNil(t *testing.T) {
	if Events(nil) != nil {
		t.Errorf("Events(nil) should be nil")
	}
	out := Events([]model.Event{
		{Command: "echo " + canaryAWS},
		{URL: canaryQuery},
	})
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if strings.Contains(out[0].Command, canaryAWS) {
		t.Errorf("element 0 not redacted: %q", out[0].Command)
	}
	if strings.Contains(out[1].URL, canarySig) {
		t.Errorf("element 1 not redacted: %q", out[1].URL)
	}
}

func TestEventsWithContentPreservesNil(t *testing.T) {
	if EventsWithContent(nil) != nil {
		t.Error("EventsWithContent(nil) should be nil")
	}
}

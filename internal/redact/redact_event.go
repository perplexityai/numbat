package redact

import (
	"bytes"
	"encoding/json"

	"github.com/perplexityai/numbat/internal/model"
)

// Event returns the default preview-only projection: observed fields are routed
// through String and full message content is omitted. It is the shared output
// guard for event and timeline records.
//
// Callers evaluate rules before applying this output guard. Generic argument
// previews are already sanitized by ToolInputPreview before truncation; typed
// detection fields remain unredacted until emission. String
// is nil/empty-safe (empty in, empty out), so an empty field stays empty and
// omitempty still drops it.
//
// This lives in package redact (which imports model) because model is a leaf and
// importing it here introduces no cycle, so a single helper can serve both the
// event sink and the timeline renderer instead of duplicating the field list at
// each call site.
func Event(ev model.Event) model.Event {
	ev.ToolInputBytes, ev.ToolInputTruncated = ev.ToolInputBytesForAnalysis(), ev.ToolInputTruncatedForAnalysis()
	ev.ToolResultBytes, ev.ToolResultTruncated = ev.ToolResultBytesForAnalysis(), ev.ToolResultTruncatedForAnalysis()
	ev = ev.WithoutAnalysisContent()
	ev.Command = String(ev.Command)
	ev.FilePath = String(ev.FilePath)
	ev.URL = String(ev.URL)
	var previewTruncated bool
	ev.ContentPreview, previewTruncated = model.NormalizeContentPreviewWithTruncation(String(ev.ContentPreview))
	ev.ContentPreviewTruncated = ev.ContentPreviewTruncated || previewTruncated
	ev.ToolInput, ev.ToolResult = "", ""
	ev.Content = ""
	ev.ContentBytes = 0
	ev.ContentTruncated = false
	ev.MCPServer = String(ev.MCPServer)
	ev.MCPTool = String(ev.MCPTool)
	ev.ProjectPath = String(ev.ProjectPath)
	ev.ApprovalReason = String(ev.ApprovalReason)
	return ev
}

// EventWithContent returns the explicit full-content projection. The retained
// body is still redacted, while its byte count describes the mapped text before
// Numbat's content bound and output redaction were applied.
func EventWithContent(ev model.Event) model.Event {
	input, result := ev.ToolInputForAnalysis(), ev.ToolResultForAnalysis()
	inputBytes, resultBytes := ev.ToolInputBytesForAnalysis(), ev.ToolResultBytesForAnalysis()
	inputTruncated, resultTruncated := ev.ToolInputTruncatedForAnalysis(), ev.ToolResultTruncatedForAnalysis()
	ev = EventWithMessageContent(ev, false)
	ev.ToolInput, ev.ToolInputTruncated = payload(input, inputTruncated)
	ev.ToolResult, ev.ToolResultTruncated = payload(result, resultTruncated)
	ev.ToolInputBytes, ev.ToolResultBytes = inputBytes, resultBytes
	return ev
}

// EventWithMessageContent includes only the retained conversation body. Raw
// preserves that body without redaction; other fields use the preview policy.
// Tool byte counts and truncation flags remain available even without bodies.
func EventWithMessageContent(ev model.Event, raw bool) model.Event {
	content := ev.ContentForAnalysis()
	contentBytes := ev.ContentBytesForAnalysis()
	contentTruncated := ev.ContentTruncatedForAnalysis()
	ev = Event(ev)
	if content == "" {
		return ev
	}
	ev.Content = content
	ev.ContentBytes = contentBytes
	ev.ContentTruncated = contentTruncated
	if !raw {
		var outputTruncated bool
		ev.Content, outputTruncated = model.LimitContent(String(content))
		ev.ContentTruncated = contentTruncated || outputTruncated
	}
	return ev
}

// Events returns a new slice holding the redacted copy of each event in evs,
// leaving the input untouched. It is the slice form the timeline JSON path uses,
// where a whole []model.Event is marshaled at once.
func Events(evs []model.Event) []model.Event {
	if evs == nil {
		return nil
	}
	out := make([]model.Event, len(evs))
	for i, ev := range evs {
		out[i] = Event(ev)
	}
	return out
}

// EventsWithContent is the slice form of EventWithContent.
func EventsWithContent(evs []model.Event) []model.Event {
	if evs == nil {
		return nil
	}
	out := make([]model.Event, len(evs))
	for i, ev := range evs {
		out[i] = EventWithContent(ev)
	}
	return out
}

// payload masks the whole JSON value before applying any output bound. A
// truncated or malformed JSON fragment cannot be safely redacted by key.
func payload(text string, truncated bool) (string, bool) {
	if text == "" {
		return "", truncated
	}
	if truncated {
		return "[payload omitted: incomplete JSON]", true
	}
	masked, err := redactedJSONValue([]byte(text))
	if err != nil {
		return "[payload omitted: JSON redaction failed]", true
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(masked); err != nil {
		return "[payload omitted: encoding error]", true
	}
	return model.LimitToolPayload(string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))))
}

// EventWithRawContent is the explicit unredacted event projection. Raw here
// means source-provided mapped content, not a byte-for-byte source transcript.
func EventWithRawContent(ev model.Event) model.Event {
	ev.Content, ev.ContentBytes, ev.ContentTruncated = ev.ContentForAnalysis(), ev.ContentBytesForAnalysis(), ev.ContentTruncatedForAnalysis()
	ev.ToolInput, ev.ToolInputBytes, ev.ToolInputTruncated = ev.ToolInputForAnalysis(), ev.ToolInputBytesForAnalysis(), ev.ToolInputTruncatedForAnalysis()
	ev.ToolResult, ev.ToolResultBytes, ev.ToolResultTruncated = ev.ToolResultForAnalysis(), ev.ToolResultBytesForAnalysis(), ev.ToolResultTruncatedForAnalysis()
	return ev.WithoutAnalysisContent()
}

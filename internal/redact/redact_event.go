package redact

import "github.com/perplexityai/numbat/internal/model"

// Event returns the default preview-only projection: observed fields are routed
// through String and full message content is omitted. It is the shared output
// guard for event and timeline records.
//
// Redaction runs on OUTPUT only: callers evaluate rules against the UNREDACTED
// event first, then redact for emission, so detection is never affected. String
// is nil/empty-safe (empty in, empty out), so an empty field stays empty and
// omitempty still drops it.
//
// This lives in package redact (which imports model) because model is a leaf and
// importing it here introduces no cycle, so a single helper can serve both the
// event sink and the timeline renderer instead of duplicating the field list at
// each call site.
func Event(ev model.Event) model.Event {
	ev = ev.WithoutAnalysisContent()
	ev.Command = String(ev.Command)
	ev.FilePath = String(ev.FilePath)
	ev.URL = String(ev.URL)
	var previewTruncated bool
	ev.ContentPreview, previewTruncated = model.NormalizeContentPreviewWithTruncation(String(ev.ContentPreview))
	ev.ContentPreviewTruncated = ev.ContentPreviewTruncated || previewTruncated
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
	content := ev.ContentForAnalysis()
	contentBytes := ev.ContentBytesForAnalysis()
	contentTruncated := ev.ContentTruncatedForAnalysis()
	ev = Event(ev)
	if content == "" {
		return ev
	}
	var outputTruncated bool
	ev.Content, outputTruncated = model.LimitContent(String(content))
	ev.ContentBytes = contentBytes
	ev.ContentTruncated = contentTruncated || outputTruncated
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

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
	ev.Command = String(ev.Command)
	ev.FilePath = String(ev.FilePath)
	ev.URL = String(ev.URL)
	ev.ContentPreview = String(ev.ContentPreview)
	ev.Content = ""
	ev.ContentBytes = 0
	ev.ContentTruncated = false
	ev.MCPServer = String(ev.MCPServer)
	ev.MCPTool = String(ev.MCPTool)
	ev.ProjectPath = String(ev.ProjectPath)
	ev.ApprovalReason = String(ev.ApprovalReason)
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

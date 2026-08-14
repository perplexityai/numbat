package model

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// eventFields is the co-occurrence contract for discriminating fields. Envelope
// and session-context fields are valid on every event type and are not listed.
var eventFields = map[EventType][]string{
	// Lifecycle envelopes carry no discriminating value fields.
	EventSessionStart: {},
	EventSessionEnd:   {},

	// Conversation turns may carry a bounded message body in addition to the
	// preview shared by every event.
	EventPromptUser:       {"content", "content_bytes", "content_truncated"},
	EventMessageAssistant: {"content", "content_bytes", "content_truncated"},
	EventMessageReasoning: {"content", "content_bytes", "content_truncated"},

	// Tool identity, correlation, and structured target fields.
	EventToolCall: {"tool_name", "tool_call_id", "mcp_server", "mcp_tool", "url", "file_path", "decision"},
	// Result correlation and source-provided status.
	EventToolResult: {"tool_name", "tool_call_id", "mcp_server", "mcp_tool", "decision"},

	// Command requests and results.
	EventCommandExec:   {"command", "tool_name", "tool_call_id", "decision"},
	EventCommandResult: {"command", "tool_name", "tool_call_id", "exit_code", "duration_ms", "decision"},

	// File activity and optional edit summaries.
	EventFileRead:   {"file_path", "tool_name", "tool_call_id", "decision"},
	EventFileWrite:  {"file_path", "tool_name", "tool_call_id", "decision", "diff_sha256", "diff_bytes"},
	EventFileDelete: {"file_path", "tool_name", "tool_call_id", "diff_sha256", "diff_bytes"},

	// Permission decisions and their guarded tool.
	EventPermissionRequested: {"tool_name", "tool_call_id", "decision", "approval_required", "approval_decision", "approval_reason"},
	EventPermissionApproved:  {"tool_name", "tool_call_id", "decision", "approval_required", "approval_decision", "approval_reason"},
	EventPermissionDenied:    {"tool_name", "tool_call_id", "decision", "approval_required", "approval_decision", "approval_reason"},

	// Agent/MCP configuration: config.agent marks a change in the active agent
	// persona; config.mcp describes the available MCP tool surface.
	EventConfigAgent: {},
	EventConfigMCP:   {"mcp_server", "mcp_tool"},

	// Structured network targets and source correlation.
	EventNetworkIndicator: {"url", "tool_name", "mcp_server", "mcp_tool", "tool_call_id", "decision"},
}

// valueBearingFields lets Validate detect fields set outside eventFields.
var valueBearingFields = []struct {
	name string
	set  func(Event) bool
}{
	{"command", func(e Event) bool { return e.Command != "" }},
	{"exit_code", func(e Event) bool { return e.ExitCode != nil }},
	{"duration_ms", func(e Event) bool { return e.DurationMs != nil }},
	{"file_path", func(e Event) bool { return e.FilePath != "" }},
	{"diff_sha256", func(e Event) bool { return e.DiffSHA256 != "" }},
	{"diff_bytes", func(e Event) bool { return e.DiffBytes != 0 }},
	{"tool_name", func(e Event) bool { return e.ToolName != "" }},
	{"tool_call_id", func(e Event) bool { return e.ToolCallID != "" }},
	{"mcp_server", func(e Event) bool { return e.MCPServer != "" }},
	{"mcp_tool", func(e Event) bool { return e.MCPTool != "" }},
	{"url", func(e Event) bool { return e.URL != "" }},
	{"decision", func(e Event) bool { return e.Decision != "" }},
	{"approval_required", func(e Event) bool { return e.ApprovalRequired != nil }},
	{"approval_decision", func(e Event) bool { return e.ApprovalDecision != "" }},
	{"approval_reason", func(e Event) bool { return e.ApprovalReason != "" }},
	{"content", func(e Event) bool { return e.Content != "" || e.analysisContent != "" }},
	{"content_bytes", func(e Event) bool { return e.ContentBytes != 0 || e.analysisContentBytes != 0 }},
	{"content_truncated", func(e Event) bool { return e.ContentTruncated || e.analysisContentTruncated }},
}

// Validate enforces identity, closed vocabularies, hashes, counters, and field
// co-occurrence before detection or emission. Optional vocabulary fields accept
// their documented empty value.
func (e Event) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("event %s: invalid schema_version %q", e.EventID, e.SchemaVersion)
	}
	if e.EventID == "" {
		return fmt.Errorf("event: empty event_id")
	}
	if e.EventType == "" {
		return fmt.Errorf("event %s: empty event_type", e.EventID)
	}
	allowed, ok := eventFields[e.EventType]
	if !ok {
		return fmt.Errorf("event %s: unknown event_type %q", e.EventID, e.EventType)
	}
	if !IsValidConfidence(e.Confidence) {
		return fmt.Errorf("event %s: invalid confidence %q", e.EventID, e.Confidence)
	}
	if !IsValidSourceAgent(e.SourceAgent) {
		return fmt.Errorf("event %s: invalid source_agent %q", e.EventID, e.SourceAgent)
	}
	if !IsValidSourceType(e.SourceType) {
		return fmt.Errorf("event %s: invalid source_type %q", e.EventID, e.SourceType)
	}
	if e.Actor != "" && !IsValidActor(e.Actor) {
		return fmt.Errorf("event %s: invalid actor %q", e.EventID, e.Actor)
	}
	if !IsValidDecision(e.Decision) {
		return fmt.Errorf("event %s: invalid decision %q", e.EventID, e.Decision)
	}
	if !IsValidDecision(e.ApprovalDecision) {
		return fmt.Errorf("event %s: invalid approval_decision %q", e.EventID, e.ApprovalDecision)
	}
	if e.Evidence.ArtifactType == "" {
		return fmt.Errorf("event %s: empty evidence.artifact_type", e.EventID)
	}
	seenTags := make(map[string]struct{}, len(e.Tags))
	for _, tag := range e.Tags {
		if strings.TrimSpace(tag) == "" {
			return fmt.Errorf("event %s: empty tag", e.EventID)
		}
		if tag != strings.TrimSpace(tag) {
			return fmt.Errorf("event %s: tag %q has leading or trailing whitespace", e.EventID, tag)
		}
		if _, exists := seenTags[tag]; exists {
			return fmt.Errorf("event %s: duplicate tag %q", e.EventID, tag)
		}
		seenTags[tag] = struct{}{}
	}
	if e.Evidence.Line < 0 {
		return fmt.Errorf("event %s: invalid evidence.line %d", e.EventID, e.Evidence.Line)
	}
	if e.Evidence.RowID < 0 {
		return fmt.Errorf("event %s: invalid evidence.rowid %d", e.EventID, e.Evidence.RowID)
	}
	if e.Evidence.SHA256 != "" && !isLowerHex64(e.Evidence.SHA256) {
		return fmt.Errorf("event %s: invalid evidence.sha256", e.EventID)
	}
	if e.DiffSHA256 != "" && !isLowerHex64(e.DiffSHA256) {
		return fmt.Errorf("event %s: invalid diff_sha256", e.EventID)
	}
	if e.DiffBytes < 0 {
		return fmt.Errorf("event %s: invalid diff_bytes %d", e.EventID, e.DiffBytes)
	}
	if e.DurationMs != nil && *e.DurationMs < 0 {
		return fmt.Errorf("event %s: invalid duration_ms %d", e.EventID, *e.DurationMs)
	}
	if e.ContentBytes < 0 {
		return fmt.Errorf("event %s: invalid content_bytes %d", e.EventID, e.ContentBytes)
	}
	if utf8.RuneCountInString(e.ContentPreview) > ContentPreviewMaxRunes {
		return fmt.Errorf("event %s: content_preview exceeds %d runes", e.EventID, ContentPreviewMaxRunes)
	}
	if len(e.Content) > ContentMaxBytes {
		return fmt.Errorf("event %s: content exceeds %d bytes", e.EventID, ContentMaxBytes)
	}
	if len(e.analysisContent) > ContentMaxBytes {
		return fmt.Errorf("event %s: analysis content exceeds %d bytes", e.EventID, ContentMaxBytes)
	}
	if e.Content != "" && e.ContentBytes == 0 {
		return fmt.Errorf("event %s: content requires content_bytes", e.EventID)
	}
	if e.Content == "" && (e.ContentBytes != 0 || e.ContentTruncated) {
		return fmt.Errorf("event %s: content metadata requires content", e.EventID)
	}
	if e.analysisContent != "" && e.analysisContentBytes == 0 {
		return fmt.Errorf("event %s: analysis content requires content_bytes", e.EventID)
	}
	if e.analysisContent == "" && (e.analysisContentBytes != 0 || e.analysisContentTruncated) {
		return fmt.Errorf("event %s: analysis content metadata requires content", e.EventID)
	}
	if e.Content != "" && e.analysisContent != "" {
		return fmt.Errorf("event %s: content has both emitted and analysis values", e.EventID)
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, f := range allowed {
		allow[f] = struct{}{}
	}
	var bad []string
	for _, vf := range valueBearingFields {
		if vf.set(e) {
			if _, okk := allow[vf.name]; !okk {
				bad = append(bad, vf.name)
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("event %s: field(s) %s not allowed on event_type %q",
			e.EventID, strings.Join(bad, ", "), e.EventType)
	}
	return nil
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

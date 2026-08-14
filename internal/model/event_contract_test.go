package model

import (
	"strings"
	"testing"
)

const validSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validEvent(ev Event) Event {
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = SchemaVersion
	}
	if ev.EventID == "" {
		ev.EventID = "event-fixture"
	}
	if ev.SourceAgent == "" {
		ev.SourceAgent = AgentClaudeCode
	}
	if ev.SourceType == "" {
		ev.SourceType = SourceArtifact
	}
	if ev.Confidence == "" {
		ev.Confidence = ConfidenceHigh
	}
	if ev.Evidence.ArtifactType == "" {
		ev.Evidence.ArtifactType = "test_artifact"
	}
	return ev
}

// Every event_type in the closed vocabulary must declare an allow-list, or
// Validate would reject a legitimately-typed event as "unknown event_type".
func TestEventFieldsCoversVocabulary(t *testing.T) {
	for et := range eventTypes {
		if _, ok := eventFields[et]; !ok {
			t.Errorf("eventFields missing allow-list for %q", et)
		}
	}
	for et := range eventFields {
		if !IsValidEventType(et) {
			t.Errorf("eventFields has entry for non-vocabulary type %q", et)
		}
	}
}

// A representative valid event of each major type passes Validate. Every
// fixture carries the required schema/envelope/evidence values so it exercises
// the co-occurrence contract without tripping the shape checks; an actor is
// supplied where one is natural.
func TestValidatePassesValidEvents(t *testing.T) {
	code := 0
	valid := []Event{
		validEvent(Event{EventID: "a", EventType: EventSessionStart, Model: "claude", GitBranch: "main", CLIVersion: "1.0", SubAgent: "code-reviewer"}),
		validEvent(Event{EventID: "b", EventType: EventPromptUser, Actor: ActorUser, ContentPreview: "hello", Content: "hello", ContentBytes: 5}),
		validEvent(Event{EventID: "c", EventType: EventMessageAssistant, Actor: ActorAssistant, ContentPreview: "hi"}),
		validEvent(Event{EventID: "d", EventType: EventCommandExec, Command: "cat .env", ToolName: "Bash", ToolCallID: "t1"}),
		validEvent(Event{EventID: "e", EventType: EventCommandResult, ToolCallID: "t1", ExitCode: &code}),
		validEvent(Event{EventID: "f", EventType: EventFileRead, FilePath: "/x/.env", ToolName: "Read", ToolCallID: "t2"}),
		validEvent(Event{EventID: "g", EventType: EventFileWrite, FilePath: "/x/out", ToolName: "Write", Decision: DecisionDenied}),
		validEvent(Event{EventID: "h", EventType: EventFileDelete, FilePath: "/x/old", ToolName: "apply_patch"}),
		validEvent(Event{EventID: "i", EventType: EventToolCall, ToolName: "mcp__github__create_issue", ToolCallID: "t3", MCPServer: "github", MCPTool: "create_issue"}),
		validEvent(Event{EventID: "j", EventType: EventToolResult, ToolCallID: "t3"}),
		validEvent(Event{EventID: "k", EventType: EventNetworkIndicator, Confidence: ConfidenceMedium, URL: "https://api.example.com", MCPServer: "fetch", MCPTool: "fetch"}),
		validEvent(Event{EventID: "l", EventType: EventConfigAgent, SubAgent: "code-reviewer"}),
	}
	for _, ev := range valid {
		if err := ev.Validate(); err != nil {
			t.Errorf("valid %q event failed Validate: %v", ev.EventType, err)
		}
	}
}

// A value-bearing field set outside its event_type's allow-list fails with a
// message naming the offending field and the type.
func TestValidateRejectsOutOfContractField(t *testing.T) {
	ev := validEvent(Event{EventID: "x", EventType: EventFileWrite, FilePath: "/x/out", MCPServer: "github"})
	err := ev.Validate()
	if err == nil {
		t.Fatalf("expected Validate to reject mcp_server on file.write")
	}
	if !strings.Contains(err.Error(), "mcp_server") || !strings.Contains(err.Error(), string(EventFileWrite)) {
		t.Errorf("error should name the field and type: %v", err)
	}
}

func TestValidateRejectsContentOnActionEvent(t *testing.T) {
	tests := []Event{
		validEvent(Event{EventID: "emitted", EventType: EventFileRead, FilePath: "/x/file", Content: "file body", ContentBytes: 9}),
		validEvent(Event{EventID: "analysis", EventType: EventFileRead, FilePath: "/x/file"}),
	}
	tests[1].SetContent("file body", true)
	for _, ev := range tests {
		err := ev.Validate()
		if err == nil || !strings.Contains(err.Error(), "content") {
			t.Fatalf("Validate(%s) error = %v, want out-of-contract content", ev.EventID, err)
		}
	}
}

// The additive v0.1 fields are accepted on their declared event types: a
// duration on a command.result, a diff digest+size on a file.write, and the
// approval payload on a permission.* event.
func TestValidateAcceptsAdditiveFields(t *testing.T) {
	dur := int64(0)
	req := true
	valid := []Event{
		validEvent(Event{EventID: "a", EventType: EventCommandResult, ToolCallID: "t1", DurationMs: &dur}),
		validEvent(Event{EventID: "b", EventType: EventFileWrite, FilePath: "/x/out", DiffSHA256: validSHA256, DiffBytes: 42}),
		validEvent(Event{EventID: "c", EventType: EventFileDelete, FilePath: "/x/old", DiffSHA256: validSHA256, DiffBytes: 7}),
		validEvent(Event{EventID: "d", EventType: EventPermissionRequested, SourceType: SourceHook, Confidence: ConfidenceMedium, ToolCallID: "call-1", Decision: DecisionAsked, ApprovalRequired: &req, ApprovalDecision: DecisionAsked, ApprovalReason: "writes outside workspace"}),
		validEvent(Event{EventID: "e", EventType: EventPermissionDenied, SourceType: SourceHook, Confidence: ConfidenceMedium, ApprovalDecision: DecisionDenied}),
		validEvent(Event{EventID: "f", EventType: EventSessionEnd, SubAgent: "code-reviewer"}),
		validEvent(Event{EventID: "g", EventType: EventCommandExec, Command: "go test ./...", SubAgent: "code-reviewer"}),
		validEvent(Event{EventID: "h", EventType: EventCommandResult, Command: "go test ./...", Decision: DecisionAllowed}),
		validEvent(Event{EventID: "i", EventType: EventToolResult, ToolName: "grep", Decision: DecisionDenied}),
	}
	for _, ev := range valid {
		if err := ev.Validate(); err != nil {
			t.Errorf("valid %q event with additive fields failed Validate: %v", ev.EventType, err)
		}
	}
}

// Each additive field is rejected outside its allow-list, proving the gating is
// per-event-type and not a blanket allow.
func TestValidateRejectsAdditiveFieldOutOfContract(t *testing.T) {
	dur := int64(5)
	req := true
	cases := []struct {
		name  string
		ev    Event
		field string
	}{
		{"duration_ms on file.write", validEvent(Event{EventID: "x", EventType: EventFileWrite, FilePath: "/x", DurationMs: &dur}), "duration_ms"},
		{"diff on command.exec", validEvent(Event{EventID: "x", EventType: EventCommandExec, Command: "ls", DiffSHA256: validSHA256, DiffBytes: 2}), "diff_sha256"},
		{"diff on file.read", validEvent(Event{EventID: "x", EventType: EventFileRead, FilePath: "/x", DiffBytes: 9}), "diff_bytes"},
		{"approval on tool.call", validEvent(Event{EventID: "x", EventType: EventToolCall, ToolName: "Bash", ApprovalRequired: &req}), "approval_required"},
		{"approval_decision on file.write", validEvent(Event{EventID: "x", EventType: EventFileWrite, FilePath: "/x", ApprovalDecision: DecisionAllowed}), "approval_decision"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.ev.Validate()
			if err == nil {
				t.Fatalf("expected Validate to reject %s on %q", c.field, c.ev.EventType)
			}
			if !strings.Contains(err.Error(), c.field) || !strings.Contains(err.Error(), string(c.ev.EventType)) {
				t.Errorf("error should name field %q and type %q: %v", c.field, c.ev.EventType, err)
			}
		})
	}
}

// Permission events may carry the guarded tool and its correlation ID.
func TestValidateAcceptsPermissionToolIdentity(t *testing.T) {
	req := true
	perms := []Event{
		validEvent(Event{EventID: "a", EventType: EventPermissionRequested, SourceType: SourceHook, Confidence: ConfidenceMedium, ToolName: "Bash", ToolCallID: "call-a", Decision: DecisionAsked, ApprovalRequired: &req, ApprovalDecision: DecisionAsked, ApprovalReason: "shell command"}),
		validEvent(Event{EventID: "b", EventType: EventPermissionApproved, SourceType: SourceHook, Confidence: ConfidenceMedium, ToolName: "Write", ToolCallID: "call-b", Decision: DecisionAllowed, ApprovalDecision: DecisionAllowed}),
		validEvent(Event{EventID: "c", EventType: EventPermissionDenied, SourceType: SourceHook, Confidence: ConfidenceMedium, ToolName: "WebFetch", ToolCallID: "call-c", Decision: DecisionDenied, ApprovalDecision: DecisionDenied}),
	}
	for _, ev := range perms {
		if err := ev.Validate(); err != nil {
			t.Errorf("permission event %q with tool identity failed Validate: %v", ev.EventType, err)
		}
	}
}

// A command.result populated the way the hook post-tool mapper populates it —
// the executed command, the shell tool's name, an exit code, and a duration —
// passes Validate. internal/hook.mapPostTool echoes command and tool_name onto
// the result alongside exit_code/duration_ms, so all four are on the allow-list.
func TestValidateAcceptsCommandResultToolName(t *testing.T) {
	code := 0
	dur := int64(1500)
	results := []Event{
		validEvent(Event{EventID: "a", EventType: EventCommandResult, SourceType: SourceHook, Confidence: ConfidenceMedium, Command: "go test ./...", ToolName: "Bash", ExitCode: &code, DurationMs: &dur}),
		validEvent(Event{EventID: "b", EventType: EventCommandResult, SourceType: SourceHook, Confidence: ConfidenceMedium, Command: "ls", ToolName: "Bash"}),
	}
	for _, ev := range results {
		if err := ev.Validate(); err != nil {
			t.Errorf("command.result %q with command+tool_name failed Validate: %v", ev.EventID, err)
		}
	}
}

// A tool.result populated the way the hook post-tool mapper populates it — the
// tool's name, and the mcp_server/mcp_tool split for an MCP tool — passes
// Validate. internal/hook.mapPostTool always stamps tool_name on the generic
// result and splits an mcp__server__tool name, so those fields are allowed.
func TestValidateAcceptsToolResultToolName(t *testing.T) {
	results := []Event{
		validEvent(Event{EventID: "a", EventType: EventToolResult, SourceType: SourceHook, Confidence: ConfidenceMedium, ToolName: "TodoWrite"}),
		validEvent(Event{EventID: "b", EventType: EventToolResult, SourceType: SourceHook, Confidence: ConfidenceMedium, ToolName: "mcp__github__create_issue", MCPServer: "github", MCPTool: "create_issue"}),
	}
	for _, ev := range results {
		if err := ev.Validate(); err != nil {
			t.Errorf("tool.result %q with tool_name failed Validate: %v", ev.EventID, err)
		}
	}
}

// The additive fields are registered on the CEL event view so a rule can
// reference them at load time without an unknown-field error.
func TestAdditiveFieldsAreInCELFieldSet(t *testing.T) {
	for _, f := range []string{"duration_ms", "approval_required", "approval_decision", "approval_reason", "diff_sha256", "diff_bytes", "sub_agent", "content", "content_bytes", "content_truncated", "content_preview_truncated"} {
		if !IsCELField(f) {
			t.Errorf("event field %q not registered for CEL", f)
		}
	}
}

// An unknown or empty event_type is rejected outright.
func TestValidateRejectsUnknownType(t *testing.T) {
	if err := validEvent(Event{EventID: "x"}).Validate(); err == nil {
		t.Errorf("empty event_type should fail")
	}
	if err := validEvent(Event{EventID: "y", EventType: "bogus.type"}).Validate(); err == nil {
		t.Errorf("unknown event_type should fail")
	}
}

func TestValidateRejectsMalformedSchemaFields(t *testing.T) {
	neg := int64(-1)
	base := func() Event {
		return validEvent(Event{
			EventID:    "x",
			EventType:  EventFileWrite,
			FilePath:   "/x/out",
			ToolName:   "Write",
			DiffSHA256: validSHA256,
			DiffBytes:  42,
			DurationMs: nil,
		})
	}
	cases := []struct {
		name    string
		mutate  func(*Event)
		wantMsg string
	}{
		{"bad schema_version", func(e *Event) { e.SchemaVersion = "9.9.9" }, "schema_version"},
		{"empty event_id", func(e *Event) { e.EventID = "" }, "event_id"},
		{"empty evidence artifact", func(e *Event) { e.Evidence.ArtifactType = "" }, "evidence.artifact_type"},
		{"empty tag", func(e *Event) { e.Tags = []string{"network", " "} }, "tag"},
		{"tag whitespace", func(e *Event) { e.Tags = []string{" network"} }, "whitespace"},
		{"duplicate tag", func(e *Event) { e.Tags = []string{"network", "network"} }, "duplicate tag"},
		{"bad evidence sha", func(e *Event) { e.Evidence.SHA256 = "abc" }, "evidence.sha256"},
		{"negative evidence line", func(e *Event) { e.Evidence.Line = -1 }, "evidence.line"},
		{"negative evidence rowid", func(e *Event) { e.Evidence.RowID = -1 }, "evidence.rowid"},
		{"bad diff sha", func(e *Event) { e.DiffSHA256 = "abc" }, "diff_sha256"},
		{"uppercase diff sha", func(e *Event) { e.DiffSHA256 = strings.ToUpper(validSHA256) }, "diff_sha256"},
		{"negative diff bytes", func(e *Event) { e.DiffBytes = -1 }, "diff_bytes"},
		{"negative content bytes", func(e *Event) { e.ContentBytes = -1 }, "content_bytes"},
		{"overlong content preview", func(e *Event) { e.ContentPreview = strings.Repeat("x", ContentPreviewMaxRunes+1) }, "content_preview"},
		{"oversized content", func(e *Event) { e.Content = strings.Repeat("x", ContentMaxBytes+1) }, "content exceeds"},
		{"content without byte count", func(e *Event) { e.Content = "hello" }, "content_bytes"},
		{"byte count without content", func(e *Event) { e.ContentBytes = 5 }, "requires content"},
		{"truncation without content", func(e *Event) { e.ContentTruncated = true }, "requires content"},
		{"negative duration", func(e *Event) {
			e.EventType = EventCommandResult
			e.FilePath = ""
			e.ToolName = "Bash"
			e.DiffSHA256 = ""
			e.DiffBytes = 0
			e.DurationMs = &neg
		}, "duration_ms"},
		{"bad approval decision", func(e *Event) {
			e.EventType = EventPermissionDenied
			e.FilePath = ""
			e.ToolName = "Bash"
			e.DiffSHA256 = ""
			e.DiffBytes = 0
			e.ApprovalDecision = "maybe"
		}, "approval_decision"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := base()
			c.mutate(&ev)
			err := ev.Validate()
			if err == nil {
				t.Fatalf("expected Validate to reject %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("error should name %q: %v", c.wantMsg, err)
			}
		})
	}
}

// An out-of-vocabulary value in a closed-vocabulary field is rejected at the
// contract boundary. The required fields (source_agent, source_type, confidence)
// also reject the empty string; the optional fields (actor, decision) reject only a
// non-empty bad value. Each case starts from a fully-valid event and corrupts
// exactly one field, so the error names that field.
func TestValidateRejectsBadVocabularyValue(t *testing.T) {
	base := func() Event {
		return validEvent(Event{EventID: "x", EventType: EventFileWrite, FilePath: "/x/out", ToolName: "Write"})
	}
	cases := []struct {
		name    string
		mutate  func(*Event)
		wantMsg string
	}{
		{"bad confidence", func(e *Event) { e.Confidence = "certain" }, "confidence"},
		{"empty confidence", func(e *Event) { e.Confidence = "" }, "confidence"},
		{"bad source_agent", func(e *Event) { e.SourceAgent = "claude" }, "source_agent"},
		{"empty source_agent", func(e *Event) { e.SourceAgent = "" }, "source_agent"},
		{"bad source_type", func(e *Event) { e.SourceType = "syslog" }, "source_type"},
		{"empty source_type", func(e *Event) { e.SourceType = "" }, "source_type"},
		{"bad actor", func(e *Event) { e.Actor = "robot" }, "actor"},
		{"bad decision", func(e *Event) { e.Decision = "maybe" }, "decision"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := base()
			c.mutate(&ev)
			err := ev.Validate()
			if err == nil {
				t.Fatalf("expected Validate to reject %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("error should name %q: %v", c.wantMsg, err)
			}
		})
	}
}

// The empty-allowed optional fields pass: an event with no actor and no
// decision is valid (DecisionUnknown is "" by design, and many event types
// carry no actor). This is the companion to TestValidateRejectsBadVocabularyValue
// proving the optional fields are not made mandatory.
func TestValidateAcceptsEmptyOptionalVocabulary(t *testing.T) {
	ev := validEvent(Event{EventID: "x", EventType: EventFileRead, FilePath: "/x/.env", ToolName: "Read"})
	if ev.Actor != "" || ev.Decision != "" {
		t.Fatalf("fixture should leave actor and decision empty")
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event with empty actor and decision should pass: %v", err)
	}
	// A valid non-empty actor and decision also pass.
	ev.Actor = ActorUser
	ev.Decision = DecisionAllowed
	if err := ev.Validate(); err != nil {
		t.Errorf("event with valid actor and decision should pass: %v", err)
	}
}

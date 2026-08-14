package finding

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

func sampleMatch() rule.Match {
	return rule.Match{
		Rule: rule.Rule{
			ID:       "secrets.agent_read_env",
			Title:    "Agent read .env file",
			Severity: model.SeverityHigh,
			Version:  "1.0",
			Tags:     []string{"secret_file_read"},
		},
		Event: model.Event{
			EventID:     "u1#1",
			CaseID:      "case-1",
			SourceAgent: model.AgentClaudeCode,
			SourceType:  model.SourceArtifact,
			Timestamp:   "2026-06-02T10:00:01Z",
			SessionID:   "s-1",
			Model:       "claude-sonnet-4",
			SubAgent:    "code-reviewer",
			ProjectPath: "/home/dev/secret-proj",
			EventType:   model.EventFileRead,
			FilePath:    "/home/dev/secret-proj/.env",
			Tags:        []string{"agent_activity"},
			Confidence:  model.ConfidenceHigh,
			Evidence: model.Evidence{
				ArtifactType: "claude_jsonl",
				LocalPath:    "/cases/session.jsonl",
				Line:         2,
				JSONPointer:  "/message/content/1",
				SHA256:       strings.Repeat("a", 64),
			},
		},
	}
}

func TestFromMatchShape(t *testing.T) {
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	f := FromMatch(sampleMatch(), Options{Now: now})

	if f.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema_version = %q", f.SchemaVersion)
	}
	if f.RuleID != "secrets.agent_read_env" || f.RuleVersion != "1.0" || f.Severity != model.SeverityHigh {
		t.Errorf("rule fields wrong: %+v", f)
	}
	if f.CaseID != "case-1" || f.SessionID != "s-1" || f.SourceAgent != model.AgentClaudeCode || f.SourceType != model.SourceArtifact {
		t.Errorf("identity fields wrong: %+v", f)
	}
	if f.Model != "claude-sonnet-4" || f.SubAgent != "code-reviewer" {
		t.Errorf("context fields wrong: %+v", f)
	}
	if f.Timestamp != "2026-06-02T10:00:01Z" {
		t.Errorf("timestamp = %q, want source activity time", f.Timestamp)
	}
	if f.DetectedAt != "2026-06-02T12:00:00Z" {
		t.Errorf("detected_at = %q, want injected now", f.DetectedAt)
	}
	if f.Redacted {
		t.Error("redacted should be false when the redactor made no changes")
	}
	if f.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q", f.Confidence)
	}
	if len(f.EvidenceRefs) != 1 || f.EvidenceRefs[0].Line != 2 || f.EvidenceRefs[0].JSONPointer != "/message/content/1" {
		t.Errorf("evidence refs wrong: %+v", f.EvidenceRefs)
	}
	if len(f.CitedEventIDs) != 1 || f.CitedEventIDs[0] != "u1#1" {
		t.Errorf("cited event ids wrong: %+v", f.CitedEventIDs)
	}
	// Rule and event tags are merged and de-duplicated.
	if got := strings.Join(f.Tags, ","); got != "agent_activity,secret_file_read" {
		t.Errorf("tags = %q, want merged+sorted", got)
	}
}

// The project path must be hashed, never emitted in the clear.
func TestFromMatchHashesProjectPath(t *testing.T) {
	f := FromMatch(sampleMatch(), Options{})
	if !strings.HasPrefix(f.ProjectPathHash, "sha256:") {
		t.Errorf("project_path_hash = %q, want sha256: prefix", f.ProjectPathHash)
	}
	if strings.Contains(f.ProjectPathHash, "secret-proj") {
		t.Error("raw project path leaked into the hash field")
	}
	if f.ProjectPathHash != model.HashPath("/home/dev/secret-proj") {
		t.Error("project path hash does not match model.HashPath")
	}
}

// An event without a project path leaves the hash empty rather than hashing "".
func TestFromMatchNoProjectPath(t *testing.T) {
	m := sampleMatch()
	m.Event.ProjectPath = ""
	f := FromMatch(m, Options{})
	if f.ProjectPathHash != "" {
		t.Errorf("project_path_hash = %q, want empty", f.ProjectPathHash)
	}
}

func TestFindingIDStableAndDistinct(t *testing.T) {
	m := sampleMatch()
	a := FromMatch(m, Options{}).FindingID
	b := FromMatch(m, Options{}).FindingID
	if a != b {
		t.Errorf("finding id not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "fnd-") {
		t.Errorf("finding id = %q, want fnd- prefix", a)
	}
	// A different event yields a different id.
	m2 := sampleMatch()
	m2.Event.EventID = "u2#0"
	if c := FromMatch(m2, Options{}).FindingID; c == a {
		t.Errorf("distinct events share a finding id: %q", c)
	}
	// A different rule on the same event also differs.
	m3 := sampleMatch()
	m3.Rule.ID = "secrets.read_private_key"
	if d := FromMatch(m3, Options{}).FindingID; d == a {
		t.Errorf("distinct rules share a finding id: %q", d)
	}
	// A revised rule is a distinct detection decision on the same evidence.
	m4 := sampleMatch()
	m4.Rule.Version = "1.1"
	if e := FromMatch(m4, Options{}).FindingID; e == a {
		t.Errorf("distinct rule revisions share a finding id: %q", e)
	}
	// Activity and detection times are not part of finding identity.
	m5 := sampleMatch()
	m5.Event.Timestamp = "2026-06-03T00:00:00Z"
	if e := FromMatch(m5, Options{Now: time.Unix(1, 0)}).FindingID; e != a {
		t.Errorf("time fields changed finding id: %q vs %q", e, a)
	}
}

// The observed artifact carries the matched event's context: a file.read
// surfaces the path and the closed-vocabulary event_type/actor.
func TestObservedFields(t *testing.T) {
	f := FromMatch(sampleMatch(), Options{})
	if f.ObservedEventType != string(model.EventFileRead) {
		t.Errorf("observed_event_type = %q", f.ObservedEventType)
	}
	if f.ObservedFilePath != "/home/dev/secret-proj/.env" {
		t.Errorf("observed_file_path = %q", f.ObservedFilePath)
	}
}

// Every sensitive observed_* value is routed through redaction: a secret in a
// command or a token in a URL must never reach an emitted finding.
func TestObservedRedactsSecrets(t *testing.T) {
	m := sampleMatch()
	m.Event.FilePath = ""
	m.Event.Command = "echo GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789 >> .env"
	m.Event.URL = "https://evil.test/x?token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	f := FromMatch(m, Options{})
	if !f.Redacted {
		t.Error("redacted should be true when observed fields were masked")
	}
	if strings.Contains(f.ObservedCommand, "ghp_") {
		t.Errorf("observed_command leaked a token: %q", f.ObservedCommand)
	}
	if !strings.Contains(f.ObservedCommand, "[redacted]") || !strings.Contains(f.ObservedCommand, ".env") {
		t.Errorf("observed_command = %q, want masked secret but visible .env", f.ObservedCommand)
	}
	if strings.Contains(f.ObservedURL, "ghp_") {
		t.Errorf("observed_url leaked a token: %q", f.ObservedURL)
	}
	if !strings.Contains(f.ObservedURL, "[redacted]") {
		t.Errorf("observed_url = %q, want masked token", f.ObservedURL)
	}
}

func TestObservedContentPreviewCarriesTruncation(t *testing.T) {
	m := sampleMatch()
	m.Event.EventType = model.EventPromptUser
	m.Event.FilePath = ""
	m.Event.ContentPreview = strings.Repeat("Authorization: Bearer x ", 8)
	f := FromMatch(m, Options{})
	if utf8.RuneCountInString(f.ObservedContentPreview) > model.ContentPreviewMaxRunes ||
		!f.ObservedContentPreviewTruncated || !f.Redacted {
		t.Fatalf("finding preview = %d runes, truncated=%t redacted=%t",
			utf8.RuneCountInString(f.ObservedContentPreview), f.ObservedContentPreviewTruncated, f.Redacted)
	}
}

// A presigned S3 URL routed into observed_url must not carry live auth material
// off the box: the signature, credential scope, and security token are masked
// while the host/path stay readable. This is the no-leak invariant for the new
// observed_url field, exercised end-to-end through FromMatch.
func TestObservedRedactsPresignedURL(t *testing.T) {
	m := sampleMatch()
	m.Event.FilePath = ""
	m.Event.EventType = model.EventNetworkIndicator
	m.Event.URL = "https://bucket.s3.amazonaws.com/key.txt?" +
		"X-Amz-Algorithm=AWS4-HMAC-SHA256&" +
		"X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20260603/us-east-1/s3/aws4_request&" +
		"X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLESECURITYTOKEN0123456789&" +
		"X-Amz-Signature=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	f := FromMatch(m, Options{})
	if !f.Redacted {
		t.Error("redacted should be true when observed_url credential fields were masked")
	}
	for _, leak := range []string{
		"abcdef0123456789abcdef0123456789",
		"AKIAIOSFODNN7EXAMPLE",
		"aws4_request",
		"FwoGZXIvYXdzEXAMPLESECURITYTOKEN0123456789",
	} {
		if strings.Contains(f.ObservedURL, leak) {
			t.Fatalf("observed_url leaked credential material %q: %q", leak, f.ObservedURL)
		}
	}
	if !strings.Contains(f.ObservedURL, "bucket.s3.amazonaws.com/key.txt") {
		t.Errorf("observed_url over-redacted, lost host/path: %q", f.ObservedURL)
	}
}

// A network/MCP event surfaces url and the split MCP server/tool — context the
// old summary never carried.
func TestObservedNetworkAndMCP(t *testing.T) {
	m := sampleMatch()
	m.Event.EventType = model.EventNetworkIndicator
	m.Event.FilePath = ""
	m.Event.URL = "https://api.example.com/v1/data"
	m.Event.MCPServer = "github"
	m.Event.MCPTool = "create_issue"
	f := FromMatch(m, Options{})
	if f.ObservedURL != "https://api.example.com/v1/data" {
		t.Errorf("observed_url = %q", f.ObservedURL)
	}
	if f.ObservedMCPServer != "github" || f.ObservedMCPTool != "create_issue" {
		t.Errorf("observed mcp = %q/%q", f.ObservedMCPServer, f.ObservedMCPTool)
	}
}

func TestObservedRedactsMCPIdentifiers(t *testing.T) {
	m := sampleMatch()
	m.Event.EventType = model.EventToolCall
	m.Event.FilePath = ""
	m.Event.MCPServer = "github_api_key=server-secret"
	m.Event.MCPTool = "tool_password=tool-secret"
	f := FromMatch(m, Options{})
	if !f.Redacted {
		t.Fatal("redacted should be true when MCP identifiers were masked")
	}
	if strings.Contains(f.ObservedMCPServer, "server-secret") || strings.Contains(f.ObservedMCPTool, "tool-secret") {
		t.Fatalf("MCP identifiers leaked secrets: %+v", f)
	}
}

// An event with no command/file/url/preview emits only event_type and actor;
// the value fields stay empty so omitempty drops them.
func TestObservedAllEmpty(t *testing.T) {
	m := sampleMatch()
	m.Event.Actor = model.ActorAssistant
	m.Event.FilePath = ""
	m.Event.Command = ""
	m.Event.URL = ""
	m.Event.ContentPreview = ""
	m.Event.MCPServer = ""
	m.Event.MCPTool = ""
	f := FromMatch(m, Options{})
	if f.ObservedEventType != string(model.EventFileRead) || f.ObservedActor != model.ActorAssistant {
		t.Errorf("observed context lost: %q/%q", f.ObservedEventType, f.ObservedActor)
	}
	if f.ObservedCommand != "" || f.ObservedFilePath != "" || f.ObservedURL != "" ||
		f.ObservedContentPreview != "" || f.ObservedMCPServer != "" || f.ObservedMCPTool != "" {
		t.Errorf("expected empty value fields, got %+v", f)
	}
}

func TestFromMatchDefaultsDetectedAtToWallClock(t *testing.T) {
	before := time.Now().UTC()
	f := FromMatch(sampleMatch(), Options{})
	got, err := time.Parse(time.RFC3339Nano, f.DetectedAt)
	if err != nil {
		t.Fatalf("detected_at %q not RFC3339Nano: %v", f.DetectedAt, err)
	}
	if got.Before(before.Add(-time.Minute)) || got.After(time.Now().UTC().Add(time.Minute)) {
		t.Errorf("default detected_at %v is not near now", got)
	}
}

func TestFromMatchOmitsUnusableActivityTimestamp(t *testing.T) {
	for _, ts := range []string{
		"",
		"not-a-time",
		"2026-06-02T1:00:00Z",
		"2026-06-02T10:00:00,1Z",
		"2026-06-02T10:00:00+24:00",
		"2026-06-02T10:00:00+00:60",
		"2026-02-30T10:00:00Z",
		"2026-04-31T10:00:00Z",
	} {
		m := sampleMatch()
		m.Event.Timestamp = ts
		f := FromMatch(m, Options{Now: time.Unix(1, 0)})
		if f.Timestamp != "" {
			t.Errorf("source timestamp %q emitted as %q", ts, f.Timestamp)
		}
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"timestamp":`) {
			t.Errorf("source timestamp %q was not omitted: %s", ts, raw)
		}
	}
}

func TestFromMatchAcceptsStrictRFC3339ActivityTimestamp(t *testing.T) {
	for _, ts := range []string{
		"2026-06-02T10:00:00Z",
		"2026-06-02T10:00:00.123456789+05:30",
		"2026-06-02t10:00:00z",
	} {
		m := sampleMatch()
		m.Event.Timestamp = ts
		if got := FromMatch(m, Options{Now: time.Unix(1, 0)}).Timestamp; got != ts {
			t.Errorf("source timestamp %q emitted as %q", ts, got)
		}
	}
}

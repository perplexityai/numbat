package model

// Severity levels for findings, ordered low to critical.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// validSeverities is the closed set accepted by rule loading and emission.
var validSeverities = map[string]struct{}{
	SeverityInfo: {}, SeverityLow: {}, SeverityMedium: {},
	SeverityHigh: {}, SeverityCritical: {},
}

// IsValidSeverity reports whether s is a recognized severity level.
func IsValidSeverity(s string) bool {
	_, ok := validSeverities[s]
	return ok
}

// Finding is a rule match over one or more Events. It is the only thing
// Numbat emits by default. Findings are portable and redaction-safe: they
// carry local Evidence references and a hashed project path, never raw
// transcript or secret content.
type Finding struct {
	SchemaVersion string `json:"schema_version"`
	FindingID     string `json:"finding_id"`
	CaseID        string `json:"case_id,omitempty"`
	// Timestamp is the matched activity time and is omitted when the matched event
	// has no valid RFC3339 timestamp. DetectedAt is when numbat evaluated the
	// activity and created this finding.
	Timestamp  string `json:"timestamp,omitempty"`
	DetectedAt string `json:"detected_at"`

	RuleID      string `json:"rule_id"`
	RuleVersion string `json:"rule_version"`
	Severity    string `json:"severity"`

	SourceAgent     string `json:"source_agent"`
	SourceType      string `json:"source_type"`
	ProjectPathHash string `json:"project_path_hash,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	Model           string `json:"model,omitempty"`
	ModelProvider   string `json:"model_provider,omitempty"`
	SubAgent        string `json:"sub_agent,omitempty"`

	Title string `json:"title"`

	// observed_* surface the matched event's actual artifact so a finding shows
	// what fired, not just the rule title. Sensitive values (command, file_path,
	// url, content_preview) are routed through redact.String; event_type and
	// actor are closed-vocabulary enums emitted verbatim.
	ObservedEventType               string `json:"observed_event_type,omitempty"`
	ObservedActor                   string `json:"observed_actor,omitempty"`
	ObservedCommand                 string `json:"observed_command,omitempty"`
	ObservedFilePath                string `json:"observed_file_path,omitempty"`
	ObservedURL                     string `json:"observed_url,omitempty"`
	ObservedMCPServer               string `json:"observed_mcp_server,omitempty"`
	ObservedMCPTool                 string `json:"observed_mcp_tool,omitempty"`
	ObservedContentPreview          string `json:"observed_content_preview,omitempty"`
	ObservedContentPreviewTruncated bool   `json:"observed_content_preview_truncated,omitempty"`

	Tags         []string   `json:"tags,omitempty"`
	EvidenceRefs []Evidence `json:"evidence_refs"`
	// CitedEventIDs are the contributing event ids this finding was rendered
	// from. They let downstream consumers join a finding back to live hook/otel
	// events whose Evidence is intentionally thin and non-unique.
	CitedEventIDs []string `json:"cited_event_ids"`

	// Redacted reports whether at least one emitted finding field was actually
	// masked. A false value does not mean raw retention was enabled: finding
	// value fields are still passed through the redactor before emit.
	Redacted   bool   `json:"redacted"`
	Confidence string `json:"confidence"`
}

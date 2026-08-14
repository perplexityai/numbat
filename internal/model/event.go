// Package model defines the normalized events and findings shared by parsers,
// live sensors, rules, and emitters. Evidence references raw local artifacts;
// records do not copy their contents by default.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"sort"
	"strings"
)

// SchemaVersion is the version of the event and finding schema. It is stamped
// on every emitted record so receivers can route and migrate deterministically.
const SchemaVersion = "0.3.0"

// ToolName is the identifier emitted in records and reports.
const ToolName = "numbat"

// SourceAgent identifies which endpoint agent an artifact came from.
const (
	AgentClaudeCode = "claude-code"
	// AgentCowork is Claude local-agent-mode / Dispatch, parsed from at-rest
	// audit logs only.
	AgentCowork    = "cowork"
	AgentCodex     = "codex"
	AgentGeminiCLI = "gemini-cli"
	AgentCursor    = "cursor"
	AgentWindsurf  = "windsurf"
	AgentCopilot   = "copilot"
	// AgentVSCode is VS Code Copilot Chat / Agent Mode, separate from the GitHub
	// Copilot CLI source.
	AgentVSCode   = "vscode"
	AgentOpenCode = "opencode"
	// AgentOpenClaw covers stable at-rest sessions and native live plugin hooks.
	AgentOpenClaw = "openclaw"
	// AgentAntigravity is hook-only until its documented transcript files have a
	// stable, public record schema numbat can verify.
	AgentAntigravity = "antigravity"
	// AgentFactory is a hook-only Factory Droid source until its at-rest session
	// schema is verifiable.
	AgentFactory = "factory"
	// AgentGrok is a hook-only Grok Build source until an at-rest transcript
	// schema is verifiable.
	AgentGrok = "grok"
	// AgentDevinCLI is a hook-only Devin CLI source; Devin Desktop shares the
	// Windsurf/Cascade hook surface.
	AgentDevinCLI = "devin-cli"
	// AgentHermesCLI is a hook-only Hermes Agent source.
	AgentHermesCLI = "hermes"
	// AgentPi is the Pi coding agent, parsed from its versioned JSONL sessions.
	AgentPi = "pi"
	// AgentKimiCode is Moonshot AI's current Kimi Code CLI, not legacy kimi-cli.
	AgentKimiCode = "kimi-code"
	// AgentQwenCode is the Qwen Code CLI hook source.
	AgentQwenCode = "qwen-code"
	// AgentCline is the Cline CLI hook source.
	AgentCline = "cline"
	// AgentAmp is Sourcegraph's Amp coding agent hook source.
	AgentAmp = "amp"
	// AgentAuggie is Augment Code's Auggie CLI hook source.
	AgentAuggie = "auggie"
	// AgentKiro is the shared Kiro IDE / CLI v3 global-hook source.
	AgentKiro = "kiro"
	// AgentGoose is the Goose Open Plugins hook source.
	AgentGoose = "goose"
	// AgentKilo is the current Kilo Code CLI and extension plugin source.
	AgentKilo = "kilo"
	// AgentOpenHands is the OpenHands repository hook source.
	AgentOpenHands = "openhands"
	// AgentCrush is the Crush PreToolUse hook source.
	AgentCrush = "crush"
	// AgentJunie is the Junie CLI Early Access hook source.
	AgentJunie   = "junie"
	AgentUnknown = "unknown"
)

// SourceType classifies how an event was observed: artifact is an at-rest
// parse of a durable on-disk record, hook is a live in-process signal, and
// otel is a live OTLP telemetry signal. All three are produced today.
const (
	SourceArtifact = "artifact"
	SourceHook     = "hook"
	SourceOTel     = "otel"
)

// Actor identifies who produced the event within a session.
const (
	ActorUser      = "user"
	ActorAssistant = "assistant"
	ActorSystem    = "system"
	ActorTool      = "tool"
)

// Decision records an agent permission outcome when the artifact exposes one.
const (
	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
	DecisionAsked   = "asked"
	DecisionUnknown = ""
)

// Confidence expresses how directly the event is supported by evidence.
//
//	high   — direct artifact evidence (a transcript line, a config value)
//	medium — inferred from a command, file path, or config shape
//	low     — weak signal or a partial/tolerant parse
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Shared parser tags live here; source-specific tags stay with their parser.
const (
	// TagNetwork marks structured network egress.
	TagNetwork = "network"
	// TagToolError marks failure reported by a structured source field.
	TagToolError = "tool_error"
	// TagPermissionModeElevated marks an agent mode that reduces interactive
	// approval.
	TagPermissionModeElevated = "permission_mode_elevated"
)

// EventType enumerates the normalized event vocabulary. Parsers map agent
// artifacts onto these; rules match on them. The set is intentionally closed
// so rule authors can rely on it.
type EventType string

const (
	EventSessionStart        EventType = "session.start"
	EventSessionEnd          EventType = "session.end"
	EventPromptUser          EventType = "prompt.user"
	EventMessageAssistant    EventType = "message.assistant"
	EventToolCall            EventType = "tool.call"
	EventToolResult          EventType = "tool.result"
	EventCommandExec         EventType = "command.exec"
	EventCommandResult       EventType = "command.result"
	EventFileRead            EventType = "file.read"
	EventFileWrite           EventType = "file.write"
	EventFileDelete          EventType = "file.delete"
	EventPermissionRequested EventType = "permission.requested"
	EventPermissionApproved  EventType = "permission.approved"
	EventPermissionDenied    EventType = "permission.denied"
	EventConfigAgent         EventType = "config.agent"
	EventConfigMCP           EventType = "config.mcp"
	EventNetworkIndicator    EventType = "network.indicator"
	EventMessageReasoning    EventType = "message.reasoning"
)

// eventTypes is the closed set used for validation and CEL exposure.
var eventTypes = map[EventType]struct{}{
	EventSessionStart: {}, EventSessionEnd: {}, EventPromptUser: {},
	EventMessageAssistant: {}, EventToolCall: {}, EventToolResult: {},
	EventCommandExec: {}, EventCommandResult: {}, EventFileRead: {},
	EventFileWrite: {}, EventFileDelete: {},
	EventPermissionRequested: {}, EventPermissionApproved: {}, EventPermissionDenied: {},
	EventConfigAgent: {}, EventConfigMCP: {}, EventNetworkIndicator: {},
	EventMessageReasoning: {},
}

// IsValidEventType reports whether t is part of the closed event vocabulary.
func IsValidEventType(t EventType) bool {
	_, ok := eventTypes[t]
	return ok
}

var (
	sourceAgents = map[string]struct{}{
		AgentClaudeCode: {}, AgentCowork: {}, AgentCodex: {},
		AgentGeminiCLI: {}, AgentCursor: {}, AgentWindsurf: {},
		AgentCopilot: {}, AgentVSCode: {}, AgentOpenCode: {},
		AgentOpenClaw: {}, AgentAntigravity: {}, AgentFactory: {},
		AgentGrok: {}, AgentDevinCLI: {}, AgentHermesCLI: {},
		AgentPi: {}, AgentKimiCode: {}, AgentQwenCode: {}, AgentCline: {},
		AgentAmp: {}, AgentAuggie: {}, AgentKiro: {}, AgentGoose: {}, AgentKilo: {},
		AgentOpenHands: {}, AgentCrush: {}, AgentJunie: {},
		AgentUnknown: {},
	}
	confidences = map[string]struct{}{ConfidenceHigh: {}, ConfidenceMedium: {}, ConfidenceLow: {}}
	sourceTypes = map[string]struct{}{SourceArtifact: {}, SourceHook: {}, SourceOTel: {}}
	actors      = map[string]struct{}{ActorUser: {}, ActorAssistant: {}, ActorSystem: {}, ActorTool: {}}
	decisions   = map[string]struct{}{DecisionAllowed: {}, DecisionDenied: {}, DecisionAsked: {}, DecisionUnknown: {}}
)

// IsValidSourceAgent reports whether a is a recognized source agent.
func IsValidSourceAgent(a string) bool { _, ok := sourceAgents[a]; return ok }

// IsValidConfidence reports whether c is a recognized confidence level.
func IsValidConfidence(c string) bool { _, ok := confidences[c]; return ok }

// IsValidSourceType reports whether s is a recognized observation source type.
func IsValidSourceType(s string) bool { _, ok := sourceTypes[s]; return ok }

// IsValidActor reports whether a is a recognized actor (empty is invalid).
func IsValidActor(a string) bool { _, ok := actors[a]; return ok }

// IsValidDecision reports whether d is a recognized permission decision.
// The empty string (DecisionUnknown) is valid: most events carry no decision.
func IsValidDecision(d string) bool { _, ok := decisions[d]; return ok }

// Evidence is a local, portable reference back to the artifact a record was
// derived from. It carries enough to locate and integrity-check the source
// without copying its (potentially sensitive) content.
type Evidence struct {
	// ArtifactType names the parser family, e.g. "claude_jsonl",
	// "codex_rollout", "gemini_chat", "agent_config".
	ArtifactType string `json:"artifact_type"`
	// LocalPath is the on-disk path for file-backed evidence. Live sensors such
	// as hooks and OTLP can omit it because there is no local artifact to reopen.
	LocalPath string `json:"local_path,omitempty"`
	// Line is the 1-based line number for line-oriented artifacts (JSONL).
	Line int `json:"line,omitempty"`
	// RowID is the SQLite rowid for DB-backed artifacts.
	RowID int64 `json:"rowid,omitempty"`
	// JSONPointer locates the value within a structured record (RFC 6901).
	JSONPointer string `json:"json_pointer,omitempty"`
	// SHA256 is the hex digest of the source artifact at parse time, so a
	// reviewer can confirm the evidence has not changed since the finding.
	SHA256 string `json:"sha256,omitempty"`
}

// Event is the normalized unit of agent activity. Parsers retain observed values
// for local rule evaluation; output paths redact them before emission.
type Event struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id,omitempty"`
	EventID       string `json:"event_id"`

	SourceAgent string `json:"source_agent"`
	SourceType  string `json:"source_type"`

	// Timestamp is normally RFC3339 and is empty when the source carries no time.
	// Textual source values may be preserved even when malformed; consumers order
	// them with a deterministic fallback rather than discarding the event.
	Timestamp   string `json:"timestamp,omitempty"`
	ProjectPath string `json:"project_path,omitempty"`
	SessionID   string `json:"session_id,omitempty"`

	Actor     string    `json:"actor,omitempty"`
	EventType EventType `json:"event_type"`

	ToolName string `json:"tool_name,omitempty"`
	Command  string `json:"command,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	Decision string `json:"decision,omitempty"`

	// ToolCallID correlates a generic or specialized action with its later result
	// when the artifact assigns one (Claude tool_use id, Codex call_id).
	ToolCallID string `json:"tool_call_id,omitempty"`

	// DiffSHA256 and DiffBytes summarize patch text without emitting it. The hash
	// is bare lowercase hex, matching Evidence.SHA256. CEL tests their zero values
	// for absence because these fields are not pointers.
	DiffSHA256 string `json:"diff_sha256,omitempty"`
	DiffBytes  int    `json:"diff_bytes,omitempty"`

	// ExitCode is optional so a recorded success (0) differs from absence.
	ExitCode *int `json:"exit_code,omitempty"`

	// DurationMs is optional so a recorded 0ms differs from absence.
	DurationMs *int64 `json:"duration_ms,omitempty"`

	// Approval fields retain a structured permission gate when the source records
	// one. ApprovalRequired is optional so false differs from absence.
	ApprovalRequired *bool  `json:"approval_required,omitempty"`
	ApprovalDecision string `json:"approval_decision,omitempty"`
	ApprovalReason   string `json:"approval_reason,omitempty"`

	// MCPServer and MCPTool split a Model Context Protocol invocation recorded
	// as the flattened mcp__<server>__<tool> identifier, so a rule or a SIEM can
	// pivot on the server or the tool without re-parsing ToolName.
	MCPServer string `json:"mcp_server,omitempty"`
	MCPTool   string `json:"mcp_tool,omitempty"`

	// URL is the network target of an egress event (WebFetch, MCP fetch, ...),
	// promoted to its own field instead of being buried in ContentPreview.
	URL string `json:"url,omitempty"`

	// Model and ModelProvider name the model behind a session when the source
	// records it; Numbat does not infer them.
	Model         string `json:"model,omitempty"`
	ModelProvider string `json:"model_provider,omitempty"`

	// GitBranch, Entrypoint, and CLIVersion are source-provided session context.
	GitBranch  string `json:"git_branch,omitempty"`
	Entrypoint string `json:"entrypoint,omitempty"`
	CLIVersion string `json:"cli_version,omitempty"`

	// SubAgent names the active named subagent/agent persona when the source
	// records one. It is the typed home for config.agent markers and live
	// subagent session boundaries, so a reviewer can pivot on the persona without
	// parsing ContentPreview.
	SubAgent string `json:"sub_agent,omitempty"`

	// ContentPreview is a bounded observed excerpt, redacted on every output path.
	ContentPreview          string `json:"content_preview,omitempty"`
	ContentPreviewTruncated bool   `json:"content_preview_truncated,omitempty"`

	// Content is populated only by an explicit full-content output projection.
	// Parsers keep the unredacted analysis body in the non-serializable fields
	// below so a default marshal cannot expose it accidentally.
	Content          string `json:"content,omitempty"`
	ContentBytes     int    `json:"content_bytes,omitempty"`
	ContentTruncated bool   `json:"content_truncated,omitempty"`

	analysisContent          string
	analysisContentBytes     int
	analysisContentTruncated bool

	// Tags are coarse labels a parser may pre-attach; rules may add more.
	Tags []string `json:"tags,omitempty"`

	Confidence string   `json:"confidence"`
	Evidence   Evidence `json:"evidence"`
}

// NormalizePaths converts source-native separators in semantic event paths to
// forward slashes. Evidence.LocalPath remains host-native because consumers may
// need to reopen that file on the endpoint.
func (e Event) NormalizePaths() Event {
	e.ProjectPath = NormalizeEventPath(e.ProjectPath)
	e.FilePath = NormalizeEventPath(e.FilePath)
	return e
}

// NormalizeEventPath returns the platform-neutral wire representation of a
// project or action path.
func NormalizeEventPath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// celView is the map-shaped action and context projection used for CEL rule
// evaluation. Field names match JSON tags (e.g. event.event_type).
func (e Event) celView() map[string]any {
	return map[string]any{
		"source_agent":              e.SourceAgent,
		"source_type":               e.SourceType,
		"timestamp":                 e.Timestamp,
		"project_path":              e.ProjectPath,
		"session_id":                e.SessionID,
		"actor":                     e.Actor,
		"event_type":                string(e.EventType),
		"tool_name":                 e.ToolName,
		"command":                   e.Command,
		"file_path":                 e.FilePath,
		"decision":                  e.Decision,
		"tool_call_id":              e.ToolCallID,
		"exit_code":                 exitCodeView(e.ExitCode),
		"duration_ms":               int64PtrView(e.DurationMs),
		"approval_required":         boolPtrView(e.ApprovalRequired),
		"approval_decision":         e.ApprovalDecision,
		"approval_reason":           e.ApprovalReason,
		"diff_sha256":               e.DiffSHA256,
		"diff_bytes":                e.DiffBytes,
		"mcp_server":                e.MCPServer,
		"mcp_tool":                  e.MCPTool,
		"url":                       e.URL,
		"model":                     e.Model,
		"model_provider":            e.ModelProvider,
		"git_branch":                e.GitBranch,
		"entrypoint":                e.Entrypoint,
		"cli_version":               e.CLIVersion,
		"sub_agent":                 e.SubAgent,
		"content_preview":           e.ContentPreview,
		"content_preview_truncated": e.ContentPreviewTruncated,
		"content":                   e.contentForAnalysis(),
		"content_bytes":             e.contentBytesForAnalysis(),
		"content_truncated":         e.contentTruncatedForAnalysis(),
		"tags":                      toAnySlice(e.Tags),
		"confidence":                e.Confidence,
	}
}

// SetContent records a message preview and, when retain is true, a bounded body
// for local analysis. It does not populate the emitted Content field.
func (e *Event) SetContent(raw string, retain bool) {
	e.ContentPreview, e.ContentPreviewTruncated = NormalizeContentPreviewWithTruncation(raw)
	e.Content = ""
	e.ContentBytes = 0
	e.ContentTruncated = false
	e.analysisContent = ""
	e.analysisContentBytes = 0
	e.analysisContentTruncated = false
	if !retain || strings.TrimSpace(raw) == "" {
		return
	}
	e.analysisContentBytes = len(raw)
	e.analysisContent, e.analysisContentTruncated = LimitContent(raw)
}

// ContentForAnalysis returns the bounded body retained by a parser, or Content
// when evaluating a caller-supplied event record.
func (e Event) ContentForAnalysis() string { return e.contentForAnalysis() }

// ContentBytesForAnalysis returns the mapped message-body byte count recorded
// before Numbat's content bound was applied.
func (e Event) ContentBytesForAnalysis() int { return e.contentBytesForAnalysis() }

// ContentTruncatedForAnalysis reports whether ContentForAnalysis omits bytes.
func (e Event) ContentTruncatedForAnalysis() bool { return e.contentTruncatedForAnalysis() }

// WithoutAnalysisContent returns a copy with the process-local message body
// removed. Output projections call it after taking any explicitly requested
// content so the returned event cannot expose the unredacted analysis copy.
func (e Event) WithoutAnalysisContent() Event {
	e.analysisContent = ""
	e.analysisContentBytes = 0
	e.analysisContentTruncated = false
	return e
}

func (e Event) contentForAnalysis() string {
	if e.analysisContent != "" {
		return e.analysisContent
	}
	return e.Content
}

func (e Event) contentBytesForAnalysis() int {
	if e.analysisContentBytes != 0 {
		return e.analysisContentBytes
	}
	return e.ContentBytes
}

func (e Event) contentTruncatedForAnalysis() bool {
	return e.analysisContentTruncated || e.ContentTruncated
}

// CELActivation returns the variable bindings for evaluating a rule against
// this event. It is the single contract between the event model and the rule
// engine, keeping CEL field names in one place.
func (e Event) CELActivation() map[string]any {
	return map[string]any{"event": e.celView()}
}

// celFields is the set of valid `event.<field>` keys, derived from the celView
// of a zero Event so it can never drift from the projection above.
var celFields = func() map[string]struct{} {
	set := make(map[string]struct{})
	for k := range (Event{}).celView() {
		set[k] = struct{}{}
	}
	return set
}()

// IsCELField reports whether name is a valid field of the `event` CEL view.
// The rule engine uses it to reject expressions referencing unknown fields at
// load time instead of failing silently per-event at runtime.
func IsCELField(name string) bool {
	_, ok := celFields[name]
	return ok
}

// exitCodeView projects an optional exit code for CEL: the int when the artifact
// recorded one, else nil so a real exit 0 stays distinct from "no code". The
// celView always includes the "exit_code" key, so a rule tests presence with
// `event.exit_code != null` (NOT has(event.exit_code) — cel-go has() checks key
// presence, which is always true here); `event.exit_code == 0` then matches a
// real clean exit and never an absent code.
func exitCodeView(code *int) any {
	if code == nil {
		return nil
	}
	return *code
}

// int64PtrView projects an optional int64 (duration_ms) for CEL: the value when
// the artifact recorded one, else nil so a real 0 stays distinct from absent. A
// rule tests presence with `event.duration_ms != null`, mirroring exit_code.
func int64PtrView(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// boolPtrView projects an optional bool (approval_required) for CEL: the value
// when recorded, else nil so an explicit false stays distinct from absent. A
// rule tests presence with `event.approval_required != null`.
func boolPtrView(v *bool) any {
	if v == nil {
		return nil
	}
	return *v
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// HashContent returns the lowercase hex SHA-256 of b. Parsers use it to stamp
// Evidence.SHA256 so findings remain verifiable against their source.
func HashContent(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashPath returns a stable, unsalted "sha256:" digest of a normalized path.
// It is a pseudonymous join key, not anonymization: predictable paths can be
// guessed and compared with their hashes.
func HashPath(p string) string {
	clean := filepathClean(p)
	if clean == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(clean))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// filepathClean normalizes a forward-slash path for hashing so logically-equal
// paths collide. It uses path.Clean (slash-only, OS-independent) to collapse
// duplicate separators and resolve . / .. segments; an empty input stays empty
// rather than becoming ".".
func filepathClean(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return path.Clean(NormalizeEventPath(p))
}

// MergeTags returns the sorted, de-duplicated union of two tag sets.
func MergeTags(a, b []string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for _, t := range a {
		if t != "" {
			set[t] = struct{}{}
		}
	}
	for _, t := range b {
		if t != "" {
			set[t] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

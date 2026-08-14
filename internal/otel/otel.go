// Package otel maps an OTLP log record emitted by an endpoint agent's live
// telemetry into numbat's normalized model.Event. It is the OTel-sensor analog
// of internal/hook: where the hook package turns a per-agent lifecycle JSON
// payload into an Event, this package turns an OTLP/HTTP LogRecord (plus its
// Resource attributes) into the same flat Event the on-disk extractors produce,
// so the shared pipeline detects on a telemetry event exactly as it does on an
// artifact or a hook event.
//
// Two honesty constraints — identical to the hook path — shape the mapping:
//
//   - source_type is always "otel". A telemetry event is a live observation
//     pushed over OTLP, not a parse of a durable on-disk artifact, and
//     downstream consumers must be able to tell the two apart.
//   - Evidence is deliberately thin. An OTLP record carries no artifact path,
//     line number, rowid, or content hash — there is no on-disk record to point
//     back to — so Evidence holds only the synthetic artifact type ("otel"),
//     with no path, line, rowid, or hash. Fabricating one here would forge
//     forensic provenance, so we do not.
//
// Mapping uses OpenTelemetry GenAI conventions plus exact documented aliases for
// agents that still emit private event names. Records with no normalized analog
// return Mapped=false instead of receiving a guessed event type.
package otel

import (
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// Standard semantic-convention attribute keys numbat keys off. These are
// OpenTelemetry conventions (GenAI + resource), not any one exporter's private
// namespace, so a record from any conforming agent classifies the same.
const (
	attrServiceName            = "service.name"
	eventGenAIInferenceDetails = "gen_ai.client.inference.operation.details"

	attrSessionID         = "session.id"
	attrConversationID    = "conversation.id"
	attrGenAIConversation = "gen_ai.conversation.id"

	attrGenAIOperation = "gen_ai.operation.name"
	attrGenAISystem    = "gen_ai.system"
	attrGenAIProvider  = "gen_ai.provider.name"
	attrGenAIReqModel  = "gen_ai.request.model"
	attrGenAIRespModel = "gen_ai.response.model"

	attrGenAIPrompt = "gen_ai.prompt"
	attrGenAIInput  = "gen_ai.input.messages"
	attrGenAIOutput = "gen_ai.output.messages"

	attrGenAIAgentName = "gen_ai.agent.name"
	attrGenAIAgentID   = "gen_ai.agent.id"

	attrGenAIToolName     = "gen_ai.tool.name"
	attrGenAIToolCallID   = "gen_ai.tool.call.id"
	attrGenAIToolCallArgs = "gen_ai.tool.call.arguments"
	attrToolName          = "tool.name"
	attrToolCallArgs      = "tool.call.arguments"

	attrProcessCommand     = "process.command"
	attrProcessCommandLine = "process.command_line"
	attrCommand            = "command"
	attrExitCode           = "process.exit.code"
	attrDurationMs         = "duration_ms"

	attrURLFull = "url.full"
	attrURL     = "url"
	attrHTTPURL = "http.url"

	attrFilePath = "file.path"
	attrCodePath = "code.filepath"
	attrFileOp   = "file.operation"

	attrApprovalRequired   = "approval.required"
	attrApprovalDecision   = "approval.decision"
	attrApprovalReason     = "approval.reason"
	attrPermissionDecision = "permission.decision"

	attrDiffSHA256 = "diff.sha256"
	attrDiffBytes  = "diff.bytes"

	attrGitBranch      = "vcs.repository.ref.name"
	attrServiceVersion = "service.version"
	attrAppVersion     = "app.version"
	attrOriginator     = "originator"

	// attrEventName / attrEventNameUnderscore carry the OTLP log record's event
	// name when an exporter sets it as an attribute rather than (or in addition
	// to) the LogRecord.event_name proto field. Codex and Gemini CLI both emit
	// their event name this way, so numbat consults the attribute when the proto
	// field is empty (see eventName).
	attrEventName           = "event.name"
	attrEventNameUnderscore = "event_name"
	attrEventTimestamp      = "event.timestamp"
)

// MapResult is the outcome of mapping one OTLP record. Mapped identifies a
// normalized event; Ignored identifies known supplemental telemetry that must
// not count as a rejected record. Event is meaningful only when Mapped is true.
type MapResult struct {
	Event   model.Event
	Mapped  bool
	Ignored bool
	// SourceAgent is the agent the record's service.name resolved to, returned
	// even for a skipped or ignored record.
	SourceAgent string
}

// MapRecords flattens a decoded OTLP logs request into per-record map results,
// pairing each LogRecord with its emitting Resource's attributes and assigning a
// stable event id from idFor(index). The caller (the receiver) feeds each mapped
// event through the shared pipeline and skips the rest.
func MapRecords(b []byte, idFor func(int) string) ([]MapResult, error) {
	data, err := decodeLogsRequest(b)
	if err != nil {
		return nil, err
	}
	var out []MapResult
	i := 0
	for _, rl := range data.resourceLogs {
		for _, sl := range rl.scopeLogs {
			for _, rec := range sl.logRecords {
				out = append(out, mapRecord(rl.resource.attributes, rec, idFor(i)))
				i++
			}
		}
	}
	return out, nil
}

// serviceName derives source_agent from the resource's service.name using
// standard semconv. The match is prefix/substring based so naming variants an
// exporter might use (claude-cowork, claude-code, codex-cli, gemini-cli, qwen-code) all
// resolve to numbat's canonical model.Agent* id. An unrecognized service.name
// yields AgentUnknown rather than a guess — numbat does not pretend to know
// which agent emitted a record it cannot identify.
func serviceName(a attrs) string {
	svc := strings.ToLower(strings.TrimSpace(a.str(attrServiceName)))
	switch {
	case svc == "":
		return model.AgentUnknown
	case strings.Contains(svc, "cowork"):
		return model.AgentCowork
	case strings.Contains(svc, "antigravity"):
		return model.AgentAntigravity
	case strings.Contains(svc, "claude"):
		return model.AgentClaudeCode
	case strings.Contains(svc, "codex"):
		return model.AgentCodex
	case strings.Contains(svc, "gemini"):
		return model.AgentGeminiCLI
	case strings.Contains(svc, "qwen"):
		return model.AgentQwenCode
	case strings.Contains(svc, "cursor"):
		return model.AgentCursor
	case strings.Contains(svc, "windsurf"):
		return model.AgentWindsurf
	case strings.Contains(svc, "vscode") || strings.Contains(svc, "vs-code") ||
		strings.Contains(svc, "copilot-chat") || strings.Contains(svc, "copilot_chat"):
		return model.AgentVSCode
	case strings.Contains(svc, "copilot"):
		return model.AgentCopilot
	case strings.Contains(svc, "opencode"):
		return model.AgentOpenCode
	case strings.Contains(svc, "openclaw"):
		return model.AgentOpenClaw
	case strings.Contains(svc, "factory"):
		return model.AgentFactory
	case strings.Contains(svc, "grok"):
		return model.AgentGrok
	case strings.Contains(svc, "devin"):
		return model.AgentDevinCLI
	case strings.Contains(svc, "hermes"):
		return model.AgentHermesCLI
	default:
		return model.AgentUnknown
	}
}

// mapRecord classifies one OTLP log record onto numbat's event vocabulary. It
// keys off standard semconv: the gen_ai.operation.name / event.name discriminator
// first, then the presence of tool/command/file/url/approval attributes, mirroring
// how the hook path classifies a tool by name. A record with no analog returns
// Mapped=false so the caller skips it without inventing an event_type.
func mapRecord(resourceAttrs []keyValue, rec logRecord, eventID string) MapResult {
	a := newAttrs(resourceAttrs, rec.attributes)
	sourceAgent := serviceName(a)
	name := eventName(&a, rec)
	if name == geminiFileOperation || name == qwenFileOperation {
		return MapResult{Ignored: true, SourceAgent: sourceAgent}
	}

	ev := model.Event{
		SchemaVersion: model.SchemaVersion,
		EventID:       eventID,
		SourceAgent:   sourceAgent,
		SourceType:    model.SourceOTel,
		SessionID:     a.str(attrGenAIConversation, attrConversationID, attrSessionID),
		Actor:         model.ActorAssistant,
		// A telemetry record is a live signal with no artifact line to verify
		// against, so its confidence is medium: the action is real but the evidence
		// is the agent's own emitted record, not a durable artifact. The artifact
		// type names the sensor.
		Confidence: model.ConfidenceMedium,
		Evidence:   model.Evidence{ArtifactType: "otel"},
	}
	if ts := recordTime(rec); ts != "" {
		ev.Timestamp = ts
	} else {
		ev.Timestamp = a.str(attrEventTimestamp)
	}

	if !classify(&ev, &a, rec) {
		return MapResult{SourceAgent: sourceAgent}
	}
	applyCommonContext(&ev, &a)
	return MapResult{Event: ev, Mapped: true, SourceAgent: sourceAgent}
}

// applyCommonContext retains session metadata carried on every record by some
// exporters (notably Codex), without making individual event classifiers repeat
// the same aliases.
func applyCommonContext(ev *model.Event, a *attrs) {
	if ev.Model == "" {
		ev.Model = a.str(attrGenAIRespModel, attrGenAIReqModel, attrModel)
	}
	if ev.ModelProvider == "" {
		ev.ModelProvider = a.str(attrGenAIProvider, attrGenAISystem, attrProviderName)
	}
	if ev.GitBranch == "" {
		ev.GitBranch = a.str(attrGitBranch)
	}
	if ev.CLIVersion == "" {
		ev.CLIVersion = a.str(attrAppVersion, attrServiceVersion)
	}
	if ev.Entrypoint == "" {
		ev.Entrypoint = a.str(attrOriginator)
	}
	if ev.SubAgent == "" {
		ev.SubAgent = a.str(attrGenAIAgentName, attrGenAIAgentID)
	}
}

// eventName returns the record's lower-cased event name. It prefers the OTLP
// LogRecord.event_name proto field (what wire.go decodes into rec.eventName) and
// falls back to an event.name / event_name attribute, because Codex and Gemini
// CLI set the carrier as an attribute, not the proto field. Without this
// fallback their entire live stream would classify as Mapped=false.
func eventName(a *attrs, rec logRecord) string {
	name := strings.TrimSpace(rec.eventName)
	if name == "" {
		name = strings.TrimSpace(a.str(attrEventName, attrEventNameUnderscore))
	}
	return strings.ToLower(name)
}

// classify sets ev.EventType and the discriminating fields from the record's
// semconv attributes, returning false when the record has no analog in numbat's
// closed vocabulary. The order matters: the explicit operation/event-name
// discriminator wins, then attribute-presence heuristics, so a record that names
// its operation is never reclassified by a coincidental attribute.
func classify(ev *model.Event, a *attrs, rec logRecord) bool {
	op := strings.ToLower(strings.TrimSpace(a.str(attrGenAIOperation)))
	name := eventName(a, rec)

	// Exact-name aliases for agents that emit their activity under a private
	// event.name namespace (Codex codex.*, Gemini gemini_cli.*) rather than the
	// gen_ai.* semconv. These are matched first and by EXACT name only: a
	// documented false negative is preferred over any false positive, so there is
	// no fuzzy/substring matching here.
	if classifyAgentAlias(ev, a, rec, name) {
		return true
	}

	switch {
	case isSessionStart(op, name):
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.Model = a.str(attrGenAIReqModel, attrGenAIRespModel)
		ev.ModelProvider = a.str(attrGenAIProvider, attrGenAISystem)
		ev.GitBranch = a.str(attrGitBranch)
		ev.CLIVersion = a.str(attrAppVersion, attrServiceVersion)
		return true

	case isSessionEnd(op, name):
		ev.EventType = model.EventSessionEnd
		ev.Actor = model.ActorSystem
		return true

	case name == eventGenAIInferenceDetails || op == "chat" || op == "text_completion" || op == "generate_content" ||
		strings.HasPrefix(name, "gen_ai.choice") || name == "gen_ai.assistant.message":
		// A model turn. Token usage and model identity ride on the same record.
		ev.EventType = model.EventMessageAssistant
		ev.Model = a.str(attrGenAIRespModel, attrGenAIReqModel)
		ev.ModelProvider = a.str(attrGenAIProvider, attrGenAISystem)
		ev.SetContent(firstNonEmpty(a.str(attrGenAIOutput), bodyText(rec)), true)
		return true

	case name == "gen_ai.user.message" || a.has(attrGenAIPrompt, attrGenAIInput):
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		ev.SetContent(firstNonEmpty(a.str(attrGenAIPrompt, attrGenAIInput), bodyText(rec)), true)
		return true

	case a.has(attrApprovalDecision, attrApprovalRequired, attrPermissionDecision):
		// A permission gate is checked before the tool/command branches: such a
		// record commonly also carries the gated tool's name, and the gate is the
		// salient event, not the tool call it guards.
		classifyPermission(ev, a)
		return true

	case op == "execute_tool" || a.has(attrGenAIToolName, attrToolName) || strings.HasPrefix(name, "gen_ai.tool"):
		classifyTool(ev, a, rec)
		return true

	case a.has(attrProcessCommand, attrProcessCommandLine, attrCommand):
		classifyCommand(ev, a)
		return true

	default:
		// No standard-semconv signal numbat understands. Do not invent an
		// event_type; report a skip so the caller can account for it honestly.
		return false
	}
}

// classifyTool maps a tool invocation. A tool whose name or arguments expose a
// network target becomes a network.indicator (mirroring the hook path's WebFetch
// handling); a shell/exec tool carrying a command becomes command.exec; a tool
// touching a file path becomes file.read/file.write per the operation; everything
// else is the generic tool.call. An mcp__server__tool name is split out.
func classifyTool(ev *model.Event, a *attrs, rec logRecord) {
	name := a.str(attrGenAIToolName, attrToolName)
	ev.ToolName = name
	callID := a.str(attrGenAIToolCallID)
	ev.ToolCallID = callID

	if rawURL := a.str(attrURLFull, attrURL, attrHTTPURL); rawURL != "" {
		ev.EventType = model.EventNetworkIndicator
		ev.URL = otelNetworkTargetURL(rawURL)
		ev.ContentPreview = preview(rawURL)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
		if errored(a, rec) {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}

	if path := a.str(attrFilePath, attrCodePath); path != "" {
		classifyFile(ev, a, name, path)
		if errored(a, rec) {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}

	switch {
	case isShellToolName(name):
		ev.Command = firstNonEmpty(a.str(attrCommand, attrProcessCommandLine, attrProcessCommand), toolCommandArg(a))
		ev.ToolName = name
		if applyCommandResultMetadata(ev, a) {
			ev.EventType = model.EventCommandResult
			ev.Actor = model.ActorTool
		} else {
			ev.EventType = model.EventCommandExec
		}
	default:
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}

	if errored(a, rec) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// classifyFile maps a file operation when its direction is explicit or clear
// from the tool name. Ambiguous path-bearing tools remain tool.call rather than
// being guessed as reads.
func classifyFile(ev *model.Event, a *attrs, name, path string) {
	ev.FilePath = path
	ev.ToolName = name
	var eventType model.EventType
	switch strings.ToLower(a.str(attrFileOp)) {
	case "delete", "remove", "unlink":
		eventType = model.EventFileDelete
	case "write", "edit", "create", "update", "append":
		eventType = model.EventFileWrite
	case "read", "open", "view":
		eventType = model.EventFileRead
	default:
		eventType = fileEventTypeFromTool(name)
	}
	if eventType == "" {
		ev.EventType = model.EventToolCall
		return
	}

	ev.EventType = eventType
	if eventType == model.EventFileWrite || eventType == model.EventFileDelete {
		if sha := normalizeSHA256Hex(a.str(attrDiffSHA256)); sha != "" {
			ev.DiffSHA256 = sha
		}
		if n, ok := nonNegativeInt(a, attrDiffBytes); ok {
			if nb, inRange := narrowInt(n); inRange {
				ev.DiffBytes = nb
			}
		}
	}
}

func fileEventTypeFromTool(name string) model.EventType {
	lower := strings.ToLower(strings.TrimSpace(name))
	tokens := strings.FieldsFunc(lower, func(r rune) bool {
		return r < 'a' || r > 'z'
	})
	hasVerb := func(verbs ...string) bool {
		for _, verb := range verbs {
			if strings.HasPrefix(lower, verb) {
				return true
			}
			for _, token := range tokens {
				if token == verb {
					return true
				}
			}
		}
		return false
	}
	switch {
	case hasVerb("delete", "remove", "unlink"):
		return model.EventFileDelete
	case hasVerb("write", "edit", "create", "update", "append"):
		return model.EventFileWrite
	case hasVerb("read", "cat", "view", "open"):
		return model.EventFileRead
	default:
		return ""
	}
}

// classifyCommand maps a process/command-execution record onto command.exec, or
// command.result when the record carries a terminal exit code or duration. The
// command text is read from standard process.* keys.
func classifyCommand(ev *model.Event, a *attrs) {
	ev.Command = a.str(attrCommand, attrProcessCommandLine, attrProcessCommand)
	if applyCommandResultMetadata(ev, a) {
		ev.EventType = model.EventCommandResult
		ev.Actor = model.ActorTool
		return
	}
	ev.EventType = model.EventCommandExec
}

func applyCommandResultMetadata(ev *model.Event, a *attrs) bool {
	code, hasCode := a.intval(attrExitCode)
	ms, hasMs := nonNegativeInt(a, attrDurationMs)

	if hasCode || hasMs {
		if hasCode {
			if c, inRange := narrowInt(code); inRange {
				ev.ExitCode = &c
			}
		}
		if hasMs {
			ev.DurationMs = &ms
		}
		return true
	}
	return false
}

// classifyPermission maps an approval/permission gate onto the permission.*
// vocabulary, populating the approval_* fields. An allowed/denied decision routes
// to the matching event; anything else is an open request.
func classifyPermission(ev *model.Event, a *attrs) {
	ev.ToolName = a.str(attrGenAIToolName, attrToolName)
	ev.ToolCallID = a.str(attrGenAIToolCallID)
	if req, ok := a.boolval(attrApprovalRequired); ok {
		ev.ApprovalRequired = &req
	} else {
		required := true
		ev.ApprovalRequired = &required
	}
	switch normalizeDecision(a.str(attrApprovalDecision, attrPermissionDecision)) {
	case model.DecisionAllowed:
		ev.EventType = model.EventPermissionApproved
		ev.Decision = model.DecisionAllowed
		ev.ApprovalDecision = model.DecisionAllowed
	case model.DecisionDenied:
		ev.EventType = model.EventPermissionDenied
		ev.Decision = model.DecisionDenied
		ev.ApprovalDecision = model.DecisionDenied
	default:
		ev.EventType = model.EventPermissionRequested
		ev.Decision = model.DecisionAsked
		ev.ApprovalDecision = model.DecisionAsked
	}
	ev.ApprovalReason = a.str(attrApprovalReason)
}

// isSessionStart reports whether the operation/event name denotes a session or
// agent-run beginning under the GenAI agent conventions.
func isSessionStart(op, name string) bool {
	return op == "start_session" || name == "gen_ai.session.start" || name == "session.start"
}

// isSessionEnd reports whether the operation/event name denotes a session end.
func isSessionEnd(op, name string) bool {
	return op == "end_session" || name == "gen_ai.session.end" || name == "session.end"
}

// normalizeDecision maps the various spellings an exporter may use for a
// permission outcome onto numbat's DecisionAllowed/DecisionDenied, returning ""
// for an absent or ask-shaped value so the caller treats it as an open request.
func normalizeDecision(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow", "allowed", "approve", "approved", "accept", "accepted":
		return model.DecisionAllowed
	case "deny", "denied", "block", "blocked", "reject", "rejected":
		return model.DecisionDenied
	default:
		return ""
	}
}

// errored reports whether the record marks its tool invocation as failed, via a
// standard error severity or an explicit error attribute.
func errored(a *attrs, rec logRecord) bool {
	severity := strings.ToLower(strings.TrimSpace(rec.severityText))
	if strings.HasPrefix(severity, "error") || strings.HasPrefix(severity, "fatal") ||
		(rec.severityNumber >= 17 && rec.severityNumber <= 24) {
		return true
	}
	if b, ok := a.boolval("error", "gen_ai.tool.error"); ok && b {
		return true
	}
	return a.str("error.type") != ""
}

// toolCommandArg pulls a shell command from plain or JSON-encoded tool arguments.
func toolCommandArg(a *attrs) string {
	raw := a.str(attrGenAIToolCallArgs, attrToolCallArgs)
	if object := jsonObject(raw); object != nil {
		return mapString(object, "command", "cmd")
	}
	return raw
}

// narrowInt safely narrows an attacker-controlled int64 OTLP attribute to int.
// On a 32-bit build int is 32 bits, so a value outside [MinInt, MaxInt] would
// silently wrap; ok is false in that case so the caller drops the out-of-range
// field rather than recording a forged number. On 64-bit builds the range check
// is trivially satisfied and the conversion is exact.
func narrowInt(v int64) (int, bool) {
	if v < math.MinInt || v > math.MaxInt {
		return 0, false
	}
	return int(v), true
}

func normalizeSHA256Hex(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return ""
	}
	return strings.ToLower(s)
}

// recordTime prefers the event timestamp and falls back to the collector's
// observed timestamp. It returns empty when neither is usable.
func recordTime(rec logRecord) string {
	nanos := rec.timeUnixNano
	if nanos == 0 {
		nanos = rec.observedTimeUnixNano
	}
	if nanos == 0 || nanos > uint64(math.MaxInt64) {
		return ""
	}
	return time.Unix(0, int64(nanos)).UTC().Format(time.RFC3339Nano)
}

// bodyText returns the record body when it is a string AnyValue, else "".
func bodyText(rec logRecord) string {
	if rec.body.kind == valueString {
		return rec.body.stringValue
	}
	if rec.body.kind == valueArray || rec.body.kind == valueKVList || rec.body.kind == valueBytes {
		return rec.body.structuredText()
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// previewMax bounds a retained excerpt, in runes, matching the hook/extractor.
const previewMax = model.ContentPreviewMaxRunes

func preview(s string) string {
	return model.NormalizeContentPreview(s)
}

// otelNetworkTargetURL returns raw iff it parses as an absolute http:// or
// https:// URL with a host, else "". It is the OTLP-sensor twin of the at-rest
// networkTargetURL / live hookNetworkTargetURL helpers: a network.indicator's
// URL must be a real egress target, so a tampered url.full carrying file://,
// javascript:, data:, a relative path, or junk is rejected here rather than
// promoted into Event.URL (the raw value stays visible via ContentPreview). It
// is kept package-local so the otel sensor stays free of an extract import.
func otelNetworkTargetURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Hostname() == "" {
		return ""
	}
	return raw
}

// mcpFetchToolName and the mcp__ split mirror the hook/extractor constants, kept
// local so the otel sensor stays self-contained.
const (
	mcpNamePrefix = "mcp__"
)

func splitMCPName(name string) (server, tool string, ok bool) {
	if !strings.HasPrefix(name, mcpNamePrefix) {
		return "", "", false
	}
	rest := name[len(mcpNamePrefix):]
	i := strings.Index(rest, "__")
	if i <= 0 || i+2 >= len(rest) {
		return "", "", false
	}
	return rest[:i], rest[i+2:], true
}

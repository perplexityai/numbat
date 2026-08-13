package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// OpenClaw persists one JSONL transcript per session on the Gateway host under
// its agents tree:
//
//	~/.openclaw/agents/<agentId>/sessions/<sessionId>.jsonl
//	~/.openclaw/agents/<agentId>/sessions/<sessionId>-topic-<threadId>.jsonl
//
// This store is HARNESS-AGNOSTIC and MULTI-FLAVOR: OpenClaw embeds several
// harnesses (its native AgentMessage harness, an embedded Codex, and
// others), and EACH writes its OWN wire format into the same .jsonl tree.
// OpenClaw's own reader (.agents/skills/agent-transcript) does a detect-then-
// handle: it sniffs the decoded rows of a file to pick a flavor, then runs a
// flavor-specific extractor. numbat mirrors that contract — it MUST NOT coerce a
// row of one flavor through another flavor's path, and MUST NOT silently return
// zero events on a non-empty file.
//
// SUPPORTED-FLAVOR MATRIX (see openclaw.go for the per-file detector):
//
//	flavor      detect signal                                  numbat support
//	--------    -------------------------------------------    ----------------------------
//	native      type:"session"/"message"; normalized          FULL (toolCall blocks,
//	            AgentMessage content and role:"toolResult"    toolResult envelopes, prose;
//	                                                           provider-block compatibility)
//	codex       type:"response_item"/"session_meta"            FULL (function_call /
//	            (payload.type function_call,                    function_call_output,
//	            function_call_output, reasoning, ...)           local_shell_call,
//	                                                            web_search_call; structured-
//	                                                            only signals)
//	event_msg   type:"event_msg" (payload.type user_message/   FAIL-LOUD (recognized but not
//	            agent_message/...)                              parsed; emits a diagnostic,
//	                                                            never coerced)
//	unknown     none of the above                              FAIL-LOUD diagnostic
//
// HIGH PRECISION boundary (both flavors):
//   - A tool-error tag is read ONLY from a structured boolean (native isError or
//     compatibility is_error). Success, absence, or error-looking prose never
//     produces the tag.
//   - Native exec results expose details.exitCode; numbat emits it only when it
//     is a JSON integer. Embedded-Codex function_call_output has no structured
//     exit-code field and therefore leaves ExitCode nil.

// artifactOpenClawJSONL is the Evidence.ArtifactType stamped on every event
// derived from an OpenClaw session transcript.
const artifactOpenClawJSONL = "openclaw_jsonl"

// openClawFlavor is the per-file wire format numbat detected from the decoded
// rows. The detector (detectOpenClawFlavor) sniffs the first decodable rows; the
// chosen flavor routes the whole file through one extractor so rows of one flavor
// are never coerced through another's path.
type openClawFlavor int

const (
	// openClawFlavorUnknown is the zero value: no row matched a recognized
	// signal. The file is reported as an unparsed flavor (fail-loud), never
	// coerced through a parser.
	openClawFlavorUnknown openClawFlavor = iota
	// openClawFlavorNative is the stable normalized AgentMessage harness.
	// Provider-native blocks are accepted only as backward compatibility.
	openClawFlavorNative
	// openClawFlavorCodex is the embedded Codex harness: response_item /
	// session_meta rows with a payload.type the Codex extractor models.
	openClawFlavorCodex
	// openClawFlavorEventMsg is the event_msg flavor (user_message /
	// agent_message). numbat recognizes but does not parse it: it emits a
	// fail-loud diagnostic rather than coercing it through the native path.
	openClawFlavorEventMsg
)

// String names the flavor for diagnostics.
func (f openClawFlavor) String() string {
	switch f {
	case openClawFlavorNative:
		return "native"
	case openClawFlavorCodex:
		return "codex"
	case openClawFlavorEventMsg:
		return "event_msg"
	default:
		return "unknown"
	}
}

// OpenClaw transcript entry type discriminators (the "type" field of a line).
// Only the kinds numbat maps or explicitly ignores are named; any other type is
// surfaced as a coverage gap rather than guessed at.
const (
	// openClawTypeSession is a session header: it carries session-level context
	// (id, cwd) but is not itself a tool/message event.
	openClawTypeSession = "session"
	// openClawTypeMessage is a user / assistant / toolResult message — the
	// forensic gold, carrying normalized AgentMessages.
	openClawTypeMessage = "message"
	// openClawTypeCustomMessage is an extension-injected message that enters the
	// model context. Its real wire shape is a TOP-LEVEL {type, customType,
	// content, display}, NOT a nested message envelope — it is replayed into
	// context as a user-side custom message, not an agent action. numbat
	// recognizes it and intentionally no-ops it (never fabricates a tool event).
	openClawTypeCustomMessage = "custom_message"
	// openClawTypeCustom is extension state, NOT model context — no forensic
	// signal. Ignored.
	openClawTypeCustom = "custom"
	// openClawTypeCompaction is a persisted history summary (firstKeptEntryId,
	// tokensBefore) — a derived summary, not an action record. Ignored.
	openClawTypeCompaction = "compaction"
	// openClawTypeBranchSummary is a persisted branch summary — derived. Ignored.
	openClawTypeBranchSummary = "branch_summary"
	// Stable SessionEntry control/metadata records that do not describe agent
	// actions. They are recognized no-ops rather than future-schema errors.
	openClawTypeThinkingLevelChange = "thinking_level_change"
	openClawTypeModelChange         = "model_change"
	openClawTypeLabel               = "label"
	openClawTypeSessionInfo         = "session_info"
	openClawTypeLeaf                = "leaf"

	// Codex-flavor outer row discriminators (see codex_entry.go). Their presence
	// in a file selects the Codex flavor.
	openClawTypeResponseItem = "response_item"
	openClawTypeSessionMeta  = "session_meta"
	openClawTypeTurnContext  = "turn_context"

	// openClawTypeEventMsg is the event_msg flavor's row discriminator. Its
	// presence (without native/Codex signals) selects the event_msg flavor,
	// which numbat recognizes but does not parse.
	openClawTypeEventMsg = "event_msg"
)

// OpenClaw message roles (message.role). A tool_use block is an assistant action
// regardless of the carrying role; the role distinguishes a human prompt from an
// assistant turn for prose text.
const (
	openClawRoleUser       = "user"
	openClawRoleAssistant  = "assistant"
	openClawRoleSystem     = "system"
	openClawRoleToolResult = "toolResult"
	openClawRoleBash       = "bashExecution"
	openClawRoleCustom     = "custom"
)

// Stable OpenClaw persists normalized toolCall, text, and thinking blocks. The
// snake_case provider variants remain a compatibility path for older artifacts.
const (
	openClawBlockText              = "text"
	openClawBlockThinking          = "thinking"
	openClawBlockToolCall          = "toolCall"
	openClawBlockToolUseCamel      = "toolUse"
	openClawBlockFunctionCall      = "functionCall"
	openClawBlockToolCallSnake     = "tool_call"
	openClawBlockToolUse           = "tool_use"
	openClawBlockFunctionCallSnake = "function_call"
	openClawBlockToolResult        = "tool_result"
)

// Stable v2026.7.1 built-ins are exec; read; write/edit/apply_patch; and
// web_fetch/web_search/browser. Existing provider-style aliases remain accepted
// for compatibility. Every unknown/plugin tool falls through to tool.call.
var (
	openClawCommandTools = map[string]struct{}{
		"Bash": {}, "shell": {}, "exec": {},
	}
	openClawReadTools = map[string]struct{}{
		"FileRead": {}, "Read": {}, "read": {},
	}
	openClawWriteTools = map[string]struct{}{
		"FileWrite": {}, "FileEdit": {}, "Write": {}, "Edit": {}, "write": {}, "edit": {},
	}
	openClawNetworkTools = map[string]struct{}{
		"WebFetch": {}, "WebSearch": {}, "web_fetch": {}, "web_search": {}, "browser": {},
	}
)

// OpenClaw tool input argument keys, from the same artifact-backed vocabulary.
// Numbat reads only the fields it maps onto a typed event; everything else in
// input is ignored.
const (
	openClawArgCommand   = "command"   // command tools
	openClawArgURL       = "url"       // network tools
	openClawArgTargetURL = "targetUrl" // browser navigation
	openClawArgQuery     = "query"     // web search
)

// openClawFilePathKeys are the input keys a file tool may carry the path under,
// in precedence order (file_path then path).
var openClawFilePathKeys = []string{"file_path", "path"}

// openClawEntry is a tolerant view of one transcript line. Only the fields
// numbat maps are decoded; OpenClaw entries carry many more (id, parentId,
// timestamps, token bookkeeping) that numbat does not surface, so unrelated
// schema additions do not break parsing. Type is the discriminator; the
// remaining fields are populated only for the line kind that carries them.
type openClawEntry struct {
	Type string `json:"type"`
	// Session header fields (type:"session").
	ID        string `json:"id"`
	CWD       string `json:"cwd"`
	Timestamp string `json:"timestamp"`
	// Message fields (type:"message").
	Message openClawMessage `json:"message"`
	// custom_message fields. The real wire shape is TOP-LEVEL, not a nested
	// message envelope: {type:"custom_message", customType, content, display}.
	// numbat recognizes it and no-ops it (it is context replay, not an action),
	// so the fields are decoded only to confirm recognition, never mapped to a
	// tool event.
	CustomType string `json:"customType"`
	// Codex-flavor payload (deferred). For a response_item / session_meta /
	// turn_context / event_msg row, the inner shape is decoded by the Codex path.
	Payload json.RawMessage `json:"payload"`
}

// openClawMessage is the stable normalized AgentMessage envelope. Content is a
// string or block array. A role:"toolResult" message carries correlation and
// status on this envelope rather than in a content block.
type openClawMessage struct {
	Role            string
	Content         []openClawBlock
	ContentIsString bool
	ToolCallID      string
	ToolName        string
	IsError         *bool
	Details         json.RawMessage
	Command         string
	Output          string
	ExitCode        *int
	Cancelled       bool
	Truncated       bool
}

// openClawBlock is one normalized content block. Stable toolCall blocks carry
// id/name/arguments. Input, ToolUseID, and IsError decode the legacy provider-
// block compatibility shape. Synthesized marks text created from string content
// so the evidence pointer remains source-faithful.
type openClawBlock struct {
	Type            string           `json:"type"`
	Text            string           `json:"text"`
	Thinking        string           `json:"thinking"`
	Redacted        bool             `json:"redacted"`
	Name            string           `json:"name"`
	ID              string           `json:"id"`
	ToolCallID      string           `json:"toolCallId"`
	ToolUseIDCamel  string           `json:"toolUseId"`
	ToolCallIDSnake string           `json:"tool_call_id"`
	ToolUseID       string           `json:"tool_use_id"`
	CallID          string           `json:"callId"`
	CallIDSnake     string           `json:"call_id"`
	Arguments       openClawToolArgs `json:"arguments"`
	Input           openClawToolArgs `json:"input"`
	IsError         *bool            `json:"is_error"`
	Synthesized     bool             `json:"-"`
}

// openClawToolArgs tolerates both the object form used by normalized/camel
// calls and the JSON-encoded string retained by some legacy function_call rows.
// A malformed/non-object value becomes an empty argument set without rejecting
// the entire message line and losing adjacent valid calls.
type openClawToolArgs map[string]json.RawMessage

func (a *openClawToolArgs) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		*a = nil
		return nil
	}
	if trimmed[0] == '"' {
		var encoded string
		if json.Unmarshal(raw, &encoded) != nil {
			*a = nil
			return nil
		}
		raw = []byte(encoded)
		trimmed = strings.TrimSpace(encoded)
	}
	if trimmed == "" || trimmed[0] != '{' {
		*a = nil
		return nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		*a = nil
		return nil
	}
	*a = object
	return nil
}

// openClawMessageWire mirrors the on-disk message shape, deferring content
// decoding so the string-or-array union can be resolved explicitly.
type openClawMessageWire struct {
	Role            string          `json:"role"`
	Content         json.RawMessage `json:"content"`
	ToolCallID      string          `json:"toolCallId"`
	ToolUseID       string          `json:"toolUseId"`
	ToolCallIDSnake string          `json:"tool_call_id"`
	ToolUseIDSnake  string          `json:"tool_use_id"`
	CallID          string          `json:"callId"`
	CallIDSnake     string          `json:"call_id"`
	ToolName        string          `json:"toolName"`
	IsError         *bool           `json:"isError"`
	Details         json.RawMessage `json:"details"`
	Command         string          `json:"command"`
	Output          string          `json:"output"`
	ExitCode        *int            `json:"exitCode"`
	Cancelled       bool            `json:"cancelled"`
	Truncated       bool            `json:"truncated"`
}

// UnmarshalJSON normalizes the two content encodings OpenClaw persists:
//
//	"content": "a plain prompt"            → one synthetic, Synthesized text block
//	"content": [ {"type":"tool_use",...} ] → decoded as-is
//
// A missing or null content yields no blocks rather than an error, keeping the
// parse tolerant. ContentIsString records the string case so the emit site
// stamps /message/content (the resolvable pointer) rather than a fabricated
// /message/content/0/text. Legacy provider blocks use the same array branch.
func (m *openClawMessage) UnmarshalJSON(b []byte) error {
	var w openClawMessageWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	m.Role = w.Role
	m.Content = nil
	m.ContentIsString = false
	m.ToolCallID = openClawFirstNonEmpty(
		w.ToolCallID,
		w.ToolUseID,
		w.ToolCallIDSnake,
		w.ToolUseIDSnake,
		w.CallID,
		w.CallIDSnake,
	)
	m.ToolName = w.ToolName
	m.IsError = w.IsError
	m.Details = w.Details
	m.Command = w.Command
	m.Output = w.Output
	m.ExitCode = w.ExitCode
	m.Cancelled = w.Cancelled
	m.Truncated = w.Truncated

	raw := strings.TrimSpace(string(w.Content))
	if raw == "" || raw == "null" {
		return nil
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(w.Content, &s); err != nil {
			return err
		}
		m.ContentIsString = true
		if s != "" {
			m.Content = []openClawBlock{{Type: openClawBlockText, Text: s, Synthesized: true}}
		}
	case '[':
		return json.Unmarshal(w.Content, &m.Content)
	default:
		// A non-string, non-array content (a bare object or scalar) is not a
		// provider-native shape numbat trusts; leave content empty so the line
		// degrades to "no tool signal" rather than failing the whole parse.
		return nil
	}
	return nil
}

// openClawFirstNonEmpty follows OpenClaw's tool-result correlation contract:
// provider transports retain several legacy ID aliases, all of which are
// trimmed before use. The canonical toolCallId field remains first priority.
func openClawFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

// isError reports whether a compatibility tool_result block is flagged by the
// structured is_error boolean. A nil pointer (absent field) is NOT an
// error: the sole tool-error signal is an explicit is_error:true, never inferred
// from output prose.
func (c *openClawBlock) isError() bool { return c.IsError != nil && *c.IsError }

// isError reports whether a stable toolResult envelope explicitly records a
// failure. Output prose is never inspected.
func (m *openClawMessage) isError() bool { return m.IsError != nil && *m.IsError }

// openClawExitCode returns a native exec result's structured integer
// details.exitCode. Strings, fractions, null, absence, and malformed details are
// unknown rather than coerced.
func openClawExitCode(details json.RawMessage) *int {
	var envelope struct {
		ExitCode json.RawMessage `json:"exitCode"`
	}
	if len(details) == 0 || json.Unmarshal(details, &envelope) != nil {
		return nil
	}
	raw := strings.TrimSpace(string(envelope.ExitCode))
	if raw == "" || raw == "null" {
		return nil
	}
	var code int
	if json.Unmarshal(envelope.ExitCode, &code) != nil {
		return nil
	}
	return &code
}

// openClawArgString returns the string value of a tool input arg, or "" when the
// arg is absent or not a JSON string. It mirrors openCodeArgString / inputString.
func openClawArgString(input map[string]json.RawMessage, key string) string {
	raw, ok := input[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// openClawArgFirstString returns the first non-empty string among the given
// input keys, in order (used for the file_path/path alias).
func openClawArgFirstString(input map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := openClawArgString(input, k); s != "" {
			return s
		}
	}
	return ""
}

// openClawEventID returns a stable, unique identifier for an event derived from
// a transcript line at a known on-disk path. line fixes the source position;
// block keeps the id unique when one line emits more than one event (a message
// with several content blocks). A tool id/tool_use_id is NOT used as the event
// id: it correlates a call to its result but is shared between them, so it is not
// unique per event.
func openClawEventID(path string, line, block int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, block))
	return "openclaw-" + hex.EncodeToString(sum[:16])
}

// openClawSubEventID extends the ordinary line/block identity for a single
// apply_patch block that expands into multiple requested file events.
func openClawSubEventID(path string, line, block, sub int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d:%d", path, line, block, sub))
	return "openclaw-" + hex.EncodeToString(sum[:16])
}

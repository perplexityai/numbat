package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// mcpFetchToolName is the qualified identifier of the canonical Model Context
// Protocol fetch server's tool (modelcontextprotocol/servers src/fetch): the
// tool "fetch" on a server named "fetch". Both Claude Code and Codex flatten an
// MCP tool to mcp__<server>__<tool>, so the canonical fetch server appears
// identically as "mcp__fetch__fetch". It is shared here because more than one
// parser recognizes this exact tool as a network-egress site; agent-specific
// tool names stay in their own parser. Matching is exact identity, never a
// substring/heuristic sniff of arbitrary MCP names.
const mcpFetchToolName = "mcp__fetch__fetch"

// mcpNamePrefix is the prefix both Claude Code and Codex stamp on a flattened
// Model Context Protocol tool identifier (mcp__<server>__<tool>).
const mcpNamePrefix = "mcp__"

// splitMCPName splits a flattened MCP tool identifier mcp__<server>__<tool>
// into its server and tool segments. The server is everything between the
// mcp__ prefix and the next "__"; the tool is the remainder (which may itself
// contain "__", as a tool name can). It returns ok=false for any name that is
// not an mcp__ identifier with both segments present, so a native tool name is
// left untouched.
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

// claudeEntry is a tolerant view of one Claude Code transcript line. Only the
// fields Numbat maps are decoded; the format carries many more (usage, model,
// gitBranch, ...) that we intentionally ignore so unrelated schema changes do
// not break parsing.
type claudeEntry struct {
	Type          string          `json:"type"`
	UUID          string          `json:"uuid"`
	SessionID     string          `json:"sessionId"`
	AgentID       string          `json:"agentId"`
	Timestamp     string          `json:"timestamp"`
	CWD           string          `json:"cwd"`
	RelocatedCWD  string          `json:"relocatedCwd"`
	Message       claudeMessage   `json:"message"`
	ToolUseResult json.RawMessage `json:"toolUseResult"`
	// Session-context header fields Claude Code stamps on transcript entries: the
	// repo branch the agent ran against, and the Claude Code CLI version. They are
	// session join keys, not evidence, surfaced on the synthetic session.start
	// event (the version on CLIVersion — it is a version string, not a launch
	// entrypoint).
	GitBranch string `json:"gitBranch"`
	Version   string `json:"version"`
	// PermissionMode is set only on type:"permission-mode" records, which Claude
	// Code writes whenever the session's permission mode changes. Per Claude
	// Code's permission docs the value is one of six modes: "default", "plan",
	// "acceptEdits", "auto", "dontAsk", "bypassPermissions".
	PermissionMode string `json:"permissionMode"`
	// Mode is set only on type:"mode" records, which Claude Code writes on a
	// permission-mode switch the same way type:"permission-mode" does, but carries
	// the new mode in the "mode" field and stamps no timestamp. Observed values
	// include "normal" (the in-loop default); the guardrail-removing modes
	// elevatedPermissionMode flags (acceptEdits/auto/bypassPermissions) carry the
	// same meaning here as on PermissionMode.
	Mode string `json:"mode"`
	// PRURL is set only on type:"pr-link" records, which Claude Code writes when a
	// pull request is created/associated during the session. It is the pull request
	// URL — a concrete network/output artifact.
	PRURL string `json:"prUrl"`
	// AgentName is set only on type:"agent-name" records, a lightweight marker
	// Claude Code writes to identify which named subagent/skill persona is active
	// in the session. The line carries no command, file, or tool payload and no
	// timestamp — only type, agentName, sessionId.
	AgentName string `json:"agentName"`
	// Attachment is set only on type:"attachment" records, which carry context
	// injected into the model rather than agent activity. Its own type field
	// discriminates the payload; only "deferred_tools_delta" (a change to the
	// tool/capability set available to the agent) is forensically material.
	Attachment claudeAttachment `json:"attachment"`
}

// claudeAttachment is a tolerant view of an attachment record's payload. Only
// the deferred_tools_delta fields are decoded; other subtypes (IDE selections,
// queued-command echoes) carry no capability signal and are ignored.
type claudeAttachment struct {
	Type         string   `json:"type"`
	AddedNames   []string `json:"addedNames"`
	RemovedNames []string `json:"removedNames"`
}

// claudeMessage is the user/assistant message envelope. content is either a
// plain string (simple user prompts) or an array of typed content blocks; the
// custom unmarshaler normalizes both into Content. Model is the assistant
// message's model id, a source-recorded session join key.
type claudeMessage struct {
	Role    string
	Model   string
	Content []claudeContent
}

// claudeContent is one block within a message's content array. ID is the
// tool_use block's call id (correlates with the matching tool_result);
// Thinking is the reasoning text on a thinking block.
type claudeContent struct {
	Type      string                     `json:"type"`
	Text      string                     `json:"text"`
	Name      string                     `json:"name"`
	ID        string                     `json:"id"`
	ToolUseID string                     `json:"tool_use_id"`
	Input     map[string]json.RawMessage `json:"input"`
	IsError   *bool                      `json:"is_error"`
	Thinking  string                     `json:"thinking"`
}

// messageWire mirrors the on-disk message shape, deferring content decoding so
// the string-or-array union can be resolved explicitly.
type messageWire struct {
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
}

// UnmarshalJSON normalizes the two content encodings Claude emits:
//
//	"content": "a plain prompt"          → one synthetic text block
//	"content": [ {"type":"text",...}, ]  → decoded as-is
//
// A missing or null content yields no blocks rather than an error, keeping the
// parse tolerant.
func (m *claudeMessage) UnmarshalJSON(b []byte) error {
	var w messageWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	m.Role = w.Role
	m.Model = w.Model
	m.Content = nil

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
		if s != "" {
			m.Content = []claudeContent{{Type: "text", Text: s}}
		}
	case '[':
		return json.Unmarshal(w.Content, &m.Content)
	default:
		return fmt.Errorf("unexpected message.content encoding")
	}
	return nil
}

// text returns the concatenated text of all text blocks in the message.
func (m claudeMessage) text() string {
	var b strings.Builder
	for i := range m.Content {
		if m.Content[i].Type == "text" {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(m.Content[i].Text)
		}
	}
	return b.String()
}

// hasToolUseResult reports whether the entry carries a non-null top-level
// toolUseResult payload (the parallel field Claude writes alongside tool output).
func (e *claudeEntry) hasToolUseResult() bool {
	return len(e.ToolUseResult) > 0 && string(e.ToolUseResult) != "null"
}

// toolUseResultObj is the object form of a top-level toolUseResult. Claude
// writes the Bash tool's outcome here as stdout/stderr/exit_code/is_error
// (claude_test.go nonzero_exit/zero_exit cases); other tools write other shapes.
// A string or list payload decodes to the zero value and exposes no fields.
type toolUseResultObj struct {
	IsError  *bool   `json:"is_error"`
	ExitCode *int    `json:"exit_code"`
	Stdout   *string `json:"stdout"`
	Stderr   *string `json:"stderr"`
	// Duration is the command's wall-clock time in milliseconds. Claude Code
	// records it on the Bash toolUseResult as durationMs (the alias totalDurationMs
	// appears on some builds); either is accepted, durationMs taking precedence.
	DurationMs      *int64 `json:"durationMs"`
	TotalDurationMs *int64 `json:"totalDurationMs"`
}

// decodeToolUseResult decodes the top-level toolUseResult into its object form.
// ok is false for an absent/null payload or a non-object (string/list) body, so
// callers can treat a non-command shape as "no signal".
func (e *claudeEntry) decodeToolUseResult() (obj toolUseResultObj, ok bool) {
	if !e.hasToolUseResult() {
		return toolUseResultObj{}, false
	}
	if json.Unmarshal(e.ToolUseResult, &obj) != nil {
		return toolUseResultObj{}, false
	}
	return obj, true
}

// toolUseResultIsError reports whether a top-level toolUseResult payload signals
// failure. The payload shape varies by tool; an object with is_error:true, a
// non-zero exit_code, or non-empty stderr is treated as an error. A string or
// list payload carries no error signal and returns false.
func (e *claudeEntry) toolUseResultIsError() bool {
	obj, ok := e.decodeToolUseResult()
	if !ok {
		return false
	}
	switch {
	case obj.IsError != nil:
		return *obj.IsError
	case obj.ExitCode != nil:
		return *obj.ExitCode != 0
	case obj.Stderr != nil:
		return *obj.Stderr != ""
	default:
		return false
	}
}

// toolUseResultExitCode returns the command exit code carried by a top-level
// toolUseResult, or nil when the payload records none (so a clean exit 0 stays
// distinct from an absent code). It is the only structured exit status Claude
// persists; it lives on the entry, never on the per-block tool_result.
func (e *claudeEntry) toolUseResultExitCode() *int {
	obj, ok := e.decodeToolUseResult()
	if !ok {
		return nil
	}
	return obj.ExitCode
}

// toolUseResultDurationMs returns the command's wall-clock duration in
// milliseconds from a top-level toolUseResult, or nil when none was recorded (so
// a real 0ms stays distinct from absent). durationMs is preferred; some builds
// write totalDurationMs instead. It accompanies the exit code on a Bash result.
func (e *claudeEntry) toolUseResultDurationMs() *int64 {
	obj, ok := e.decodeToolUseResult()
	if !ok {
		return nil
	}
	if obj.DurationMs != nil {
		return obj.DurationMs
	}
	return obj.TotalDurationMs
}

// toolUseResultIsCommand reports whether a top-level toolUseResult payload is
// recognizably a command (Bash) result by its own shape. The test is exit_code
// alone: a command Claude writes to the top level always carries one, while
// stdout/stderr are NOT command-specific — a file read's toolUseResult also
// carries stdout, so keying on it would mis-promote a Read to command.result.
// This evidence promotes a tool.result to command.result only when no
// tool_use_id is present to correlate against a prior Bash call; without an
// exit_code there is no faithful evidence the payload is a command, so it stays
// tool.result.
func (e *claudeEntry) toolUseResultIsCommand() bool {
	obj, ok := e.decodeToolUseResult()
	if !ok {
		return false
	}
	return obj.ExitCode != nil
}

// isError reports whether a tool_result block is flagged as an error.
func (c *claudeContent) isError() bool { return c.IsError != nil && *c.IsError }

// eventID returns a stable, unique identifier for an event derived from this
// entry. One transcript line can emit several events (an assistant turn with
// text and multiple tool calls), so the content-block index is folded in to
// keep ids unique. Claude entries carry a uuid; when absent, the artifact path
// and line stand in so ids remain deterministic and reproducible.
func (e *claudeEntry) eventID(path string, line, block int) string {
	if e.UUID != "" {
		return fmt.Sprintf("%s#%d", e.UUID, block)
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, block))
	return "claude-" + hex.EncodeToString(sum[:8])
}

// inputString returns the string value of a tool input field, or "" if the
// field is absent or not a JSON string.
func inputString(input map[string]json.RawMessage, key string) string {
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

// firstInputString returns the first non-empty string among the given input
// keys, in order.
func firstInputString(input map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := inputString(input, k); s != "" {
			return s
		}
	}
	return ""
}

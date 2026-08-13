package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perplexityai/numbat/internal/applypatch"
)

// Codex rollout outer record types (the top-level "type" discriminator). See
// codex-rs/protocol/src/protocol.rs (RolloutItem) and the schema research
// report: every line is {"timestamp","type","payload"}.
const (
	codexTypeSessionMeta  = "session_meta"
	codexTypeResponseItem = "response_item"
	codexTypeEventMsg     = "event_msg"
	codexTypeTurnContext  = "turn_context"
	codexTypeCompacted    = "compacted"
)

// Codex response_item inner payload types (ResponseItem enum, snake_case). Only
// the variants numbat maps are named; unknown variants fall through to a
// generic tool.call or are skipped so a format addition never breaks parsing.
const (
	codexRIMessage             = "message"
	codexRIReasoning           = "reasoning"
	codexRIFunctionCall        = "function_call"
	codexRIFunctionCallOutput  = "function_call_output"
	codexRILocalShellCall      = "local_shell_call"
	codexRICustomToolCall      = "custom_tool_call"
	codexRICustomToolCallOut   = "custom_tool_call_output"
	codexRIToolSearchCall      = "tool_search_call"
	codexRIToolSearchOutput    = "tool_search_output"
	codexRIWebSearchCall       = "web_search_call"
	codexRIImageGenerationCall = "image_generation_call"
	// Inner history-compaction variants. The Compaction body carries only
	// opaque encrypted_content (no human-readable summary), so these are
	// explicit no-ops, distinct from a silent default fallthrough. The alias
	// compaction_summary is the same Rust variant (models.rs Compaction).
	codexRICompaction        = "compaction"
	codexRICompactionSummary = "compaction_summary"
	codexRIContextCompaction = "context_compaction"
)

// Codex event_msg types numbat interprets: explicit user prompts, distinct
// state changes, structured MCP outcomes, and fork boundaries.
const (
	codexEMUserMessage      = "user_message"
	codexEMItemStarted      = "item_started"
	codexEMItemCompleted    = "item_completed"
	codexEMTurnAborted      = "turn_aborted"
	codexEMThreadRolledBack = "thread_rolled_back"
	// task_started is a fork replay boundary, not an emitted timeline event.
	codexEMTaskStarted = "task_started"
	// Persisted event_msg lifecycle/state transitions with NO response_item
	// twin (verified against policy.rs should_persist_event_msg). Unlike
	// user_message/agent_message/patch_apply_end — which duplicate a
	// response_item record — these are emitted as low-confidence session
	// notes so the transition is on the timeline rather than lost.
	codexEMEnteredReviewMode = "entered_review_mode"
	codexEMExitedReviewMode  = "exited_review_mode"
	codexEMThreadGoalUpdated = "thread_goal_updated"
	// codexEMMcpToolCallEnd terminates an MCP tool call. The response_item layer
	// already emitted the tool.call/tool.result for the same call_id, so the
	// timeline is not re-emitted from this event_msg; it is read ONLY for its
	// structured result, which faithfully records MCP success/failure (see
	// codexMcpResultIsError). policy.rs persists this variant (the begin twin is
	// not), so a failed MCP tool result is recoverable at rest.
	codexEMMcpToolCallEnd = "mcp_tool_call_end"
)

// Codex function_call tool names (literal "name" values). Shell calls have
// appeared as shell, shell_command, and exec_command across Codex surfaces.
// apply_patch carries a unified-diff patch; the explicit file tools name their
// target directly.
const (
	codexToolShell        = "shell"
	codexToolShellCommand = "shell_command"
	codexToolExecCommand  = "exec_command"
	codexToolApplyPatch   = "apply_patch"
	codexToolReadFile     = "read_file"
	codexToolWriteFile    = "create_file"
	codexToolEditFile     = "edit_file"
	codexToolCodeModeExec = "exec"
	codexToolWait         = "wait"
	codexToolUpdatePlan   = "update_plan"
	codexToolSearch       = "tool_search"
	codexToolImage        = "image_generation"
)

// Tags numbat stamps on Codex events. patch_apply_requested marks an
// apply_patch file event as a REQUESTED change (taken from the function_call
// request line) rather than a confirmed write: Codex records the actual outcome
// separately in a patch_apply_end event_msg, and numbat does not correlate the
// two layers, so the request-side event is honestly flagged as intent.
const codexTagPatchRequested = "patch_apply_requested"

// codexLine is the tolerant view of one rollout JSONL line. Payload is deferred
// for a second decode pass keyed by Type.
type codexLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// codexSessionMeta is the first-line metadata: thread identity, fork lineage,
// working directory, and runtime details. Only fields numbat uses are decoded.
type codexSessionMeta struct {
	ID            string `json:"id"`
	ForkedFromID  string `json:"forked_from_id"`
	Timestamp     string `json:"timestamp"`
	Cwd           string `json:"cwd"`
	Originator    string `json:"originator"`
	CliVersion    string `json:"cli_version"`
	ModelProvider string `json:"model_provider"`
}

func codexUUID(id string) ([16]byte, bool) {
	var uuid [16]byte
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return uuid, false
	}
	compact := id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:]
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != len(uuid) {
		return uuid, false
	}
	copy(uuid[:], decoded)
	version := uuid[6] >> 4
	if uuid[8]&0xc0 != 0x80 || version == 0 || version > 8 {
		return [16]byte{}, false
	}
	return uuid, true
}

func codexUUIDv7(id string) ([16]byte, bool) {
	uuid, ok := codexUUID(id)
	if !ok || uuid[6]>>4 != 7 {
		return [16]byte{}, false
	}
	return uuid, true
}

// codexTurnContext carries the per-turn working directory. One turn_context is
// written before each turn of a resumed session; numbat uses cwd to keep
// ProjectPath current as the session's working directory changes mid-file.
type codexTurnContext struct {
	Cwd string `json:"cwd"`
}

// codexResponseItem is the tolerant view of a response_item payload. The inner
// "type" discriminates the variant; the remaining fields are the union of the
// variant fields numbat reads. Codex has written arguments/input as both JSON
// strings and structured JSON depending on variant/version, so those fields use
// codexFlexibleString to keep parser drift from turning valid rollouts into
// diagnostics. output is string-or-array and is left raw.
type codexResponseItem struct {
	Type string `json:"type"`
	// FunctionCall / CustomToolCall
	Name      string              `json:"name"`
	Arguments codexFlexibleString `json:"arguments"`
	Input     codexFlexibleString `json:"input"`
	CallID    string              `json:"call_id"`
	Namespace string              `json:"namespace"`
	// Message
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	// LocalShellCall / WebSearchCall
	Status string          `json:"status"`
	Action json.RawMessage `json:"action"`
	// FunctionCallOutput / CustomToolCallOutput. The output wire shape is
	// untagged: either a plain string or an array of content items
	// (FunctionCallOutputPayload in models.rs), so it is decoded with the same
	// string-or-array logic as message content.
	Output json.RawMessage `json:"output"`
	// ToolSearchOutput. The wire shape (ToolSearchOutput in models.rs) carries
	// a list of tool *definitions* under "tools": [{type,name,description,...}],
	// not a free-form "output" string. numbat surfaces the discovered tool
	// names so the timeline records which capabilities were searched/exposed.
	Tools json.RawMessage `json:"tools"`
	// Reasoning. The reasoning item's human-readable text is the summary array
	// (ReasoningItemReasoningSummary: [{type:"summary_text", text}]). Older/raw
	// shapes carry it under content instead, so both are accepted; the reasoning
	// text is surfaced only when reasoning is requested.
	Summary json.RawMessage `json:"summary"`
}

// codexFlexibleString accepts a JSON string or any structured JSON value and
// stores the human-usable text form. A JSON object remains object JSON, which
// lets codexArgString parse current Codex tool_search/function_call arguments;
// a JSON string remains the unwrapped arguments string.
type codexFlexibleString string

func (s *codexFlexibleString) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*s = ""
		return nil
	}
	var text string
	if json.Unmarshal(trimmed, &text) == nil {
		*s = codexFlexibleString(text)
		return nil
	}
	if json.Valid(trimmed) {
		*s = codexFlexibleString(trimmed)
		return nil
	}
	*s = ""
	return nil
}

// codexWebSearchAction is the action union of a web_search_call. The Rust
// WebSearchAction enum has search (query), open_page (url), and find_in_page
// (url + pattern) variants; numbat surfaces whichever locator is present so a
// network event names what was searched/opened, not just that egress occurred.
type codexWebSearchAction struct {
	Type    string `json:"type"`
	Query   string `json:"query"`
	URL     string `json:"url"`
	Pattern string `json:"pattern"`
}

// codexContentItem is one element of a message.content array. input_text and
// output_text carry user/assistant prose; input_image carries an image URL
// numbat does not retain.
type codexContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// codexLocalShellAction is the action of a local_shell_call. The only variant
// is "exec", whose command is an argv array.
type codexLocalShellAction struct {
	Type    string   `json:"type"`
	Command []string `json:"command"`
}

// codexEventMsg is the tolerant view of the event_msg variants numbat uses.
type codexEventMsg struct {
	Type    string          `json:"type"`
	TurnID  string          `json:"turn_id"`
	Reason  string          `json:"reason"`
	Message string          `json:"message"`
	Item    json.RawMessage `json:"item"`
	// CallID joins an mcp_tool_call_end to the custom_tool_call(_output) the
	// response_item layer already emitted for the same MCP invocation.
	CallID string `json:"call_id"`
	// Result is the mcp_tool_call_end's Result<CallToolResult, String>, serialized
	// externally tagged as {"Ok": {...}} or {"Err": "..."}. Decoded by
	// codexMcpResultIsError; left raw here so a shape numbat does not recognize is
	// tolerated rather than failing the whole event_msg decode.
	Result json.RawMessage `json:"result"`
}

type codexTurnItem struct {
	Type    string             `json:"type"`
	Content []codexContentItem `json:"content"`
}

func decodeCodexCompletedUserMessage(raw json.RawMessage) (string, bool) {
	var item codexTurnItem
	if json.Unmarshal(raw, &item) != nil || item.Type != "UserMessage" {
		return "", false
	}
	parts := make([]string, 0, len(item.Content))
	for _, content := range item.Content {
		if content.Type == "text" {
			parts = append(parts, content.Text)
		}
	}
	return strings.Join(parts, ""), true
}

func codexUserPromptContinuation(line codexLine) bool {
	if line.Type != codexTypeEventMsg {
		return false
	}
	var event codexEventMsg
	if json.Unmarshal(line.Payload, &event) != nil {
		return true
	}
	switch event.Type {
	case codexEMUserMessage:
		return true
	case codexEMItemStarted, codexEMItemCompleted:
		var item codexTurnItem
		return json.Unmarshal(event.Item, &item) == nil && item.Type == "UserMessage"
	default:
		return false
	}
}

// codexMcpResultIsError reports whether an mcp_tool_call_end's result records a
// FAILURE, reading only the structured Result<CallToolResult, String> — never
// any prose body. serde serializes that Result externally tagged, so failure is
// either an "Err" variant (transport/protocol error) or an "Ok" CallToolResult
// whose is_error is true (the MCP tool itself reported failure; is_error absent
// means success, per the rmcp default). ok is false when the field is absent or
// its shape is unrecognized, so a tool whose end-event numbat cannot read is
// left untagged rather than guessed either way.
func codexMcpResultIsError(raw json.RawMessage) (isError, ok bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return false, false
	}
	var env struct {
		Err *json.RawMessage `json:"Err"`
		Ok  *struct {
			IsError *bool `json:"is_error"`
		} `json:"Ok"`
	}
	if json.Unmarshal(trimmed, &env) != nil {
		return false, false
	}
	switch {
	case env.Err != nil:
		return true, true
	case env.Ok != nil:
		return env.Ok.IsError != nil && *env.Ok.IsError, true
	default:
		return false, false
	}
}

// messageText concatenates the text of input_text/output_text content items.
// A message.content may also be a bare JSON string (older/simple shape); that
// is handled by decodeCodexContentText.
func decodeCodexContentText(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	if trimmed[0] == '"' {
		var s string
		if json.Unmarshal(trimmed, &s) == nil {
			return s
		}
		return ""
	}
	if trimmed[0] != '[' {
		return ""
	}
	var items []codexContentItem
	if json.Unmarshal(trimmed, &items) != nil {
		return ""
	}
	var b strings.Builder
	for i := range items {
		switch items[i].Type {
		// "text" is not in the current Codex ContentItem enum (input_text/
		// input_image/output_text); it is accepted defensively for tolerance.
		case "input_text", "output_text", "text":
			if items[i].Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(items[i].Text)
		}
	}
	return b.String()
}

// decodeCodexOutput decodes a function_call_output / custom_tool_call_output
// output field. The wire shape is untagged — a plain JSON string OR an array of
// content items — so it reuses decodeCodexContentText, which already handles
// both. Returns "" for absent/null/non-text output.
func decodeCodexOutput(raw json.RawMessage) string {
	return decodeCodexContentText(raw)
}

// decodeCodexToolSearchTools decodes a tool_search_output.tools array into a
// comma-joined list of the discovered tool names. The wire shape (ToolSearchOutput
// in models.rs) is tools: [{type,name,description,defer_loading,parameters}, ...];
// the name is the forensically relevant key (e.g. an mcp__ tool identifier), so
// the timeline records which capabilities a tool search surfaced. Returns "" when
// the array is absent, malformed, or carries no named tools.
func decodeCodexToolSearchTools(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var tools []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &tools) != nil {
		return ""
	}
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if name := strings.TrimSpace(t.Name); name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

// decodeCodexWebSearchAction extracts the human-readable locator from a
// web_search_call.action: the query for a search, the url for open_page, or
// "url pattern" for find_in_page. Returns "" when the action is absent or
// carries none of these. The locator is the investigative lead a reviewer
// needs from a network event.
func decodeCodexWebSearchAction(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var a codexWebSearchAction
	if json.Unmarshal(raw, &a) != nil {
		return ""
	}
	switch {
	case a.Query != "":
		return a.Query
	case a.URL != "" && a.Pattern != "":
		return a.URL + " " + a.Pattern
	case a.URL != "":
		return a.URL
	case a.Pattern != "":
		return a.Pattern
	}
	return ""
}

// codexWebSearchURL returns the concrete url a web_search_call.action targeted
// (open_page / find_in_page), or "" for a bare search query that carries no
// url. It is the typed egress target promoted onto the network indicator,
// distinct from the human-readable locator decodeCodexWebSearchAction previews.
func codexWebSearchURL(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var a codexWebSearchAction
	if json.Unmarshal(raw, &a) != nil {
		return ""
	}
	return a.URL
}

// decodeCodexReasoningText extracts the human-readable reasoning text from a
// reasoning response_item. The current shape is a summary array of
// {type:"summary_text", text}; older/raw shapes inline the text under content
// (string or array). The summary array is decoded explicitly first (its
// summary_text item type is not what decodeCodexContentText expects), falling
// back to the content field.
func decodeCodexReasoningText(summary, content json.RawMessage) string {
	if s := decodeCodexSummaryText(summary); s != "" {
		return s
	}
	return decodeCodexContentText(content)
}

// decodeCodexSummaryText joins the text of a reasoning summary array
// ([{type:"summary_text", text}, ...]). Returns "" when absent or malformed.
func decodeCodexSummaryText(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var items []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return ""
	}
	var b strings.Builder
	for i := range items {
		if items[i].Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(items[i].Text)
	}
	return b.String()
}

// decodeCodexShellAction decodes a local_shell_call.action and joins its argv
// into a single command string for the event. Returns "" when the action is
// absent, malformed, or not an exec.
func decodeCodexShellAction(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var a codexLocalShellAction
	if json.Unmarshal(raw, &a) != nil {
		return ""
	}
	return strings.Join(a.Command, " ")
}

// codexShellCommand extracts the command from a shell function_call's
// function_call arguments string. The arguments field is itself JSON-encoded
// text. shell/shell_command use "command" while exec_command uses "cmd"; either
// value may be a string or argv array.
func codexShellCommand(arguments string) string {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return ""
	}
	var probe struct {
		Command json.RawMessage `json:"command"`
		Cmd     json.RawMessage `json:"cmd"`
	}
	if json.Unmarshal([]byte(trimmed), &probe) != nil {
		return ""
	}
	cmd := bytes.TrimSpace(probe.Command)
	if len(cmd) == 0 {
		cmd = bytes.TrimSpace(probe.Cmd)
	}
	if len(cmd) == 0 {
		return ""
	}
	switch cmd[0] {
	case '"':
		var s string
		if json.Unmarshal(cmd, &s) == nil {
			return s
		}
	case '[':
		var argv []string
		if json.Unmarshal(cmd, &argv) == nil {
			return strings.Join(argv, " ")
		}
	}
	return ""
}

// codexMCPPrefix is the "mcp__" prefix Codex stamps on the server segment of an
// MCP tool's qualified name (codex-rs core/src/tools/handlers/tool_search.rs
// builds the callable namespace as format!("mcp__{server_name}"); router tests
// use namespaces like "mcp__codex_apps__calendar" and "mcp__echo__"). The double
// underscore also separates server from tool, matching Claude's
// mcp__<server>__<tool> flattening.
const codexMCPPrefix = "mcp__"

// isCodexMCPFetch reports whether a Codex function_call identifies the canonical
// MCP fetch tool: the tool "fetch" on the MCP server "fetch"
// (modelcontextprotocol/servers src/fetch). It is an EXACT canonical-server
// match, never a heuristic on arbitrary MCP names.
//
// Codex records the server/tool pair in several shapes depending on version and
// code path, so this normalizes by reconstructing the flattened identifier the
// way Codex's own flat_tool_name does (namespace concatenated with name, no
// separator inserted), then trimming any trailing separator the namespace may
// carry. All of these canonical-fetch forms resolve to "mcp__fetch__fetch" and
// are accepted:
//   - flattened name, no namespace:        name="mcp__fetch__fetch"
//   - namespace with trailing separator:   namespace="mcp__fetch__",  name="fetch"
//   - namespace without trailing separator: namespace="mcp__fetch",   name="fetch"
//
// Anything whose flattened identifier is not exactly "mcp__fetch__fetch" — a
// different tool on the fetch server (mcp__fetch__status), a different server, or
// a non-MCP tool merely named "fetch" with no mcp__ namespace — is rejected.
func isCodexMCPFetch(namespace, name string) bool {
	// flat_tool_name concatenates namespace+name directly; a namespace recorded
	// without its trailing "__" (the format!("mcp__{server}") path) would yield
	// "mcp__fetchfetch", so re-insert the separator before joining when the
	// namespace carries the mcp__ prefix but no trailing separator.
	flat := name
	if namespace != "" {
		ns := namespace
		if strings.HasPrefix(ns, codexMCPPrefix) && !strings.HasSuffix(ns, "__") {
			ns += "__"
		}
		flat = ns + name
	}
	return flat == mcpFetchToolName
}

// codexMCPNamespaceServer extracts the MCP server from a Codex tool namespace.
// Codex builds the callable namespace as format!("mcp__{server}")
// (tool_search.rs), sometimes with a trailing "__" separator — it is a
// server-only wrapper, never a flattened mcp__<server>__<tool>. The server name
// itself may contain "__" (e.g. "codex_apps__calendar"), so the whole remainder
// after the mcp__ prefix (minus any trailing separator) is the server; the tool
// stays the caller's bare ri.Name. (splitMCPName is reserved for the flattened
// ri.Name encoding, the only place mcp__<server>__<tool> is documented.) It
// returns ok=true only for an mcp__-prefixed namespace with a non-empty server,
// so a native (non-MCP) namespace leaves the fields untouched.
func codexMCPNamespaceServer(namespace string) (server string, ok bool) {
	if !strings.HasPrefix(namespace, codexMCPPrefix) {
		return "", false
	}
	server = strings.TrimSuffix(namespace[len(codexMCPPrefix):], "__")
	if server == "" {
		return "", false
	}
	return server, true
}

// codexArgString extracts a top-level string field from a function_call
// arguments JSON string (e.g. "path" for read_file/create_file/edit_file).
func codexArgString(arguments, key string) string {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(trimmed), &m) != nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// codexPatchChange is one file touched by an apply_patch envelope: its path and
// whether the change deletes the file (so the parser can emit file.delete
// rather than file.write, preserving the destructive-vs-creative distinction a
// reviewer needs). A move records a source delete and destination write.
type codexPatchChange = applypatch.Change

// codexApplyPatchChanges extracts the files touched by an apply_patch call from
// its arguments, with each file's change kind. The patch text uses the
// apply_patch envelope:
//
//	*** Begin Patch
//	*** Add File: path/to/new
//	*** Update File: path/to/existing
//	*** Delete File: path/to/old
//	*** Move to: path/to/renamed
//	*** End Patch
//
// The header keys carry the paths; numbat returns them in order so a reviewer
// sees exactly which files a patch changed and how. Returns nil when no path
// header is present (an unrecognized or empty patch).
func codexApplyPatchChanges(arguments string) []codexPatchChange {
	patch := codexArgString(arguments, "patch")
	if patch == "" {
		// Some callers inline the patch as the whole arguments string rather
		// than under a "patch" key; fall back to the raw arguments.
		patch = arguments
	}
	return applypatch.Parse(patch)
}

// codexApplyPatchDiff returns the SHA-256 digest and byte length of an
// apply_patch call's diff text. The patch is taken from the "patch" argument
// (falling back to the raw arguments when a caller inlined it), the same
// resolution codexApplyPatchChanges uses, so the digest covers exactly the diff
// the file events were derived from. The digest is the bare hex SHA-256 (no
// "sha256:" prefix), matching Evidence.SHA256's artifact-hash convention. An
// empty patch yields ("", 0) so the fields stay omitted.
func codexApplyPatchDiff(arguments string) (sha string, n int) {
	patch := codexArgString(arguments, "patch")
	if patch == "" {
		patch = arguments
	}
	return applypatch.Digest(patch)
}

// codexEventID returns a stable, unique identifier for an event derived from a
// rollout record. Codex records carry no per-line uuid (call_id is per tool
// call, not per line and not always present), so the artifact path, 1-based
// line, and per-line event index are hashed. Folding the path in keeps ids
// unique across artifacts; folding the index in keeps them unique when one line
// emits several events (a message plus, in future, multiple blocks).
func codexEventID(path string, line, idx int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, idx))
	return "codex-" + hex.EncodeToString(sum[:8])
}

package hook

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// resolver reads loosely-typed values out of a decoded hook payload with
// per-agent key fallbacks. The agents numbat supports differ only
// slightly in their key spelling (session_id vs sessionId, tool_input vs
// toolInput, ...), so a single resolver with ordered fallbacks covers them
// without a parser each. Every accessor tolerates a missing or wrong-typed
// value and returns a zero result, because the hook command must never fail the
// agent on a malformed payload.
type resolver struct {
	agent   string
	payload map[string]any
	// fields is the action-level object. Windsurf uses tool_info and Antigravity
	// uses toolCall; other agents keep action fields at the top level.
	fields map[string]any
}

// newResolver builds a resolver for an agent's decoded payload, pointing the
// action-field view at the right level while retaining the top-level envelope.
func newResolver(agent string, payload map[string]any) resolver {
	fields := payload
	switch agent {
	case AgentWindsurf:
		if ti, ok := payload["tool_info"].(map[string]any); ok {
			fields = ti
		}
	case AgentAntigravity:
		if call, ok := payload["toolCall"].(map[string]any); ok {
			fields = call
		}
	case AgentCline:
		for _, key := range []string{"preToolUse", "postToolUse", "userPromptSubmit", "taskStart", "taskResume", "taskCancel", "taskComplete"} {
			if event, ok := payload[key].(map[string]any); ok {
				fields = event
				break
			}
		}
	}
	return resolver{agent: agent, payload: payload, fields: fields}
}

// fieldMap returns the action-field view, defaulting to the payload when a
// resolver was constructed without one (zero-value resolver in a direct test).
func (r resolver) fieldMap() map[string]any {
	if r.fields != nil {
		return r.fields
	}
	return r.payload
}

// str returns the first non-empty string value among keys, read from the
// action-field view (which is the payload for flat agents and the nested
// tool_info for Windsurf).
func (r resolver) str(keys ...string) string {
	return firstString(r.fieldMap(), keys...)
}

// envStr returns the first non-empty string among keys read from the top-level
// payload envelope, regardless of where the action fields live. Session and
// working-directory identifiers are always top-level, even for Windsurf.
func (r resolver) envStr(keys ...string) string {
	return firstString(r.payload, keys...)
}

// extraStr reads an event-specific value from Hermes's documented extra
// envelope. Other agents do not use this shape.
func (r resolver) extraStr(keys ...string) string {
	extra, _ := r.payload["extra"].(map[string]any)
	return firstString(extra, keys...)
}

// timestamp returns an upstream observation time when the hook payload carries
// one. The caller supplies a receive time for payloads without a timestamp.
func (r resolver) timestamp() string {
	for _, key := range []string{"timestamp", "time"} {
		if value, ok := r.payload[key].(string); ok {
			return value
		}
		n, ok := intFrom(r.payload, key)
		if !ok {
			continue
		}
		var observed time.Time
		if n >= 100_000_000_000 || n <= -100_000_000_000 {
			observed = time.UnixMilli(n).UTC()
		} else {
			observed = time.Unix(n, 0).UTC()
		}
		if observed.Year() >= 1 && observed.Year() <= 9999 {
			return observed.Format(time.RFC3339Nano)
		}
	}
	return ""
}

func (r resolver) hookEventName() string {
	return r.envStr("hook_event_name", "hookEventName", "hookName", "event_type", "eventType", "event")
}

func (r resolver) toolCallID() string {
	if r.agent == AgentAntigravity {
		if step, ok := intFromAsInt(r.payload, "stepIdx"); ok && step >= 0 {
			return "step:" + strconv.Itoa(step)
		}
	}
	if r.agent == AgentCline {
		for _, key := range []string{"tool_call", "tool_result"} {
			if record, ok := r.payload[key].(map[string]any); ok {
				if id := firstString(record, "id"); id != "" {
					return id
				}
			}
		}
	}
	keys := []string{"tool_use_id", "toolUseId", "tool_call_id", "toolCallId", "call_id", "callId", "callID"}
	if id := firstString(r.fieldMap(), keys...); id != "" {
		return id
	}
	if id := firstString(r.payload, keys...); id != "" {
		return id
	}
	return r.extraStr(keys...)
}

// sessionID resolves the session identifier across agent spellings.
func (r resolver) sessionID() string {
	if r.agent == AgentHermes {
		switch strings.ToLower(r.hookEventName()) {
		case "subagent_start", "subagent_stop":
			// Hermes serializes the parent session into the top-level
			// session_id for delegation hooks and keeps the child's identity
			// in extra.child_session_id. These normalize to the child's
			// session boundary, so prefer the child rather than incorrectly
			// attaching both events to the parent session.
			if id := r.extraStr("child_session_id"); id != "" {
				return id
			}
		}
	}
	if r.agent == AgentOpenClaw {
		if id := r.envStr("session_key", "sessionKey", "target_session_key", "targetSessionKey", "child_session_key", "childSessionKey"); id != "" {
			return id
		}
	}
	if id := r.envStr("session_id", "sessionId", "sessionID", "conversation_id", "conversationId", "trajectory_id", "execution_id", "taskId"); id != "" {
		return id
	}
	if r.agent == AgentHermes {
		return r.extraStr("session_id", "session_key", "parent_session_id", "child_session_id", "task_id")
	}
	return ""
}

// subAgent resolves a named nested agent/subagent identity from lifecycle
// payloads that expose one. Prefer the stable profile/type when present; fall back
// to the opaque id only when no human-meaningful name was reported.
func (r resolver) subAgent() string {
	if v := r.envStr(
		"sub_agent", "subAgent",
		"subagent", "subagent_name", "subagentName",
		"subagent_type", "subagentType",
		"agent_type", "agentType",
		"agent_name", "agentName",
	); v != "" {
		return v
	}
	if r.agent == AgentHermes {
		if v := r.extraStr("child_role", "child_subagent_id", "parent_subagent_id"); v != "" {
			return v
		}
	}
	return r.envStr("agent_id", "agentId", "subagent_id", "subagentId")
}

// cwd resolves the working directory the agent reported, from the envelope.
func (r resolver) cwd() string {
	if r.agent == AgentAntigravity {
		return firstStringInList(r.payload, "workspacePaths")
	}
	if r.agent == AgentVSCode {
		if cwd := r.envStr("cwd", "workingDirectory", "working_directory", "project_dir"); cwd != "" {
			return cwd
		}
		if cwd := firstStringInList(r.payload, "workspace_roots", "workspaceRoots", "workspaceFolders"); cwd != "" {
			return cwd
		}
		return os.Getenv("VSCODE_CWD")
	}
	if r.agent == AgentCline {
		if cwd := r.envStr("cwd", "workingDirectory", "working_directory", "project_dir"); cwd != "" {
			return cwd
		}
		return firstStringInList(r.payload, "workspaceRoots", "workspace_roots")
	}
	if r.agent == AgentCursor {
		if cwd := r.envStr("cwd", "workingDirectory", "working_directory", "project_dir"); cwd != "" {
			return cwd
		}
		return firstStringInList(r.payload, "workspace_roots", "workspaceRoots")
	}
	if r.agent == AgentWindsurf {
		if cwd := r.envStr("cwd", "workingDirectory", "working_directory", "project_dir"); cwd != "" {
			return cwd
		}
		return r.str("cwd", "workingDirectory", "working_directory", "project_dir")
	}
	return r.envStr("cwd", "workingDirectory", "working_directory", "working_dir", "project_dir")
}

// toolName resolves the invoked tool's name. OpenCode's generated plugin forwards
// the tool id under the bare "tool" key (the tool.execute.before/after `input.tool`
// field), so it is included in the fallback set; the snake/camel "tool_name"/
// "toolName" spellings cover every other agent. Reading "tool" here is what lets
// the OpenCode classifier see "bash"/"read"/"webfetch"/... instead of falling
// through to the generic tool vocabulary.
func (r resolver) toolName() string {
	if r.agent == AgentAntigravity {
		return r.str("name")
	}
	return r.str("tool_name", "toolName", "tool")
}

// prompt resolves the submitted user prompt text.
func (r resolver) prompt() string {
	return r.str("prompt", "user_prompt", "userPrompt", "text", "message")
}

// command resolves a shell command string from a payload that carries it at the
// top level (Cursor beforeShellExecution), across observed in-prod spelling
// variants.
func (r resolver) command() string {
	return r.str("command", "commandLine", "command_line")
}

// filePath resolves a file path from a payload that names the file at the top
// level (Cursor beforeReadFile/afterFileEdit), across observed in-prod spelling
// variants.
func (r resolver) filePath() string {
	return r.str("file_path", "filePath", "path")
}

// attachmentPaths resolves the file paths of a prompt's attachments (Cursor
// beforeSubmitPrompt attachments[].file_path), returning them in order. A
// missing or malformed list yields nil so the prompt preview is unchanged.
func (r resolver) attachmentPaths() []string {
	raw, found := r.fieldMap()["attachments"]
	if !found {
		return nil
	}
	list, isList := raw.([]any)
	if !isList {
		return nil
	}
	var paths []string
	for _, item := range list {
		att, isMap := item.(map[string]any)
		if !isMap {
			continue
		}
		if p := firstString(att, "file_path", "filePath", "path"); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// editsDiff summarizes a Cursor afterFileEdit edit list into a diff digest+size.
// Cursor reports edits[].{old_string,new_string} rather than a unified patch, so
// numbat synthesizes a stable patch text by concatenating each edit's old and
// new strings and hashes THAT — mirroring how the Codex extractor digests an
// apply_patch's patch text (model.HashContent + byte length). The digest lets a
// reviewer confirm two edits are byte-identical without the content leaving the
// box; the content itself is never stored. ok is false when no usable edit text
// is present, so numbat never fabricates a digest over an empty edit.
func (r resolver) editsDiff() (sha string, n int, ok bool) {
	return editsDiffFrom(r.fieldMap())
}

// editsDiffFrom is the edits→digest core, parameterized by the map the edit list
// lives in. Cursor carries edits at the top level (r.fieldMap), while Copilot
// nests them inside the JSON-encoded toolArgs object that toolInput() decodes; both
// reuse this same no-fabrication digest by passing the right source map.
func editsDiffFrom(src map[string]any) (sha string, n int, ok bool) {
	raw, found := src["edits"]
	if !found {
		return "", 0, false
	}
	list, isList := raw.([]any)
	if !isList || len(list) == 0 {
		return "", 0, false
	}
	var b strings.Builder
	sawText := false
	for _, item := range list {
		edit, isMap := item.(map[string]any)
		if !isMap {
			continue
		}
		old := firstString(edit, "old_string", "oldString", "old")
		neu := firstString(edit, "new_string", "newString", "new")
		// An entry with no old AND no new text contributes nothing — a synthetic
		// patch built from its separators alone would forge a digest over an empty
		// edit. Skip it. A delete-only edit (old present, new empty) is real
		// content and still counts.
		if old == "" && neu == "" {
			continue
		}
		sawText = true
		b.WriteString(old)
		b.WriteByte('\x00')
		b.WriteString(neu)
		b.WriteByte('\n')
	}
	if !sawText {
		return "", 0, false
	}
	patch := b.String()
	return model.HashContent([]byte(patch)), len(patch), true
}

// toolInput resolves the tool's input arguments object. Agents send it under a
// few keys, and some send it as a JSON string that must be decoded.
func (r resolver) toolInput() map[string]any {
	fm := r.fieldMap()
	for _, k := range []string{"tool_input", "toolInput", "tool_args", "toolArgs", "input", "args", "parameters"} {
		switch v := fm[k].(type) {
		case map[string]any:
			return v
		case string:
			if v == "" {
				continue
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v), &parsed); err == nil {
				return parsed
			}
		}
	}
	return nil
}

// copilotToolArgs accepts the snake_case object used by PascalCase hooks and the
// camelCase object/string used by native camelCase hooks.
func (r resolver) copilotToolArgs() map[string]any {
	fm := r.fieldMap()
	for _, k := range []string{"tool_input", "toolInput", "toolArgs", "tool_args"} {
		switch v := fm[k].(type) {
		case map[string]any:
			return v
		case string:
			if v == "" {
				return nil
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v), &parsed); err == nil {
				return parsed
			}
			return nil
		}
	}
	return nil
}

func (r resolver) factoryToolErrored() bool {
	resp, ok := r.fieldMap()["tool_response"].(map[string]any)
	if !ok {
		return false
	}
	if success, ok := resp["success"].(bool); ok && !success {
		return true
	}
	if failed, ok := resp["is_error"].(bool); ok && failed {
		return true
	}
	if status, ok := resp["status"].(string); ok && strings.EqualFold(status, "error") {
		return true
	}
	return firstString(resp, "error", "error_message") != ""
}

func (r resolver) devinToolErrored() bool {
	resp, ok := r.fieldMap()["tool_response"].(map[string]any)
	if !ok {
		return false
	}
	if success, ok := resp["success"].(bool); ok && !success {
		return true
	}
	return firstString(resp, "error") != ""
}

func (r resolver) hermesDurationMs() (int64, bool) {
	extra, _ := r.payload["extra"].(map[string]any)
	return intFrom(extra, "duration_ms")
}

// hermesToolErrored prefers Hermes's documented post_tool_call status and
// error fields. A present success/blocked status is authoritative: result is
// arbitrary tool output and may legitimately contain an "error" member. The
// JSON-result fallback supports older payloads that omitted the status fields.
func (r resolver) hermesToolErrored() bool {
	switch strings.ToLower(r.extraStr("status")) {
	case "error":
		return true
	case "ok", "blocked":
		return false
	}
	if r.extraStr("error_type", "error_message") != "" {
		return true
	}
	raw := r.extraStr("result")
	if raw == "" {
		return false
	}
	var result map[string]any
	if json.Unmarshal([]byte(raw), &result) != nil {
		return false
	}
	if success, ok := result["success"].(bool); ok && !success {
		return true
	}
	return firstString(result, "error", "error_message") != ""
}

// geminiToolInput resolves a Gemini tool's input arguments. Gemini's documented
// payload carries them ONLY under the snake_case tool_input object (BeforeTool /
// AfterTool). Unlike the shared toolInput(), it deliberately does NOT fall back to
// toolInput/tool_args/toolArgs/input/args: Gemini's contract is that command/path/
// url come exclusively from tool_input, so a contradictory payload that also
// carries one of those other keys must not leak a value from the wrong shape. A
// missing or non-object tool_input yields nil so the event degrades to empty value
// fields rather than recovering one from an adjacent key. The string (JSON-encoded)
// form is accepted too, in case a build sends it pre-encoded.
func (r resolver) geminiToolInput() map[string]any {
	switch v := r.fieldMap()["tool_input"].(type) {
	case map[string]any:
		return v
	case string:
		if v == "" {
			return nil
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			return parsed
		}
	}
	return nil
}

func (r resolver) geminiMCPContext() map[string]any {
	ctx, _ := r.payload["mcp_context"].(map[string]any)
	return ctx
}

// geminiToolResponse resolves a Gemini tool's result object. Gemini's documented
// payload carries it ONLY under the snake_case tool_response object. Unlike the
// shared toolResponse(), it deliberately does NOT fall back to toolResponse/
// tool_result/result/response/output: exit/error/duration signals come exclusively
// from tool_response, so a Gemini payload with no tool_response yields nil and the
// downstream accessors report absent rather than recovering a value from an
// adjacent or top-level key.
func (r resolver) geminiToolResponse() map[string]any {
	if m, ok := r.fieldMap()["tool_response"].(map[string]any); ok {
		return m
	}
	return nil
}

// geminiExitCode resolves a process exit code STRICTLY from Gemini's tool_response
// object — never from a top-level key. ok is true only when a real numeric code is
// present, so a clean exit 0 stays distinct from absent.
func (r resolver) geminiExitCode() (int, bool) {
	resp := r.geminiToolResponse()
	for _, k := range []string{"exit_code", "exitCode", "returncode", "code"} {
		if v, ok := intFromAsInt(resp, k); ok {
			return v, true
		}
	}
	return 0, false
}

// geminiDurationMs resolves a wall-clock duration STRICTLY from Gemini's
// tool_response object — never from a top-level key.
func (r resolver) geminiDurationMs() (int64, bool) {
	resp := r.geminiToolResponse()
	for _, k := range []string{"duration_ms", "durationMs", "elapsed_ms"} {
		if v, ok := intFrom(resp, k); ok {
			return v, true
		}
	}
	return 0, false
}

// geminiDiff resolves a file-edit diff's digest and byte size STRICTLY from
// Gemini's tool_response object — never from a top-level key. numbat never
// fabricates a digest; an absent diff yields ok=false.
func (r resolver) geminiDiff() (sha string, n int, ok bool) {
	resp := r.geminiToolResponse()
	sha = firstString(resp, "diff_sha256", "diffSha256")
	if v, found := intFromAsInt(resp, "diff_bytes"); found {
		n = v
	}
	return normalizedDiff(sha, n)
}

// geminiToolErrored reports whether a Gemini post-tool payload marks the
// invocation as failed, reading STRICTLY from the tool_response object — never from
// a top-level error/is_error/status key. It is explicit-only: stderr text or a
// non-zero exit code alone never sets it, so an error is never fabricated from
// incidental signal or recovered from an adjacent top-level shape. A Gemini payload
// with no tool_response is never errored.
func (r resolver) geminiToolErrored() bool {
	resp := r.geminiToolResponse()
	if resp == nil {
		return false
	}
	if b, ok := resp["is_error"].(bool); ok && b {
		return true
	}
	if s, ok := resp["status"].(string); ok && strings.EqualFold(s, "error") {
		return true
	}
	return firstString(resp, "error", "error_message") != ""
}

// openCodeToolInput resolves an OpenCode tool's input arguments. numbat's
// generated plugin forwards OpenCode's `output.args` object verbatim under the
// "args" key (the SDK shape tool.execute.before/after expose), so that is the
// primary source. Unlike the shared toolInput(), it reads "args" FIRST and keeps
// only the documented snake_case/camelCase envelope fallbacks (tool_input/input)
// as defensive aliases — it deliberately does NOT fall back to tool_args/toolArgs,
// which are other agents' JSON-string shapes, so a contradictory payload never
// leaks a value from the wrong agent's key. The object form is canonical; a
// JSON-encoded string form is accepted too, in case a build forwards it encoded. A
// missing or malformed args yields nil so the event degrades to empty value fields
// rather than fabricating one.
func (r resolver) openCodeToolInput() map[string]any {
	fm := r.fieldMap()
	for _, k := range []string{"args", "tool_input", "input"} {
		switch v := fm[k].(type) {
		case map[string]any:
			return v
		case string:
			if v == "" {
				continue
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v), &parsed); err == nil {
				return parsed
			}
		}
	}
	return nil
}

// openCodeToolMetadata resolves an OpenCode post-tool result's STRUCTURED metadata
// object. OpenCode's tool.execute.after hands the plugin an ExecuteResult
// `{ title, output: string, metadata: M }`; numbat's generated plugin forwards
// `output.metadata` verbatim under the top-level "metadata" key, while the
// "output" key is a compact stdout/stderr STRING (not a map). So the structured
// post-tool signals (the bash tool's `exitCode`, etc.) live ONLY under "metadata".
//
// Unlike the shared toolResponse(), this reads STRICTLY "metadata" and does NOT
// fall back to tool_response/tool_result/result/response/output — those are other
// agents' shapes, and "output" in particular is a STRING here that a map assertion
// would silently drop. A missing or non-object metadata yields nil so the
// downstream accessors report absent rather than recovering a value from the wrong
// key.
func (r resolver) openCodeToolMetadata() map[string]any {
	if m, ok := r.fieldMap()["metadata"].(map[string]any); ok {
		return m
	}
	return nil
}

// openCodeExitCode resolves a process exit code STRICTLY from OpenCode's post-tool
// metadata object, key "exitCode" — the artifact-backed camelCase field the bash
// tool reports (core/src/tool/bash.ts metadata `{ command, cwd, exitCode, ... }`).
// "exit_code" is accepted only as a defensive snake alias. It never reads a
// top-level key or the "output" string. ok is true only when a real
// numeric code is present, so a clean exit 0 stays distinct from absent and is
// never fabricated.
func (r resolver) openCodeExitCode() (int, bool) {
	md := r.openCodeToolMetadata()
	for _, k := range []string{"exitCode", "exit_code"} {
		if v, ok := intFromAsInt(md, k); ok {
			return v, true
		}
	}
	return 0, false
}

// toolResponse resolves the tool's response/result object, used to read exit
// codes, durations, and error markers from a post-tool payload.
func (r resolver) toolResponse() map[string]any {
	fm := r.fieldMap()
	for _, k := range []string{"tool_response", "toolResponse", "tool_result", "toolResult", "result", "response", "output"} {
		if m, ok := fm[k].(map[string]any); ok {
			return m
		}
	}
	return nil
}

// cursorToolOutput decodes Cursor's documented postToolUse tool_output field.
// Cursor sends a JSON-encoded string rather than raw terminal text. The object
// form is accepted defensively, but arbitrary strings and arrays are not
// interpreted as structured status.
func (r resolver) cursorToolOutput() map[string]any {
	switch value := r.fieldMap()["tool_output"].(type) {
	case map[string]any:
		return value
	case string:
		if value == "" {
			return nil
		}
		var output map[string]any
		if err := json.Unmarshal([]byte(value), &output); err == nil {
			return output
		}
	}
	return nil
}

// cursorExitCode resolves only explicit process status from the structured
// tool_output object. The generic contract does not guarantee an inner shape,
// so unknown outputs remain absent rather than being guessed from text.
func (r resolver) cursorExitCode() (int, bool) {
	output := r.cursorToolOutput()
	for _, key := range []string{"exitCode", "exit_code", "returncode", "code"} {
		if value, ok := intFromAsInt(output, key); ok {
			return value, true
		}
	}
	return 0, false
}

// cursorDurationMs reads the documented top-level duration (milliseconds),
// with structured-output aliases retained for older payloads.
func (r resolver) cursorDurationMs() (int64, bool) {
	if value, ok := intFrom(r.fieldMap(), "duration"); ok {
		return value, true
	}
	output := r.cursorToolOutput()
	for _, key := range []string{"duration", "duration_ms", "durationMs", "elapsed_ms"} {
		if value, ok := intFrom(output, key); ok {
			return value, true
		}
	}
	return 0, false
}

func (r resolver) cursorFailureType() string {
	return r.str("failure_type", "failureType")
}

// cursorToolErrored uses only Cursor's explicit failure fields and structured
// tool-output status. postToolUseFailure is also passed as failed=true by the
// mapper, so even a malformed failure payload still retains the error signal.
func (r resolver) cursorToolErrored() bool {
	if r.cursorFailureType() != "" || r.str("error_message", "errorMessage") != "" {
		return true
	}
	output := r.cursorToolOutput()
	if output == nil {
		return false
	}
	if success, ok := output["success"].(bool); ok && !success {
		return true
	}
	for _, key := range []string{"isError", "is_error"} {
		if failed, ok := output[key].(bool); ok && failed {
			return true
		}
	}
	if strings.EqualFold(firstString(output, "status"), "error") {
		return true
	}
	return firstString(output, "error", "error_message", "errorMessage") != ""
}

// decision resolves a permission outcome, normalizing the various spellings an
// agent may use into numbat's DecisionAllowed/DecisionDenied/DecisionAsked. An
// unrecognized or absent value yields DecisionUnknown so the caller treats it as
// an open request.
func (r resolver) decision() string {
	raw := strings.ToLower(r.str("decision", "permission_decision", "permissionDecision", "behavior"))
	switch raw {
	case "allow", "allowed", "approve", "approved", "accept", "accepted":
		return model.DecisionAllowed
	case "deny", "denied", "block", "blocked", "reject", "rejected":
		return model.DecisionDenied
	case "ask", "asked", "requested", "prompt":
		return model.DecisionAsked
	default:
		return ""
	}
}

// exitCode resolves a process exit code from the tool response, returning ok
// only when a real numeric code is present (so a clean exit 0 stays distinct
// from absent).
func (r resolver) exitCode() (int, bool) {
	resp := r.toolResponse()
	for _, k := range []string{"exit_code", "exitCode", "returncode", "code"} {
		if v, ok := intFromAsInt(resp, k); ok {
			return v, true
		}
		if v, ok := intFromAsInt(r.fieldMap(), k); ok {
			return v, true
		}
	}
	return 0, false
}

// durationMs resolves a wall-clock duration in milliseconds if the payload
// carries one.
func (r resolver) durationMs() (int64, bool) {
	resp := r.toolResponse()
	for _, k := range []string{"duration_ms", "durationMs", "executionTimeMs", "elapsed_ms"} {
		if v, ok := intFrom(resp, k); ok {
			return v, true
		}
		if v, ok := intFrom(r.fieldMap(), k); ok {
			return v, true
		}
	}
	return 0, false
}

// diff resolves a file-edit diff's digest and byte size when the payload
// carries them directly. A hook payload rarely includes the raw diff; when it
// does not, ok is false and no diff fields are set — numbat never fabricates a
// digest.
func (r resolver) diff() (sha string, n int, ok bool) {
	resp := r.toolResponse()
	sha = firstString(resp, "diff_sha256", "diffSha256")
	if sha == "" {
		sha = firstString(r.fieldMap(), "diff_sha256", "diffSha256")
	}
	if v, found := intFromAsInt(resp, "diff_bytes"); found {
		n = v
	} else if v, found := intFromAsInt(r.fieldMap(), "diff_bytes"); found {
		n = v
	}
	return normalizedDiff(sha, n)
}

func normalizedDiff(sha string, n int) (string, int, bool) {
	sha = normalizeSHA256Hex(sha)
	if n < 0 {
		n = 0
	}
	if sha == "" && n == 0 {
		return "", 0, false
	}
	return sha, n, true
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

// toolErrored reports whether a post-tool payload marks the invocation as
// failed, via an explicit error field or an is_error/status flag. It is
// explicit-only: stderr text or a non-zero exit code alone never sets it (a clean
// command may write to stderr), so an error is never fabricated from incidental
// signal — only from a field the agent set to mark failure.
func (r resolver) toolErrored() bool {
	if r.str("error", "errorMessage", "error_message") != "" {
		return true
	}
	resp := r.toolResponse()
	if resp != nil {
		if success, ok := resp["success"].(bool); ok && !success {
			return true
		}
		if b, ok := resp["is_error"].(bool); ok && b {
			return true
		}
		if s, ok := resp["status"].(string); ok && strings.EqualFold(s, "error") {
			return true
		}
		if errStr := firstString(resp, "error", "error_message"); errStr != "" {
			return true
		}
	}
	if b, ok := r.fieldMap()["is_error"].(bool); ok && b {
		return true
	}
	if success, ok := r.fieldMap()["success"].(bool); ok && !success {
		return true
	}
	// Windsurf reports action fields FLAT under tool_info, so an explicit
	// status:"error" lands on the field map, not the nested response map above.
	// Match the same "error" vocab used for the nested status — explicit only.
	if strings.EqualFold(r.str("status"), "error") {
		return true
	}
	return false
}

// firstString returns the first non-empty string value among keys in m,
// coercing simple scalar values (numbers, bools) to their string form so a
// numeric file path or flag is not silently dropped.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch s := v.(type) {
		case string:
			if s != "" {
				return s
			}
		case json.Number:
			return s.String()
		case float64:
			return strconv.FormatFloat(s, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(s)
		}
	}
	return ""
}

func firstStringInList(m map[string]any, keys ...string) string {
	for _, k := range keys {
		raw, ok := m[k]
		if !ok {
			continue
		}
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			continue
		}
		if s, ok := list[0].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// maxInt64AsFloat is float64(1<<63) == 2^63, exactly representable. It is one
// past math.MaxInt64, so a float64 integer is in int64 range iff it is strictly
// less than this. Comparing against float64(math.MaxInt64) is WRONG: that
// constant rounds UP to 2^63, so 2^63 would pass the bound and int64(2^63) wraps
// to math.MinInt64 — a fabricated negative.
const maxInt64AsFloat = float64(1 << 63)

// intFrom reads an INTEGER value from m[k] WITHOUT a lossy float64 round-trip
// for the integer-bearing shapes. json.Number and integer strings are parsed
// with integer APIs first, so a faithful 64-bit integer (e.g. math.MaxInt64)
// is preserved exactly rather than collapsing to a wrapped negative. A genuine
// JSON float (decoded as float64) is accepted only when mathematically integral
// and strictly inside the int64 range; a fractional value (exit_code:1.7) or an
// out-of-range value yields ok=false so the field stays absent rather than being
// truncated or wrapped into fabricated integer evidence.
func intFrom(m map[string]any, k string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[k].(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case int32:
		return int64(v), true
	case json.Number:
		// Faithful integer first; only a genuinely non-integral number is rejected.
		// Do NOT fall back to Float64()+truncate (that fabricates/wraps).
		if n, err := v.Int64(); err == nil {
			return n, true
		}
		return 0, false
	case string:
		// A faithful base-10 int64; a fractional or out-of-range string is not a
		// faithful integer, so reject rather than ParseFloat-then-truncate.
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n, true
		}
		return 0, false
	case float64:
		if v != math.Trunc(v) || math.IsInf(v, 0) || v < -maxInt64AsFloat || v >= maxInt64AsFloat {
			return 0, false
		}
		return int64(v), true
	default:
		return 0, false
	}
}

// intFromAsInt is intFrom narrowed to the platform int the model.Event fields
// (ExitCode *int, DiffBytes int) carry. It exists because a bare int(v) of an
// int64 truncates on a 32-bit build (where int is 32-bit), reintroducing the
// fabrication this package forbids. So the narrowing is CHECKED: a value that
// does not fit in int yields ok=false, leaving the field absent rather than a
// wrapped value — consistent with "absent/invalid -> never fabricated". On a
// 64-bit build int is int64 and the guard is a no-op.
func intFromAsInt(m map[string]any, k string) (int, bool) {
	v, ok := intFrom(m, k)
	if !ok || v < math.MinInt || v > math.MaxInt {
		return 0, false
	}
	return int(v), true
}

package extract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// artifactCopilotEvents is the Evidence.ArtifactType for GitHub Copilot CLI's
// at-rest per-session event log (~/.copilot/session-state/<session-id>/events.jsonl).
const artifactCopilotEvents = "copilot_events"

// CopilotExtractor parses the per-session events.jsonl files under
// ~/.copilot/session-state. Copilot's SQLite session index is deferred because
// the JSONL files contain the event stream numbat needs. The parser accepts only
// observed structured fields; it never infers status or exit codes from prose.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value.
type CopilotExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (CopilotExtractor) Agent() string { return model.AgentCopilot }

// Extract parses a Copilot events.jsonl file. It reads the whole artifact to
// stamp a content hash on every event's evidence, then walks it line by line.
// Malformed or over-long lines are recorded as diagnostics and skipped, so a
// partial or truncated event log still yields the records it can.
func (e CopilotExtractor) Extract(r io.Reader, src Source) (*Result, error) {
	max := e.maxBytes
	if max <= 0 {
		max = defaultMaxArtifactSize
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", src.Path, err)
	}
	if len(data) > max {
		return nil, fmt.Errorf("read %q: exceeds %d bytes", src.Path, max)
	}
	sha := model.HashContent(data)

	res := &Result{}
	st := &copilotState{}
	br := bufio.NewReader(bytes.NewReader(data))
	for line := 1; ; line++ {
		raw, tooLong, err := readLine(br)
		if tooLong {
			res.diag(src.Path, line, "line exceeds size cap; skipped")
			continue
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 {
			e.mapLine(res, src, sha, st, line, raw)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				st.emitSessionEnd(res, sha, src)
				return res, nil
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, err)
		}
	}
}

// copilotState carries the synthetic session lifecycle across lines, mirroring
// the Windsurf/Cursor parsers: a session.start is emitted once (on the first
// record carrying a session id) and a matching session.end at end of stream. It
// also tracks which tool-call ids were a shell command so a later, separately
// framed tool result (a PostToolUse record) is promoted from a generic
// tool.result to a command.result.
type copilotState struct {
	started        bool
	startIdx       int
	sessionID      string
	projectPath    string
	lastTimestamp  string
	lastLine       int
	commandCallIDs map[string]struct{}
}

// noteCommandCall records a shell tool-call id so its later result correlates to
// a command.result.
func (st *copilotState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCallIDs == nil {
		st.commandCallIDs = map[string]struct{}{}
	}
	st.commandCallIDs[id] = struct{}{}
}

// isCommandCall reports whether id was a recorded shell command.exec call.
func (st *copilotState) isCommandCall(id string) bool {
	_, ok := st.commandCallIDs[id]
	return ok
}

// observe emits a session.start on the first record carrying a session id and
// advances the last-observed timestamp/line so the eventual session.end points at
// the close of the artifact. An events file that never names a session still
// parses; it simply carries no synthetic session bracket.
func (st *copilotState) observe(res *Result, e CopilotExtractor, src Source, sha string, line int, entry *copilotEntry) {
	if ts := entry.time(); ts != "" {
		st.lastTimestamp = ts
	}
	st.lastLine = line
	if !st.started {
		sid := entry.sessionID()
		if sid == "" {
			return
		}
		st.sessionID = sid
		st.projectPath = entry.project()
		ev := e.base(src, sha, line, entry, 0)
		ev.EventType = model.EventSessionStart
		ev.EventID = ev.EventID + ".start"
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceHigh
		ev.SessionID = sid
		st.startIdx = len(res.Events)
		st.started = true
		res.Events = append(res.Events, ev)
		return
	}
	// Backfill a project path first revealed by a later record onto the opener.
	if st.projectPath == "" {
		if p := entry.project(); p != "" {
			st.projectPath = p
			res.Events[st.startIdx].ProjectPath = p
		}
	}
}

// emitSessionEnd closes the session at end of stream, mirroring the start's
// identity but stamping the LAST observed timestamp and closing line as its
// provenance. The end carries artifact-level evidence (path/line/hash) with an
// empty pointer, since there is no single closing record to point at.
func (st *copilotState) emitSessionEnd(res *Result, sha string, src Source) {
	if !st.started {
		return
	}
	start := res.Events[st.startIdx]
	ev := start
	ev.EventType = model.EventSessionEnd
	ev.EventID = strings.TrimSuffix(start.EventID, ".start") + ".end"
	if st.lastTimestamp != "" {
		ev.Timestamp = st.lastTimestamp
	}
	ev.Evidence = model.Evidence{
		ArtifactType: artifactCopilotEvents,
		LocalPath:    src.Path,
		Line:         st.lastLine,
		SHA256:       sha,
	}
	res.Events = append(res.Events, ev)
}

// mapLine emits at most one pre- or post-tool moment per source record. A text
// body, when present, precedes that tool event. PreToolUse and PostToolUse arrive
// on separate lines, so call IDs correlate later command results and exit codes
// without buffering.
func (e CopilotExtractor) mapLine(res *Result, src Source, sha string, st *copilotState, line int, raw []byte) {
	var entry copilotEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	st.observe(res, e, src, sha, line, &entry)

	etype, actor, hasMsg := copilotMessageRole(&entry)
	hasTool := entry.hasTool()
	if !hasMsg && !hasTool {
		// A record that is neither a message nor a tool moment carries no forensic
		// signal numbat maps; only a genuinely unknown kind is a diagnostic.
		if !isCopilotBookkeepingKind(entry.kind()) {
			res.diag(src.Path, line, "unhandled record kind")
		}
		return
	}

	block := 0
	if hasMsg {
		e.emitMessage(res, src, sha, line, &entry, &block, etype, actor)
	}
	if hasTool {
		e.emitTool(res, src, sha, st, line, &entry, &block)
	}
}

// emitMessage emits a single message event (prompt.user or message.assistant) for
// a record's text body. A record with no text yields nothing. The JSON pointer is
// the source location of the body ("/content", "/text", "/message", "/prompt");
// the block index advances only when an event is emitted.
func (e CopilotExtractor) emitMessage(res *Result, src Source, sha string, line int, entry *copilotEntry, block *int, etype model.EventType, actor string) {
	text, pointer := entry.text()
	if text == "" {
		return
	}
	ev := e.base(src, sha, line, entry, *block)
	ev.EventType = etype
	ev.Actor = actor
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, text)
	ev.Evidence.JSONPointer = pointer
	res.Events = append(res.Events, ev)
	*block++
}

// emitTool emits one tool event for the record's tool moment. A pre-tool record
// becomes an action event (command.exec, file.read/write/delete,
// network.indicator, or a generic tool.call); a post-tool record becomes a
// result event. A shell pre-tool's call id is noted so its later result
// correlates; a result whose id matches a noted shell call becomes a
// command.result carrying the STRUCTURED exit code, while any other result stays
// a generic tool.result. A structurally-marked failure on a result is tagged
// tool_error. The event carries the tool-argument blob's source pointer (or the
// record root when a result names no args).
func (e CopilotExtractor) emitTool(res *Result, src Source, sha string, st *copilotState, line int, entry *copilotEntry, block *int) {
	post := entry.isPostMoment()
	ev := e.base(src, sha, line, entry, *block)
	ev.Confidence = model.ConfidenceHigh
	ev.ToolCallID = entry.toolCallID()
	if ptr := entry.toolArgsPointer(); ptr != "" {
		ev.Evidence.JSONPointer = ptr
	}

	if post {
		// A result moment. Promote to command.result only when the call id was a
		// recorded shell command; otherwise it is a generic tool.result.
		ev.Actor = model.ActorTool
		if st.isCommandCall(entry.toolCallID()) {
			ev.EventType = model.EventCommandResult
			ev.ExitCode = entry.exitCode()
		} else {
			ev.EventType = model.EventToolResult
		}
		ev.ToolName = entry.toolName()
		if entry.errored() {
			ev.Tags = []string{model.TagToolError}
		}
		res.Events = append(res.Events, ev)
		*block++
		return
	}

	// A pre-tool / invocation moment.
	ev.Actor = model.ActorAssistant
	classifyCopilotTool(&ev, entry.toolName(), entry.args())
	if ev.EventType == model.EventCommandExec {
		st.noteCommandCall(entry.toolCallID())
	}
	res.Events = append(res.Events, ev)
	*block++
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from a record. block is the message/tool index, used to keep
// EventID unique when one record emits several events.
func (e CopilotExtractor) base(src Source, sha string, line int, entry *copilotEntry, block int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       entry.eventID(src.Path, line, block),
		SourceAgent:   model.AgentCopilot,
		SourceType:    model.SourceArtifact,
		Timestamp:     entry.time(),
		ProjectPath:   entry.project(),
		SessionID:     entry.sessionID(),
		Evidence: model.Evidence{
			ArtifactType: artifactCopilotEvents,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

// isCopilotBookkeepingKind reports whether a non-message, non-tool record kind is
// one Copilot uses for session bookkeeping (so it is not flagged as an unhandled
// kind). Copilot fires session/compact lifecycle records numbat does not map.
func isCopilotBookkeepingKind(kind string) bool {
	switch kind {
	case "", "sessionstart", "session_start", "session.start",
		"sessionend", "session_end", "session.end", "agentstop", "agent_stop",
		"precompact", "pre_compact", "postcompact", "post_compact",
		"subagentstart", "subagent_start", "subagentstop", "subagent_stop",
		"system", "tool", "meta", "metadata":
		return true
	default:
		return false
	}
}

// copilotMessageRole resolves whether a record carries a message body and, if so,
// its event type and actor. Copilot names the user turn by a hook-style
// UserPromptSubmitted event as well as the generic user/human role, and the
// assistant turn by an assistant/ai/model role. A tool moment (Pre/PostToolUse)
// is never a message even if it also carries text, so the tool discriminators are
// excluded here and handled by the tool path. The shared Cursor messageRole is
// intentionally not reused: it does not know Copilot's UserPromptSubmitted
// spelling, and widening it would couple two independent agent vocabularies.
func copilotMessageRole(e *copilotEntry) (model.EventType, string, bool) {
	if e.isPreMoment() || e.isPostMoment() {
		return "", "", false
	}
	switch e.kind() {
	case "userpromptsubmitted", "user_prompt_submitted", "userprompt", "user", "human", "prompt":
		return model.EventPromptUser, model.ActorUser, true
	case "assistant", "ai", "model", "assistantmessage", "assistant_message", "agentmessage", "agent_message":
		return model.EventMessageAssistant, model.ActorAssistant, true
	default:
		return "", "", false
	}
}

// classifyCopilotTool maps a Copilot tool invocation onto numbat's normalized
// event vocabulary. The tool-name vocabulary is locked to the EXACT set the live
// Copilot mapper recognizes (internal/hook copilotToolFamily/classifyCopilotTool):
// ShellCommand/run_shell_command/Bash (shell), ReadFile/read_file/Read (read),
// WriteFile/write_file/EditFile/Write/Edit (write), and WebFetch/web_fetch/
// WebSearch (web). Both surfaces are produced by the same Copilot runtime, so the
// at-rest parser deliberately mirrors that verified vocabulary rather than widening
// it with generic aliases: a name OUTSIDE this set MUST fall back to a generic
// tool.call (splitting an mcp__server__tool name when present), never be promoted
// into command.exec/file.*/network.indicator. Promoting an unknown or custom tool
// is exactly the false-positive direction the locked precision rules forbid, so a
// documented false negative (an unrecognized verb staying tool.call) is preferred.
// The argument-field spellings (command/cmd, path/filePath/file_path, url/query)
// likewise match the live mapper. Read content is never stored.
func classifyCopilotTool(ev *model.Event, name string, input map[string]json.RawMessage) {
	ev.ToolName = name
	switch name {
	case "ShellCommand", "run_shell_command", "Bash":
		ev.EventType = model.EventCommandExec
		ev.Command = copilotFirstInputString(input, "command", "cmd")
	case "ReadFile", "read_file", "Read":
		ev.EventType = model.EventFileRead
		ev.FilePath = copilotFirstInputString(input, "path", "filePath", "file_path")
	case "WriteFile", "write_file", "EditFile", "Write", "Edit":
		ev.EventType = model.EventFileWrite
		ev.FilePath = copilotFirstInputString(input, "path", "filePath", "file_path")
	case "WebFetch", "web_fetch", "WebSearch":
		url := copilotFirstInputString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = networkTargetURL(url)
		if url != "" {
			ev.ContentPreview = preview(url)
		} else {
			ev.ContentPreview = preview(copilotFirstInputString(input, "query"))
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
}

// copilotInputString returns the string value of a tool input field, coercing a
// JSON number to its string form so a numeric argument is not silently dropped.
// It returns "" when the field is absent or not a scalar.
func copilotInputString(input map[string]json.RawMessage, key string) string {
	raw, ok := input[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

// copilotFirstInputString returns the first non-empty string among the given
// input keys, in order.
func copilotFirstInputString(input map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := copilotInputString(input, k); s != "" {
			return s
		}
	}
	return ""
}

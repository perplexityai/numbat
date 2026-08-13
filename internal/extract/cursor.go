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

// artifactCursorTranscript is the Evidence.ArtifactType for Cursor agent
// transcripts (~/.cursor/projects/<hash>/agent-transcripts/**/*.jsonl).
const artifactCursorTranscript = "cursor_transcript"

// CursorExtractor parses Cursor's at-rest agent-transcripts JSONL.
//
// This extractor reads JSONL agent transcripts under
// ~/.cursor/projects/<hash>/agent-transcripts/. Subagent threads use the same
// format in a nested directory.
//
// The secondary store — the per-workspace SQLite DB at
// ~/Library/Application Support/Cursor/User/workspaceStorage/<hash>/state.vscdb,
// whose chat data lives as JSON blobs in ItemTable key-value rows — is
// intentionally deferred because its ItemTable chat-blob schema is undocumented
// and unstable across Cursor builds.
//
// This extractor only reads at-rest evidence; Cursor's live hook integration is
// implemented separately in internal/hook.
//
// The schema is read defensively: Cursor's transcript format is undocumented
// and has varied between builds, so each field is resolved across the spelling
// variants observed in practice (see cursorEntry) rather than bound to one rigid
// shape. No field is fabricated — a value absent from the record stays empty.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value.
type CursorExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (CursorExtractor) Agent() string { return model.AgentCursor }

// Extract parses a Cursor agent-transcripts JSONL file. It reads the whole
// artifact to stamp a content hash on every event's evidence, then walks it line
// by line. Malformed or over-long lines are recorded as diagnostics and skipped,
// so a partial or truncated transcript still yields the records it can.
func (e CursorExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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
	st := &cursorState{}
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

// cursorState carries the synthetic session lifecycle across lines, mirroring
// the Claude parser: a session.start is emitted once (on the first record
// carrying a session id) and a matching session.end at end of stream. It also
// tracks which tool-call ids were a shell command so a later, separately-framed
// tool result can be promoted from a generic tool.result to a command.result.
type cursorState struct {
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
func (st *cursorState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCallIDs == nil {
		st.commandCallIDs = map[string]struct{}{}
	}
	st.commandCallIDs[id] = struct{}{}
}

// isCommandCall reports whether id was a recorded shell command.exec call.
func (st *cursorState) isCommandCall(id string) bool {
	_, ok := st.commandCallIDs[id]
	return ok
}

// observe emits a session.start on the first record carrying a session id and
// advances the last-observed timestamp/line so the eventual session.end points
// at the close of the artifact. A transcript that never names a session still
// parses; it simply carries no synthetic session bracket.
func (st *cursorState) observe(res *Result, e CursorExtractor, src Source, sha string, line int, entry *cursorEntry) {
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
func (st *cursorState) emitSessionEnd(res *Result, sha string, src Source) {
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
		ArtifactType: artifactCursorTranscript,
		LocalPath:    src.Path,
		Line:         st.lastLine,
		SHA256:       sha,
	}
	res.Events = append(res.Events, ev)
}

// mapLine decodes one record and emits its events in a source-faithful timeline.
//
// A record can carry a message body, tool calls, and tool results, possibly all
// in one content[] body. The emit order is:
//
//  1. top-level toolResult/output results — these close a call from an EARLIER
//     record, so they lead;
//  2. the content[] body walked in SOURCE-BLOCK order (text, calls, results as
//     they appear) — this keeps a same-record call ahead of its result;
//  3. top-level toolCalls/toolCall — issued by this turn, closed by a LATER one.
//
// Before any of that, this record's own shell-call ids are pre-indexed so a
// same-record tool_result correlates to its command.exec (becoming a
// command.result with the structured exit code) regardless of block order. A
// per-record block index keeps every derived EventID unique.
func (e CursorExtractor) mapLine(res *Result, src Source, sha string, st *cursorState, line int, raw []byte) {
	var entry cursorEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	if entry.Content.hasData() && entry.Message.Content.hasData() {
		res.diag(src.Path, line, "multiple content bodies; using top-level content")
	}
	st.observe(res, e, src, sha, line, &entry)
	e.indexCommandCalls(st, &entry)

	etype, actor, ok := messageRole(entry.kind())
	if !ok {
		// "tool"/"system"/empty records carry no standalone message body; their
		// forensic signal is the tool call/result handled below. Only a genuinely
		// unknown kind is a diagnostic.
		if !isKnownCursorRecordKind(entry.kind()) {
			res.diag(src.Path, line, "unhandled record kind")
		}
	}

	block := 0
	// 1. Top-level results that close earlier records' calls.
	for _, to := range entry.topLevelResults() {
		e.emitToolResult(res, src, sha, st, line, &entry, &block, &to)
	}
	// 2. The content[] body in source order. messageEmitted guards the single
	// concatenated message so a multi-text body still emits one event, at the
	// position of its first text block.
	content := entry.content()
	calls := content.ToolCalls
	results := content.ToolResults
	ci, ri := 0, 0
	messageEmitted := false
	for _, kind := range content.Order {
		switch kind {
		case cursorBlockText:
			if !messageEmitted && ok {
				e.emitMessage(res, src, sha, line, &entry, &block, etype, actor)
			}
			messageEmitted = true
		case cursorBlockCall:
			if ci < len(calls) {
				e.emitToolCall(res, src, sha, line, &entry, &block, &calls[ci])
				ci++
			}
		case cursorBlockResult:
			if ri < len(results) {
				e.emitToolResult(res, src, sha, st, line, &entry, &block, &results[ri])
				ri++
			}
		}
	}
	// A plain-string content body (or a flat "text" field) has no Order, so emit
	// its message here.
	if !messageEmitted && ok {
		e.emitMessage(res, src, sha, line, &entry, &block, etype, actor)
	}
	// 3. Top-level calls issued by this turn.
	for _, tc := range entry.topLevelCalls() {
		e.emitToolCall(res, src, sha, line, &entry, &block, &tc)
	}
}

// messageRole maps a record kind to the message event type and actor it emits,
// reporting ok=false for kinds that carry no standalone message body.
func messageRole(kind string) (model.EventType, string, bool) {
	switch kind {
	case "user", "human":
		return model.EventPromptUser, model.ActorUser, true
	case "assistant", "ai", "model":
		// Cursor transcripts carry the model's prose, not a separate reasoning
		// channel, so assistant text is forensic message content (high confidence),
		// not gated with model reasoning because this is an agent-generated note.
		return model.EventMessageAssistant, model.ActorAssistant, true
	default:
		return "", "", false
	}
}

// isKnownCursorRecordKind reports whether a non-message record kind is known
// bookkeeping that should not produce a standalone event or diagnostic.
func isKnownCursorRecordKind(kind string) bool {
	return kind == "turn_ended" || isToolBearingKind(kind)
}

// isToolBearingKind reports whether a non-message record kind is one Cursor or
// Windsurf uses for tool/system bookkeeping.
func isToolBearingKind(kind string) bool {
	switch kind {
	case "tool", "tool_result", "tool_call", "system", "":
		return true
	default:
		return false
	}
}

// indexCommandCalls records the shell/command call ids this record carries so a
// result — whether framed in the same record or a later one — correlates to a
// command.result. It runs before result mapping; emitToolCall therefore does not
// re-note ids, keeping a single source of truth for the command-call set.
func (e CursorExtractor) indexCommandCalls(st *cursorState, entry *cursorEntry) {
	for _, tc := range entry.toolCalls() {
		name := tc.name()
		if name == "" {
			continue
		}
		var probe model.Event
		classifyCursorTool(&probe, name, tc.input())
		if probe.EventType == model.EventCommandExec {
			st.noteCommandCall(tc.callID())
		}
	}
}

// emitMessage emits a single message event (prompt.user or message.assistant) for
// a record's text body. A record with no text (an attachment- or tool-only turn)
// yields nothing. The JSON pointer is the source location of the body
// ("/content", "/content/<i>", or "/text"); the block index advances only when an
// event is emitted.
func (e CursorExtractor) emitMessage(res *Result, src Source, sha string, line int, entry *cursorEntry, block *int, etype model.EventType, actor string) {
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

// emitToolCall emits one tool-invocation event, carrying the call's source
// pointer (set during normalization). Command-call ids were already noted by
// indexCommandCalls so results correlate.
func (e CursorExtractor) emitToolCall(res *Result, src Source, sha string, line int, entry *cursorEntry, block *int, tc *cursorToolCall) {
	name := tc.name()
	if name == "" {
		return
	}
	ev := e.base(src, sha, line, entry, *block)
	ev.Actor = model.ActorAssistant
	ev.Confidence = model.ConfidenceHigh
	ev.ToolCallID = tc.callID()
	ev.Evidence.JSONPointer = entry.contentPointer(tc.Pointer)
	classifyCursorTool(&ev, name, tc.input())
	res.Events = append(res.Events, ev)
	*block++
}

// emitToolResult emits one tool-result event. A result correlated by id to a
// shell command.exec (from this record, pre-indexed, or an earlier one) becomes a
// command.result carrying the structured exit code when present; any other result
// stays a generic tool.result. A structurally-marked failure is tagged
// tool_error. The event carries the result's source pointer.
func (e CursorExtractor) emitToolResult(res *Result, src Source, sha string, st *cursorState, line int, entry *cursorEntry, block *int, to *cursorToolOut) {
	ev := e.base(src, sha, line, entry, *block)
	ev.Actor = model.ActorTool
	ev.Confidence = model.ConfidenceHigh
	ev.ToolCallID = to.callID()
	ev.Evidence.JSONPointer = entry.contentPointer(to.Pointer)
	if st.isCommandCall(to.callID()) {
		ev.EventType = model.EventCommandResult
		ev.ExitCode = to.exitCode()
	} else {
		ev.EventType = model.EventToolResult
	}
	if to.errored() {
		ev.Tags = []string{model.TagToolError}
	}
	res.Events = append(res.Events, ev)
	*block++
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from a record. block is the tool/content index, used to keep
// EventID unique when one record emits several events.
func (e CursorExtractor) base(src Source, sha string, line int, entry *cursorEntry, block int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       entry.eventID(src.Path, line, block),
		SourceAgent:   model.AgentCursor,
		SourceType:    model.SourceArtifact,
		Timestamp:     entry.time(),
		ProjectPath:   entry.project(),
		SessionID:     entry.sessionID(),
		Evidence: model.Evidence{
			ArtifactType: artifactCursorTranscript,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

// classifyCursorTool maps a Cursor tool invocation onto the normalized event
// vocabulary, pulling command and file-path fields from the tool's input across
// the spellings Cursor uses. Cursor's built-in tools (Shell, Read, Edit, ...)
// are matched case-insensitively; an MCP tool flattened as mcp__<server>__<tool>
// is split into the typed server/tool fields and the canonical fetch server is
// surfaced as network egress, mirroring the Claude classifier. An unknown tool
// falls back to a generic tool.call so coverage never silently drops a call.
func classifyCursorTool(ev *model.Event, name string, input map[string]json.RawMessage) {
	ev.ToolName = name
	switch strings.ToLower(name) {
	case "shell", "run_terminal_cmd", "terminal", "bash", "runcommand":
		ev.EventType = model.EventCommandExec
		ev.Command = cursorFirstInputString(input, "command", "commandLine", "command_line", "cmd")
	case "read", "read_file", "readfile":
		ev.EventType = model.EventFileRead
		ev.FilePath = cursorFirstInputString(input, "file_path", "filePath", "path", "target_file")
	case "write", "write_file", "create_file", "createfile":
		ev.EventType = model.EventFileWrite
		ev.FilePath = cursorFirstInputString(input, "file_path", "filePath", "path", "target_file")
	case "edit", "edit_file", "editfile", "search_replace", "apply_patch", "multiedit":
		ev.EventType = model.EventFileWrite
		ev.FilePath = cursorFirstInputString(input, "file_path", "filePath", "path", "target_file")
	case "delete", "delete_file", "deletefile":
		ev.EventType = model.EventFileDelete
		ev.FilePath = cursorFirstInputString(input, "file_path", "filePath", "path", "target_file")
	case "web_search", "websearch", "search_web":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(cursorFirstInputString(input, "query", "search_term", "q"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "web_fetch", "webfetch", "fetch", "fetch_url", "read_url":
		url := cursorFirstInputString(input, "url", "uri", "link")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = networkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case mcpFetchToolName:
		url := cursorFirstInputString(input, "url", "uri", "link")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = networkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		ev.MCPServer, ev.MCPTool = "fetch", "fetch"
	default:
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
}

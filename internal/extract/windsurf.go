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

// artifactWindsurfTranscript is the Evidence.ArtifactType for Windsurf (Cascade)
// at-rest transcripts (~/.windsurf/transcripts/<trajectory_id>.jsonl).
const artifactWindsurfTranscript = "windsurf_transcript"

// WindsurfExtractor parses one JSONL transcript per Cascade trajectory under
// ~/.windsurf/transcripts. The format is not documented as a stable API, so the
// parser accepts only observed structured fields and leaves absent values empty.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value.
type WindsurfExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (WindsurfExtractor) Agent() string { return model.AgentWindsurf }

// Extract parses a Windsurf transcripts JSONL file. It reads the whole artifact
// to stamp a content hash on every event's evidence, then walks it line by line.
// Malformed or over-long lines are recorded as diagnostics and skipped, so a
// partial or truncated transcript still yields the records it can.
func (e WindsurfExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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
	st := &windsurfState{}
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

// windsurfState carries the synthetic session lifecycle across lines, mirroring
// the Cursor/Claude parsers: a session.start is emitted once (on the first record
// carrying a session id) and a matching session.end at end of stream. It also
// tracks which tool-call ids were a shell command so a later, separately-framed
// tool result can be promoted from a generic tool.result to a command.result.
type windsurfState struct {
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
func (st *windsurfState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCallIDs == nil {
		st.commandCallIDs = map[string]struct{}{}
	}
	st.commandCallIDs[id] = struct{}{}
}

// isCommandCall reports whether id was a recorded shell command.exec call.
func (st *windsurfState) isCommandCall(id string) bool {
	_, ok := st.commandCallIDs[id]
	return ok
}

// observe emits a session.start on the first record carrying a session id and
// advances the last-observed timestamp/line so the eventual session.end points
// at the close of the artifact. A transcript that never names a session still
// parses; it simply carries no synthetic session bracket.
func (st *windsurfState) observe(res *Result, e WindsurfExtractor, src Source, sha string, line int, entry *windsurfEntry) {
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
func (st *windsurfState) emitSessionEnd(res *Result, sha string, src Source) {
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
		ArtifactType: artifactWindsurfTranscript,
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
//  1. top-level toolResult/output results that close a call from an EARLIER
//     record (their call id is NOT among this record's top-level calls), so they
//     lead;
//  2. the content[] body walked in SOURCE-BLOCK order (text, calls, results as
//     they appear) — this keeps a same-record call ahead of its result;
//  3. top-level toolCalls/toolCall — issued by this turn, closed by a LATER one;
//  4. top-level toolResult/output results that close a top-level call in THIS
//     same record — emitted after step 3 so a command.result never precedes its
//     command.exec on the timeline.
//
// Before any of that, this record's own shell-call ids are pre-indexed so a
// same-record tool_result correlates to its command.exec (becoming a
// command.result with the structured exit code) regardless of block order. A
// per-record block index keeps every derived EventID unique.
func (e WindsurfExtractor) mapLine(res *Result, src Source, sha string, st *windsurfState, line int, raw []byte) {
	var entry windsurfEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	st.observe(res, e, src, sha, line, &entry)
	e.indexCommandCalls(st, &entry)

	etype, actor, ok := messageRole(entry.kind())
	if !ok {
		// "tool"/"system"/empty records carry no standalone message body; their
		// forensic signal is the tool call/result handled below. Only a genuinely
		// unknown kind is a diagnostic.
		if !isToolBearingKind(entry.kind()) {
			res.diag(src.Path, line, "unhandled record kind")
		}
	}

	// Partition top-level results: those closing a top-level call framed in THIS
	// same record must trail their call (step 4); the rest close an earlier
	// record's call and lead (step 1). Without this split a record carrying both
	// a top-level toolCall and its toolResult would emit command.result before
	// command.exec — a false forensic ordering.
	topCalls := entry.topLevelCalls()
	sameRecordCallIDs := make(map[string]struct{}, len(topCalls))
	for _, tc := range topCalls {
		if id := tc.callID(); id != "" {
			sameRecordCallIDs[id] = struct{}{}
		}
	}
	var earlierResults, sameRecordResults []windsurfToolOut
	for _, to := range entry.topLevelResults() {
		if id := to.callID(); id != "" {
			if _, ok := sameRecordCallIDs[id]; ok {
				sameRecordResults = append(sameRecordResults, to)
				continue
			}
		}
		earlierResults = append(earlierResults, to)
	}

	block := 0
	// 1. Top-level results that close earlier records' calls.
	for i := range earlierResults {
		e.emitToolResult(res, src, sha, st, line, &entry, &block, &earlierResults[i])
	}
	// 2. The content[] body in source order. messageEmitted guards the single
	// concatenated message so a multi-text body still emits one event, at the
	// position of its first text block.
	calls := entry.Content.ToolCalls
	results := entry.Content.ToolResults
	ci, ri := 0, 0
	messageEmitted := false
	for _, kind := range entry.Content.Order {
		switch kind {
		case windsurfBlockText:
			if !messageEmitted && ok {
				e.emitMessage(res, src, sha, line, &entry, &block, etype, actor)
			}
			messageEmitted = true
		case windsurfBlockCall:
			if ci < len(calls) {
				e.emitToolCall(res, src, sha, line, &entry, &block, &calls[ci])
				ci++
			}
		case windsurfBlockResult:
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
	for i := range topCalls {
		e.emitToolCall(res, src, sha, line, &entry, &block, &topCalls[i])
	}
	// 4. Top-level results that close a top-level call in this same record, emitted
	// after their command.exec so the timeline stays faithful.
	for i := range sameRecordResults {
		e.emitToolResult(res, src, sha, st, line, &entry, &block, &sameRecordResults[i])
	}
}

// indexCommandCalls records the shell/command call ids this record carries so a
// result — whether framed in the same record or a later one — correlates to a
// command.result. It runs before result mapping; emitToolCall therefore does not
// re-note ids, keeping a single source of truth for the command-call set.
func (e WindsurfExtractor) indexCommandCalls(st *windsurfState, entry *windsurfEntry) {
	for _, tc := range entry.toolCalls() {
		name := tc.name()
		if name == "" {
			continue
		}
		var probe model.Event
		classifyWindsurfTool(&probe, name, tc.input())
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
func (e WindsurfExtractor) emitMessage(res *Result, src Source, sha string, line int, entry *windsurfEntry, block *int, etype model.EventType, actor string) {
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
func (e WindsurfExtractor) emitToolCall(res *Result, src Source, sha string, line int, entry *windsurfEntry, block *int, tc *windsurfToolCall) {
	name := tc.name()
	if name == "" {
		return
	}
	ev := e.base(src, sha, line, entry, *block)
	ev.Actor = model.ActorAssistant
	ev.Confidence = model.ConfidenceHigh
	ev.ToolCallID = tc.callID()
	ev.Evidence.JSONPointer = tc.Pointer
	classifyWindsurfTool(&ev, name, tc.input())
	res.Events = append(res.Events, ev)
	*block++
}

// emitToolResult emits one tool-result event. A result correlated by id to a
// shell command.exec (from this record, pre-indexed, or an earlier one) becomes a
// command.result carrying the structured exit code when present; any other result
// stays a generic tool.result. A structurally-marked failure is tagged
// tool_error. The event carries the result's source pointer.
func (e WindsurfExtractor) emitToolResult(res *Result, src Source, sha string, st *windsurfState, line int, entry *windsurfEntry, block *int, to *windsurfToolOut) {
	ev := e.base(src, sha, line, entry, *block)
	ev.Actor = model.ActorTool
	ev.Confidence = model.ConfidenceHigh
	ev.ToolCallID = to.callID()
	ev.Evidence.JSONPointer = to.Pointer
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
func (e WindsurfExtractor) base(src Source, sha string, line int, entry *windsurfEntry, block int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       entry.eventID(src.Path, line, block),
		SourceAgent:   model.AgentWindsurf,
		SourceType:    model.SourceArtifact,
		Timestamp:     entry.time(),
		ProjectPath:   entry.project(),
		SessionID:     entry.sessionID(),
		Evidence: model.Evidence{
			ArtifactType: artifactWindsurfTranscript,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

// classifyWindsurfTool maps a Windsurf tool invocation onto the normalized event
// vocabulary, pulling command and file-path fields from the tool's input across
// the spellings Windsurf uses. Windsurf's Cascade tools (run_command, read_code,
// write_code, ...) are matched case-insensitively; an MCP tool flattened as
// mcp__<server>__<tool> is split into the typed server/tool fields and the
// canonical fetch server is surfaced as network egress, mirroring the Cursor and
// Claude classifiers. An unknown tool falls back to a generic tool.call so
// coverage never silently drops a call.
func classifyWindsurfTool(ev *model.Event, name string, input map[string]json.RawMessage) {
	ev.ToolName = name
	switch strings.ToLower(name) {
	case "run_command", "runcommand", "run_terminal_cmd", "shell", "terminal", "bash", "command":
		ev.EventType = model.EventCommandExec
		ev.Command = windsurfFirstInputString(input, "command", "commandLine", "command_line", "cmd")
	case "read_code", "readcode", "read", "read_file", "readfile", "view_file", "viewfile":
		ev.EventType = model.EventFileRead
		ev.FilePath = windsurfFirstInputString(input, "file_path", "filePath", "path", "target_file", "absolute_path")
	case "write_code", "writecode", "write", "write_file", "create_file", "createfile", "write_to_file":
		ev.EventType = model.EventFileWrite
		ev.FilePath = windsurfFirstInputString(input, "file_path", "filePath", "path", "target_file", "absolute_path")
	case "edit_code", "editcode", "edit", "edit_file", "editfile", "replace_file_content", "search_replace", "apply_patch", "multiedit":
		ev.EventType = model.EventFileWrite
		ev.FilePath = windsurfFirstInputString(input, "file_path", "filePath", "path", "target_file", "absolute_path")
	case "delete_file", "deletefile", "delete":
		ev.EventType = model.EventFileDelete
		ev.FilePath = windsurfFirstInputString(input, "file_path", "filePath", "path", "target_file", "absolute_path")
	case "search_web", "web_search", "websearch":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(windsurfFirstInputString(input, "query", "search_term", "q"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "read_url_content", "read_url", "web_fetch", "webfetch", "fetch", "fetch_url":
		url := windsurfFirstInputString(input, "url", "uri", "link")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = networkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case mcpFetchToolName:
		url := windsurfFirstInputString(input, "url", "uri", "link")
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

// windsurfInputString returns the string value of a tool input field, coercing a
// JSON number to its string form so a numeric argument is not silently dropped.
// It returns "" when the field is absent or not a scalar.
func windsurfInputString(input map[string]json.RawMessage, key string) string {
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

// windsurfFirstInputString returns the first non-empty string among the given
// input keys, in order.
func windsurfFirstInputString(input map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := windsurfInputString(input, k); s != "" {
			return s
		}
	}
	return ""
}

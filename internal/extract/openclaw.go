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

// OpenClawExtractor parses an OpenClaw CLI session transcript. OpenClaw writes
// one line-delimited JSON object per line under
// ~/.openclaw/agents/<agentId>/sessions/<sessionId>.jsonl. That tree is a
// HARNESS-AGNOSTIC, MULTI-FLAVOR store: OpenClaw embeds several harnesses and
// each writes its own wire format. This extractor mirrors OpenClaw's own reader:
// it detects the flavor of each file from the decoded rows, then routes the whole
// file through the matching flavor extractor. A flavor numbat does not parse is
// reported with a fail-loud diagnostic — never coerced through another flavor's
// path, never silently zeroed. See openclaw_entry.go for the supported-flavor
// matrix and the high-precision boundary (structured signals only).
//
// This extractor covers the JSONL store used by stable OpenClaw releases through
// 2026.7.1. The SQLite/WAL primary store in the 2026.7.2 beta/development line
// is deliberately not opened here; native plugin hooks provide live monitoring
// and enforcement independently.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value (the default cap).
type OpenClawExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (OpenClawExtractor) Agent() string { return model.AgentOpenClaw }

// openClawState is the running session identity carried across lines: the
// session id and working directory seeded from the header line, plus the set of
// tool-call ids that were a command (shell/exec) so a later result correlated by
// id is promoted from tool.result to command.result.
//
// toolEvents counts events that record a TOOL CALL or TOOL RESULT (not prose);
// recognizedRows counts rows that matched a known entry shape and were handled
// (including intentional no-ops like custom_message). The diagnostic logic uses
// the two to distinguish "recognized rows, no tool activity" (a quiet but valid
// transcript) from "unparsed flavor / nothing recognized" (a real coverage gap).
type openClawState struct {
	sessionID        string
	projectPath      string
	currentTimestamp string
	commandCalls     map[string]struct{}
	// codexCodeMode keeps embedded Codex exec polling under one command identity.
	codexCodeMode codexCodeModeTracker
	// failedMCPCallIDs is the set of call_ids whose Codex-flavor mcp_tool_call_end
	// recorded a structured failure BEFORE the matching custom_tool_call_output was
	// emitted. The later output consults this so it still carries the tool-error
	// signal regardless of the order the two layers land in the transcript —
	// mirroring codexState.failedMCPCallIDs.
	failedMCPCallIDs           map[string]struct{}
	codexMetaSeen              bool
	codexExplicitUserMessages  bool
	codexUserPromptExpected    bool
	codexResponsePromptIDs     map[string]struct{}
	pendingCodexResponsePrompt *model.Event
	toolEvents                 int
	recognizedRows             int
}

// noteCommandCall records a tool-call id that was a command (shell/exec) so its
// paired result correlates to a command.result.
func (st *openClawState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCalls == nil {
		st.commandCalls = map[string]struct{}{}
	}
	st.commandCalls[id] = struct{}{}
}

// takeCommandCall consumes the command owner for a tool result.
func (st *openClawState) takeCommandCall(id string) bool {
	_, ok := st.commandCalls[id]
	delete(st.commandCalls, id)
	return ok
}

func (st *openClawState) resetCall(id string) {
	delete(st.commandCalls, id)
	delete(st.failedMCPCallIDs, id)
	st.codexCodeMode.forgetCall(id)
}

// noteFailedMCPCall records a call_id whose mcp_tool_call_end reported a
// structured failure, so a not-yet-emitted custom_tool_call_output for it is
// tagged TagToolError on arrival (mirrors codexState.noteFailedMCPCall).
func (st *openClawState) noteFailedMCPCall(id string) {
	if id == "" {
		return
	}
	if st.failedMCPCallIDs == nil {
		st.failedMCPCallIDs = map[string]struct{}{}
	}
	st.failedMCPCallIDs[id] = struct{}{}
}

// takeFailedMCPCall consumes a deferred MCP failure for a tool result.
func (st *openClawState) takeFailedMCPCall(id string) bool {
	_, ok := st.failedMCPCallIDs[id]
	delete(st.failedMCPCallIDs, id)
	return ok
}

// Extract parses an OpenClaw session transcript. It reads the whole artifact (to
// stamp a content hash on every event's evidence), detects the file's flavor from
// the decoded rows, then walks it line by line through the matching flavor
// extractor. A malformed or over-long line is recorded as a diagnostic and
// skipped — one corrupt line never aborts the whole transcript. A non-empty file
// that yields no tool activity records a DIAGNOSTIC so the coverage gap is
// visible: an unparsed flavor is named explicitly; a parsed-but-quiet transcript
// (header-only, custom/compaction lines, prose only) is reported distinctly. A
// non-nil error is reserved for a failure that prevents reading the artifact.
func (e OpenClawExtractor) Extract(r io.Reader, src Source) (*Result, error) {
	limit := e.maxBytes
	if limit <= 0 {
		limit = defaultMaxArtifactSize
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", src.Path, err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("read %q: exceeds %d bytes", src.Path, limit)
	}
	sha := model.HashContent(data)

	res := &Result{}
	if len(bytes.TrimSpace(data)) == 0 {
		// An empty file is a clean no-op, not a corruption: no events, no
		// diagnostic, matching the other extractors' empty-input contract.
		return res, nil
	}

	flavor := detectOpenClawFlavor(data)

	st := &openClawState{}
	nonBlank, skippedLong := 0, 0
	br := bufio.NewReader(bytes.NewReader(data))
	for line := 1; ; line++ {
		raw, tooLong, rerr := readLine(br)
		if tooLong {
			res.diag(src.Path, line, "line exceeds size cap; skipped")
			skippedLong++
			if errors.Is(rerr, io.EOF) {
				break
			}
			continue
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 {
			nonBlank++
			e.mapLine(res, src, sha, st, flavor, line, raw)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, rerr)
		}
	}

	if flavor == openClawFlavorCodex {
		flushOpenClawCodexResponsePrompt(res, st)
	}
	e.surfaceCoverageGap(res, src, flavor, nonBlank, skippedLong, st)
	return res, nil
}

// surfaceCoverageGap records a diagnostic when a non-empty transcript produced no
// tool activity, naming WHY so a forensic read is never a silent 0/0. The cases
// are distinct: an unparsed flavor (event_msg / unknown) is the most severe — the
// file carried activity numbat could not read; a file of only over-long
// (skipped) lines surfaced nothing decodable; a recognized-but-quiet transcript
// (only headers, custom/compaction lines, or prose) decoded cleanly but held no
// tool call/result.
func (e OpenClawExtractor) surfaceCoverageGap(res *Result, src Source, flavor openClawFlavor, nonBlank, skippedLong int, st *openClawState) {
	if st.toolEvents > 0 {
		return
	}
	switch {
	case flavor == openClawFlavorEventMsg || flavor == openClawFlavorUnknown:
		res.diag(src.Path, 0, fmt.Sprintf("openclaw: flavor %s not parsed; %d line(s), 0 events", flavor, nonBlank))
	case nonBlank == 0 && skippedLong > 0:
		res.diag(src.Path, 0, fmt.Sprintf("openclaw transcript had %d over-long line(s) skipped, 0 decodable lines", skippedLong))
	case st.recognizedRows > 0 && len(res.Events) == 0:
		res.diag(src.Path, 0, fmt.Sprintf("openclaw transcript parsed %d line(s), 0 tool/message events", nonBlank))
	case st.recognizedRows == 0 && nonBlank > 0:
		res.diag(src.Path, 0, fmt.Sprintf("openclaw transcript parsed %d line(s), no recognized entries", nonBlank))
	}
}

// detectOpenClawFlavor sniffs the file's wire format from its decoded rows,
// mirroring OpenClaw's own detect-then-handle reader. It scans the first
// decodable rows for a flavor signal and returns on the first match: a Codex
// outer type (response_item / session_meta / turn_context) ⇒ Codex; an
// event_msg row ⇒ event_msg; a stable native session/message row ⇒ native. A
// file with no recognizable signal in its scanned
// rows is openClawFlavorUnknown (fail-loud). Detection is per-file and content-
// based, never from the filename.
func detectOpenClawFlavor(data []byte) openClawFlavor {
	const scanRows = 64
	br := bufio.NewReader(bytes.NewReader(data))
	seen := 0
	for seen < scanRows {
		raw, tooLong, rerr := readLine(br)
		if !tooLong {
			line := bytes.TrimSpace(raw)
			if len(line) > 0 {
				var probe struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(line, &probe) == nil {
					seen++
					switch probe.Type {
					case openClawTypeResponseItem, openClawTypeSessionMeta, openClawTypeTurnContext:
						return openClawFlavorCodex
					case openClawTypeEventMsg:
						return openClawFlavorEventMsg
					case openClawTypeSession, openClawTypeMessage, openClawTypeCustomMessage,
						openClawTypeCustom, openClawTypeCompaction, openClawTypeBranchSummary,
						openClawTypeThinkingLevelChange, openClawTypeModelChange,
						openClawTypeLabel, openClawTypeSessionInfo, openClawTypeLeaf:
						// type:"session" is the native harness's own header
						// (Codex uses session_meta); it disambiguates a header-only
						// transcript to the native flavor rather than leaving it unknown.
						return openClawFlavorNative
					}
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	return openClawFlavorUnknown
}

// mapLine decodes one transcript line and dispatches it through the file's
// detected flavor. A malformed line is a diagnostic and is skipped; the rest of
// the file still parses. A row whose type does not match the file's flavor is
// surfaced as a diagnostic rather than coerced through the wrong parser.
func (e OpenClawExtractor) mapLine(res *Result, src Source, sha string, st *openClawState, flavor openClawFlavor, line int, raw []byte) {
	switch flavor {
	case openClawFlavorNative:
		e.mapNativeLine(res, src, sha, st, line, raw)
	case openClawFlavorCodex:
		e.mapCodexLine(res, src, sha, st, line, raw)
	case openClawFlavorEventMsg, openClawFlavorUnknown:
		// Recognized-but-unparsed: the whole-file diagnostic in surfaceCoverageGap
		// names the flavor and line count. Per-line decode is intentionally skipped
		// so a row is never coerced through a parser that does not own its shape.
	}
}

// mapNativeLine decodes one native SessionEntry. The forensic signal lives in
// type:"message" entries carrying stable normalized AgentMessages.
func (e OpenClawExtractor) mapNativeLine(res *Result, src Source, sha string, st *openClawState, line int, raw []byte) {
	var entry openClawEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	// Every stable SessionEntry has its own outer ISO timestamp. Clear the
	// per-row value first so a malformed/legacy row never inherits the previous
	// row's timestamp.
	st.currentTimestamp = entry.Timestamp
	switch entry.Type {
	case openClawTypeSession:
		// The session header seeds session identity (id, cwd). It is session-level
		// context, not a tool/message event, so it emits nothing.
		st.recognizedRows++
		if st.sessionID == "" {
			st.sessionID = entry.ID
		}
		if st.projectPath == "" {
			st.projectPath = entry.CWD
		}
	case openClawTypeMessage:
		st.recognizedRows++
		e.mapMessage(res, src, sha, st, line, &entry)
	case openClawTypeCustomMessage:
		// A custom_message is context replay (an extension-injected user-side
		// message), NOT an agent action — its real wire shape is a top-level
		// {type, customType, content, display}, never a nested ContentBlock
		// envelope. numbat recognizes it and intentionally no-ops it: it never
		// fabricates a tool event from it. It IS counted as a recognized row so a
		// file of only custom_message rows does not trip the "nothing recognized"
		// diagnostic.
		st.recognizedRows++
	case openClawTypeCustom, openClawTypeCompaction, openClawTypeBranchSummary,
		openClawTypeThinkingLevelChange, openClawTypeModelChange,
		openClawTypeLabel, openClawTypeSessionInfo, openClawTypeLeaf:
		// custom is extension state (not model context); compaction and
		// branch_summary are derived summaries, not action records. None carries a
		// forensic action signal, so all are an explicit, recognized no-op.
		st.recognizedRows++
	case "":
		res.diag(src.Path, line, "openclaw entry missing type")
	default:
		// A future/unknown entry type within the native flavor. Surface the gap
		// so a new persisted record is visible rather than silently dropped.
		res.diag(src.Path, line, "openclaw entry type is not modeled")
	}
}

// mapMessage maps a type:"message" entry to events by walking its content. A
// STRING content (or a text block) is prose: a user-role prompt becomes
// prompt.user, an assistant-role message becomes message.assistant, and NO
// preview beyond the established prose norm is stored. The forensically material
// blocks are stable toolCall records plus legacy provider-block compatibility
// forms, emitted in block order for a faithful, rule-matchable timeline.
func (e OpenClawExtractor) mapMessage(res *Result, src Source, sha string, st *openClawState, line int, entry *openClawEntry) {
	role := entry.Message.Role
	if role == openClawRoleToolResult {
		e.emitNativeToolResult(res, src, sha, st, line, &entry.Message)
		return
	}
	if role == openClawRoleBash {
		e.emitNativeBashExecution(res, src, sha, st, line, &entry.Message)
		return
	}
	stringContent := entry.Message.ContentIsString
	for i := range entry.Message.Content {
		c := &entry.Message.Content[i]
		switch c.Type {
		case openClawBlockToolCall, openClawBlockToolUseCamel, openClawBlockFunctionCall,
			openClawBlockToolCallSnake, openClawBlockToolUse, openClawBlockFunctionCallSnake:
			e.emitNativeToolCall(res, src, sha, st, line, i, c)
		case openClawBlockToolResult:
			e.emitToolResult(res, src, sha, st, line, i, c)
		case openClawBlockText:
			e.emitText(res, src, sha, st, line, i, role, stringContent, c)
		case openClawBlockThinking:
			if role == openClawRoleAssistant && src.IncludeReasoning && !c.Redacted {
				e.emitThinking(res, src, sha, st, line, i, c)
			}
		default:
			// Image, document, and future block kinds are not activity
			// numbat models yet; ignore quietly to avoid diagnostic noise.
		}
	}
}

func (e OpenClawExtractor) emitThinking(res *Result, src Source, sha string, st *openClawState, line, block int, c *openClawBlock) {
	text := strings.TrimSpace(c.Thinking)
	if text == "" {
		return
	}
	ev := e.base(src, sha, st, line, block)
	ev.EventType = model.EventMessageReasoning
	ev.Actor = model.ActorAssistant
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, text)
	ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d/thinking", block)
	res.appendEvent(st, ev, false)
}

// emitNativeBashExecution maps OpenClaw's stable interactive shell transcript
// record. It is a user-initiated harness command rather than an assistant tool
// call, and it carries its result on the same structured message.
func (e OpenClawExtractor) emitNativeBashExecution(res *Result, src Source, sha string, st *openClawState, line int, m *openClawMessage) {
	if m.Command != "" {
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventCommandExec
		ev.Actor = model.ActorUser
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = "bash"
		ev.Command = m.Command
		ev.Evidence.JSONPointer = "/message/command"
		res.appendEvent(st, ev, true)
	}
	if m.ExitCode != nil || m.Output != "" || m.Cancelled {
		ev := e.base(src, sha, st, line, 1)
		ev.EventType = model.EventCommandResult
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = "bash"
		ev.ExitCode = m.ExitCode
		ev.Evidence.JSONPointer = "/message"
		if m.Cancelled || (m.ExitCode != nil && *m.ExitCode != 0) {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		res.appendEvent(st, ev, true)
	}
}

// emitNativeToolCall maps the normalized AgentMessage toolCall block and the
// provider-specific camel/snake call forms stable OpenClaw preserves. apply_patch
// expands into one requested file event per patch hunk; every other built-in
// uses the narrow verified tool vocabulary.
func (e OpenClawExtractor) emitNativeToolCall(res *Result, src Source, sha string, st *openClawState, line, block int, c *openClawBlock) {
	args, argsField := c.nativeToolArgs()
	callID := c.toolCallID()
	st.resetCall(callID)
	pointer := fmt.Sprintf("/message/content/%d", block)
	if argsField != "" {
		pointer += "/" + argsField
	}
	if c.Name == "apply_patch" {
		e.emitNativeApplyPatch(res, src, sha, st, line, block, c, args, pointer)
		return
	}
	ev := e.base(src, sha, st, line, block)
	ev.Actor = model.ActorAssistant
	ev.Confidence = model.ConfidenceHigh
	ev.ToolName = c.Name
	ev.ToolCallID = callID
	ev.Evidence.JSONPointer = pointer
	if classifyOpenClawTool(&ev, c.Name, args) {
		st.noteCommandCall(callID)
	}
	res.appendEvent(st, ev, true)
}

// emitNativeApplyPatch records an apply_patch call as requested file changes,
// matching the Codex parser's intent semantics. Patch content is summarized by
// hash and byte count and is never copied into ContentPreview.
func (e OpenClawExtractor) emitNativeApplyPatch(res *Result, src Source, sha string, st *openClawState, line, block int, c *openClawBlock, args map[string]json.RawMessage, pointer string) {
	patch := openClawArgString(args, "input")
	changes := codexApplyPatchChanges(patch)
	diffSHA, diffBytes := codexApplyPatchDiff(patch)
	emit := func(change *codexPatchChange, sub int) {
		ev := e.baseSub(src, sha, st, line, block, sub)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceMedium
		ev.ToolName = c.Name
		ev.ToolCallID = c.toolCallID()
		ev.EventType = model.EventFileWrite
		if change != nil {
			ev.FilePath = change.Path
			if change.Delete {
				ev.EventType = model.EventFileDelete
			}
		}
		ev.DiffSHA256 = diffSHA
		ev.DiffBytes = diffBytes
		ev.Tags = []string{codexTagPatchRequested}
		ev.Evidence.JSONPointer = pointer
		res.appendEvent(st, ev, true)
	}
	if len(changes) == 0 {
		emit(nil, 0)
		return
	}
	for i := range changes {
		emit(&changes[i], i)
	}
}

// nativeToolArgs preserves the provider-specific shapes OpenClaw deliberately
// retains in stable transcripts. Anthropic toolUse blocks carry input; the
// normalized toolCall and OpenAI functionCall forms carry arguments. A fallback
// keeps repaired/mixed historical rows usable while the returned field name
// keeps the evidence pointer source-faithful.
func (c *openClawBlock) nativeToolArgs() (map[string]json.RawMessage, string) {
	if c.Type == openClawBlockToolUseCamel || c.Type == openClawBlockToolUse {
		if c.Input != nil {
			return c.Input, "input"
		}
		if c.Arguments != nil {
			return c.Arguments, "arguments"
		}
		return nil, ""
	}
	if c.Arguments != nil {
		return c.Arguments, "arguments"
	}
	if c.Input != nil {
		return c.Input, "input"
	}
	return nil, ""
}

func (c *openClawBlock) toolCallID() string {
	return openClawFirstNonEmpty(
		c.ID,
		c.ToolCallID,
		c.ToolUseIDCamel,
		c.ToolCallIDSnake,
		c.ToolUseID,
		c.CallID,
		c.CallIDSnake,
	)
}

func (c *openClawBlock) toolResultID() string {
	return openClawFirstNonEmpty(
		c.ToolCallID,
		c.ToolUseIDCamel,
		c.ToolCallIDSnake,
		c.ToolUseID,
		c.CallID,
		c.CallIDSnake,
		c.ID,
	)
}

// emitNativeToolResult maps stable role:"toolResult" AgentMessages. Correlation,
// error state, tool name, and (for exec) exit status all come from structured
// fields on the envelope; result prose is deliberately not previewed.
func (e OpenClawExtractor) emitNativeToolResult(res *Result, src Source, sha string, st *openClawState, line int, m *openClawMessage) {
	ev := e.base(src, sha, st, line, 0)
	ev.Actor = model.ActorTool
	ev.Confidence = model.ConfidenceHigh
	ev.ToolCallID = m.ToolCallID
	ev.ToolName = m.ToolName
	ev.Evidence.JSONPointer = "/message"
	if st.takeCommandCall(m.ToolCallID) {
		ev.EventType = model.EventCommandResult
		ev.ExitCode = openClawExitCode(m.Details)
	} else {
		ev.EventType = model.EventToolResult
		if server, tool, ok := splitMCPName(m.ToolName); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if m.isError() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
	res.appendEvent(st, ev, true)
}

// emitText maps a prose text block to a conversation event. A user-role text is
// a human prompt (prompt.user); an assistant-role text is an assistant message;
// a system-role text is attributed to a system actor (NOT the assistant). An
// empty body yields nothing.
//
// The JSON Pointer is source-faithful: when the content was a STRING on disk (the
// block is Synthesized) the pointer is /message/content, the value that actually
// exists in the record; when the content was an array, the pointer indexes the
// real text block at /message/content/<i>/text.
func (e OpenClawExtractor) emitText(res *Result, src Source, sha string, st *openClawState, line, block int, role string, stringContent bool, c *openClawBlock) {
	clean := strings.TrimSpace(c.Text)
	if clean == "" {
		return
	}
	ev := e.base(src, sha, st, line, block)
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, clean)
	if stringContent || c.Synthesized {
		ev.Evidence.JSONPointer = "/message/content"
	} else {
		ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d/text", block)
	}
	switch role {
	case openClawRoleUser:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
	case openClawRoleAssistant:
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
	case openClawRoleSystem:
		// A system-role message is a system instruction, not an assistant turn:
		// attribute it to the system actor so the timeline does not misreport it as
		// the assistant speaking.
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
	default:
		// Stable custom messages carry extension/application context and are
		// replayed to the model as user-side context; they are not an assistant
		// action. Unknown future roles are likewise not guessed into telemetry.
		return
	}
	res.appendEvent(st, ev, false)
}

// emitToolResult maps a legacy provider-style tool_result block to a result event,
// correlated to the tool_use it answers by tool_use_id. A result for a recorded
// command call becomes a command.result; otherwise a tool.result (an MCP-
// qualified name additionally splits into the typed server/tool fields). The
// tool_error tag is set ONLY from the structured is_error boolean — never
// inferred from output prose. This legacy block carries no structured exit
// field, so ExitCode stays nil; stable role:"toolResult" exec messages are
// handled separately and do emit numeric details.exitCode.
func (e OpenClawExtractor) emitToolResult(res *Result, src Source, sha string, st *openClawState, line, block int, c *openClawBlock) {
	ev := e.base(src, sha, st, line, block)
	ev.Actor = model.ActorTool
	ev.Confidence = model.ConfidenceHigh
	resultID := c.toolResultID()
	ev.ToolCallID = resultID
	ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d", block)
	if st.takeCommandCall(resultID) {
		ev.EventType = model.EventCommandResult
	} else {
		ev.EventType = model.EventToolResult
		if server, tool, ok := splitMCPName(c.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if c.isError() {
		// The SOLE tool-error signal: a structured is_error:true. Absent or false →
		// no tag; output prose containing "error" is never scraped.
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
	res.appendEvent(st, ev, true)
}

// appendEvent appends an event, stamping the running session identity so a
// project path / session id is attributed even though only the header line
// carried it. tool reports whether the event records a tool CALL or RESULT (vs
// prose): only tool activity advances toolEvents, so the coverage diagnostic can
// tell a quiet-but-valid transcript from one with no tool signal at all.
func (r *Result) appendEvent(st *openClawState, ev model.Event, tool bool) {
	ev.SessionID = st.sessionID
	ev.ProjectPath = st.projectPath
	if tool {
		st.toolEvents++
	}
	r.Events = append(r.Events, ev)
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from a transcript line. block is the content-block index, used
// to keep EventID unique when one line emits several events. Evidence.Line is
// the 1-based line number (the artifact is line-oriented); the JSON Pointer (set
// by the caller) locates the value within that line's object.
func (e OpenClawExtractor) base(src Source, sha string, st *openClawState, line, block int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       openClawEventID(src.Path, line, block),
		SourceAgent:   model.AgentOpenClaw,
		SourceType:    model.SourceArtifact,
		Timestamp:     st.currentTimestamp,
		Evidence: model.Evidence{
			ArtifactType: artifactOpenClawJSONL,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

// baseSub is the apply_patch multi-event variant of base. A separate sub-index
// keeps IDs unique without changing established IDs for ordinary blocks.
func (e OpenClawExtractor) baseSub(src Source, sha string, st *openClawState, line, block, sub int) model.Event {
	ev := e.base(src, sha, st, line, block)
	ev.EventID = openClawSubEventID(src.Path, line, block, sub)
	return ev
}

// classifyOpenClawTool maps an OpenClaw tool name onto the normalized event
// vocabulary, lifting the forensically salient argument (command, file path,
// fetched URL) out of the tool's well-known input keys. The mapping is
// deliberately NARROW and artifact-backed: only the OpenClaw tool names numbat
// has verified are promoted to a typed event; every other name — plugin tools,
// MCP tools, future built-ins — falls through to a generic tool.call with NO
// alias guessing, so coverage never silently drops a call and an unknown tool is
// never mislabeled. An MCP-qualified name splits into the typed server/tool
// fields. It returns whether the call is a command tool, so a correlated
// tool_result becomes a command.result.
func classifyOpenClawTool(ev *model.Event, name string, input map[string]json.RawMessage) (isCommand bool) {
	switch {
	case inOpenClawToolSet(openClawCommandTools, name):
		if name == "exec" {
			if _, hasCode := input["code"]; hasCode {
				ev.EventType = model.EventToolCall
				return false
			}
			if _, hasLanguage := input["language"]; hasLanguage {
				ev.EventType = model.EventToolCall
				return false
			}
		}
		command := openClawArgString(input, openClawArgCommand)
		if command == "" {
			// A name alone is not enough to claim shell execution. In particular,
			// Code Mode deliberately reuses exec for JavaScript/TypeScript input.
			ev.EventType = model.EventToolCall
			return false
		}
		ev.EventType = model.EventCommandExec
		ev.Command = command
		return true
	case inOpenClawToolSet(openClawReadTools, name):
		ev.EventType = model.EventFileRead
		ev.FilePath = openClawArgFirstString(input, openClawFilePathKeys...)
		return false
	case inOpenClawToolSet(openClawWriteTools, name):
		// File WRITE content is not stored verbatim: the path is captured, the body
		// is not dumped (data minimization, matching the OpenCode/Gemini parsers).
		ev.EventType = model.EventFileWrite
		ev.FilePath = openClawArgFirstString(input, openClawFilePathKeys...)
		return false
	case inOpenClawToolSet(openClawNetworkTools, name):
		// Network egress: the indicator's URL must be a real http(s) target, so a
		// non-http or hostless value (file://, javascript:, data:, a relative path,
		// junk, or a search tool that carries no url) leaves Event.URL empty rather
		// than fabricating a target. The raw URL or search query remains the bounded
		// investigative lead in ContentPreview, matching the other agent parsers.
		if name == "WebSearch" || name == "web_search" {
			ev.EventType = model.EventNetworkIndicator
			ev.ContentPreview = preview(openClawArgString(input, openClawArgQuery))
			ev.Tags = append(ev.Tags, model.TagNetwork)
			return false
		}
		rawURL := openClawArgString(input, openClawArgURL)
		if name == "browser" {
			rawURL = openClawArgFirstString(input, openClawArgTargetURL, openClawArgURL)
			query := openClawArgString(input, openClawArgQuery)
			if rawURL == "" && query == "" {
				// Stable browser also exposes local/non-egress actions such as tabs
				// and screenshot. A browser invocation is not itself proof of a
				// network boundary when it has no target or query.
				ev.EventType = model.EventToolCall
				return false
			}
			if rawURL == "" {
				ev.EventType = model.EventNetworkIndicator
				ev.ContentPreview = preview(query)
				ev.Tags = append(ev.Tags, model.TagNetwork)
				return false
			}
		}
		ev.EventType = model.EventNetworkIndicator
		if httpURL := networkTargetURL(rawURL); httpURL != "" {
			ev.URL = httpURL
		}
		ev.ContentPreview = preview(rawURL)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		return false
	default:
		// Plugin tools, MCP tools, and every other name map to a generic call,
		// preserving coverage without promoting an unknown name to a typed alias. An
		// MCP-qualified name splits into the typed server/tool fields so a rule or
		// SIEM can pivot without re-parsing the flattened name.
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
		return false
	}
}

// inOpenClawToolSet reports whether name is one of the artifact-backed tool names
// in set.
func inOpenClawToolSet(set map[string]struct{}, name string) bool {
	_, ok := set[name]
	return ok
}

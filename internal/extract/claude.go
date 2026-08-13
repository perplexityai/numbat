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

// artifactClaudeJSONL is the Evidence.ArtifactType for Claude Code session
// transcripts (~/.claude/projects/**/*.jsonl).
const artifactClaudeJSONL = "claude_jsonl"

// defaultMaxArtifactSize caps a single artifact so a malformed or hostile file
// cannot exhaust memory. Claude transcripts are line-oriented and rarely large;
// a few hundred MB is far past any real session.
const defaultMaxArtifactSize = 512 * 1024 * 1024

// maxLineSize caps a single JSONL record. Transcript lines can be large (a tool
// result may embed file contents); an over-limit line is skipped with a
// diagnostic rather than aborting the whole artifact.
const maxLineSize = 16 * 1024 * 1024

// ClaudeExtractor parses Claude Code session transcripts. Claude writes one
// JSON object per line; each line is a user, assistant, system, or summary
// record. See https://code.claude.com/docs for the format.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value (the default cap).
//
// sourceAgent and artifactType let a sibling agent whose transcript shares this
// Claude-Code JSONL schema reuse the whole parser while stamping its own
// identity (see CoworkExtractor). Both fall back to the Claude defaults when
// unset, so the zero value remains a Claude Code extractor.
type ClaudeExtractor struct {
	maxBytes     int
	sourceAgent  string
	artifactType string
}

// agent reports the source-agent id this extractor stamps, defaulting to Claude
// Code when unset.
func (e ClaudeExtractor) agent() string {
	if e.sourceAgent != "" {
		return e.sourceAgent
	}
	return model.AgentClaudeCode
}

// artifact reports the Evidence.ArtifactType this extractor stamps, defaulting
// to the Claude transcript type when unset.
func (e ClaudeExtractor) artifact() string {
	if e.artifactType != "" {
		return e.artifactType
	}
	return artifactClaudeJSONL
}

// Agent identifies the events this extractor produces.
func (e ClaudeExtractor) Agent() string { return e.agent() }

// Extract parses a Claude Code JSONL transcript. It reads the whole artifact to
// stamp a content hash on every event's evidence, then walks it line by line.
// Malformed or over-long lines are recorded as diagnostics and skipped.
func (e ClaudeExtractor) Extract(r io.Reader, src Source) (*Result, error) {
	cap := e.maxBytes
	if cap <= 0 {
		cap = defaultMaxArtifactSize
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(cap)+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", src.Path, err)
	}
	if len(data) > cap {
		return nil, fmt.Errorf("read %q: exceeds %d bytes", src.Path, cap)
	}
	sha := model.HashContent(data)

	// The cross-project prompt history shares the agent and the .jsonl
	// extension but not the transcript schema; it is selected by path, like
	// Gemini's logs.json-vs-checkpoint split.
	if isClaudeHistory(src.Path) {
		return e.extractHistory(data, sha, src)
	}

	res := &Result{}
	st := &claudeState{}
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
				st.emitSessionEnd(res, sha, src, e.artifact())
				return res, nil
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, err)
		}
	}
}

// claudeState carries the synthetic session lifecycle across lines: a
// session.start is emitted once (on the first entry carrying a session id) and
// a matching session.end is emitted at end of stream. The start event is kept
// by index into res.Events so header context (model id, which appears only on
// assistant entries) can be backfilled onto the emitted record after the fact.
// lastTimestamp/lastLine track the most recently observed entry so session.end
// is stamped with the close of the artifact rather than reusing the opener's
// timestamp and provenance.
type claudeState struct {
	started         bool
	startIdx        int
	lastTimestamp   string
	lastLine        int
	projectPath     string
	permissionModes map[string]string
	// commandCallIDs is the set of tool_use ids that were a Bash command.exec, so
	// a later tool_result correlated by tool_use_id can be promoted from a generic
	// tool.result to a command.result. A file read or MCP call id never enters the
	// set, so its result is never reclassified.
	commandCallIDs map[string]struct{}
}

// noteCommandCall records a Bash tool_use id so its later result correlates to a
// command.result.
func (st *claudeState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCallIDs == nil {
		st.commandCallIDs = map[string]struct{}{}
	}
	st.commandCallIDs[id] = struct{}{}
}

// isCommandCall reports whether id was a recorded Bash command.exec call.
func (st *claudeState) isCommandCall(id string) bool {
	_, ok := st.commandCallIDs[id]
	return ok
}

func (st *claudeState) permissionModeChanged(pointer, mode string) bool {
	if st.permissionModes == nil {
		st.permissionModes = make(map[string]string, 2)
	}
	if previous, ok := st.permissionModes[pointer]; ok && previous == mode {
		return false
	}
	st.permissionModes[pointer] = mode
	return true
}

// observe emits a session.start on the first entry carrying a session id, then
// backfills onto it any session-context field a later entry first reveals (the
// model id appears only on assistant entries). Every entry advances the
// last-observed timestamp/line so the eventual session.end points at the close
// of the artifact.
func (st *claudeState) observe(res *Result, e ClaudeExtractor, src Source, sha string, line int, entry *claudeEntry) {
	if entry.CWD != "" {
		st.projectPath = entry.CWD
	} else {
		entry.CWD = st.projectPath
	}
	if entry.Timestamp != "" {
		st.lastTimestamp = entry.Timestamp
	}
	st.lastLine = line
	if !st.started {
		if entry.SessionID == "" {
			return
		}
		ev := e.base(src, sha, line, entry, 0)
		ev.EventType = model.EventSessionStart
		// The session.start shares the first entry's identity but is a synthetic,
		// per-session record, so its id carries a ".start" suffix to stay distinct
		// from the activity event the same entry/block also emits.
		ev.EventID = ev.EventID + ".start"
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceHigh
		ev.GitBranch = entry.GitBranch
		ev.CLIVersion = entry.Version
		ev.Model = entry.Message.Model
		st.startIdx = len(res.Events)
		st.started = true
		res.Events = append(res.Events, ev)
		return
	}
	start := &res.Events[st.startIdx]
	if start.GitBranch == "" {
		start.GitBranch = entry.GitBranch
	}
	if start.CLIVersion == "" {
		start.CLIVersion = entry.Version
	}
	if start.Model == "" {
		start.Model = entry.Message.Model
	}
}

// emitSessionEnd closes the session at end of stream. It mirrors the start's
// session identity and backfilled context so a consumer can bound the window,
// but stamps the LAST observed timestamp and closing line as its provenance —
// never the opener's. There is no single honest closing record to point a
// JSONPointer at, so the end carries artifact-level evidence (path/line/hash)
// with an empty pointer rather than reusing the start's pointer.
func (st *claudeState) emitSessionEnd(res *Result, sha string, src Source, artifactType string) {
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
		ArtifactType: artifactType,
		LocalPath:    src.Path,
		Line:         st.lastLine,
		SHA256:       sha,
	}
	res.Events = append(res.Events, ev)
}

// readLine reads one newline-delimited record, bounded by maxLineSize. It
// returns the line without its trailing newline. tooLong is true when the
// record exceeds the cap, in which case the line is drained to the next newline
// and its bytes are discarded. A trailing line without a newline is returned
// with err == io.EOF.
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, e := br.ReadSlice('\n')
		if len(buf)+len(chunk) > maxLineSize {
			tooLong = true
		}
		if !tooLong {
			buf = append(buf, chunk...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if tooLong {
			return nil, true, e
		}
		return buf, false, e
	}
}

// mapLine decodes one record and dispatches by entry type.
func (e ClaudeExtractor) mapLine(res *Result, src Source, sha string, st *claudeState, line int, raw []byte) {
	var entry claudeEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	if entry.Type == "relocated" {
		entry.CWD = entry.RelocatedCWD
	}
	st.observe(res, e, src, sha, line, &entry)
	switch entry.Type {
	case "user":
		e.mapUser(res, src, sha, st, line, &entry)
	case "assistant":
		e.mapAssistant(res, src, sha, st, line, &entry, src.IncludeReasoning)
	case "permission-mode":
		e.mapPermissionMode(res, src, sha, line, st, &entry, entry.PermissionMode, "/permissionMode")
	case "mode":
		// type:"mode" is the other shape Claude Code uses for a permission-mode
		// switch: the new mode rides on "mode" (not "permissionMode") and the line
		// carries no timestamp. Same posture-change signal, same config.agent home.
		e.mapPermissionMode(res, src, sha, line, st, &entry, entry.Mode, "/mode")
	case "pr-link":
		e.mapPRLink(res, src, sha, line, &entry)
	case "agent-name":
		e.mapAgentName(res, src, sha, line, st, &entry)
	case "attachment":
		e.mapAttachment(res, src, sha, line, &entry)
	case "summary", "system", "ai-title", "custom-title", "queue-operation", "relocated",
		"last-prompt", "file-history-snapshot", "file-history-delta", "worktree-state":
		// Metadata and noise, not agent activity: "last-prompt" duplicates the
		// most recent user prompt already captured as a "user" entry (surfacing
		// it would double-count); file-history entries are editor backup
		// bookkeeping, not separate tool-driven file changes;
		// "worktree-state" is git-worktree bookkeeping for Claude Code's worktree
		// feature; title and relocation records describe the transcript itself.
		// Recognizing them keeps diagnostics focused on real coverage gaps.
	default:
		res.diag(src.Path, line, "unhandled entry type")
	}
}

// mapUser handles type:"user" entries: tool output fed back to the model, or a
// human prompt. Claude returns tool output as a user-role entry whose content
// carries one tool_result block per preceding tool call, so each becomes its
// own tool.result event. An entry with no tool_result and no text yields
// nothing (e.g. image-only or meta entries).
func (e ClaudeExtractor) mapUser(res *Result, src Source, sha string, st *claudeState, line int, entry *claudeEntry) {
	emitted := false
	// The exit status and duration live only in the top-level toolUseResult (the
	// per-block tool_result carries content/is_error, not exit_code/durationMs), so
	// decode them once.
	exit := entry.toolUseResultExitCode()
	duration := entry.toolUseResultDurationMs()
	// The single entry-level exit code and duration are attributable to a block
	// only when the entry yields exactly one command.result. If several Bash
	// results share one entry there is no artifact field tying either to any one
	// of them, so stamping them on each would fabricate evidence; in that case
	// every block still becomes command.result but carries no exit code/duration.
	commandBlocks := 0
	for i := range entry.Message.Content {
		c := &entry.Message.Content[i]
		if c.Type == "tool_result" && st.isCommandCall(c.ToolUseID) {
			commandBlocks++
		}
	}
	for i := range entry.Message.Content {
		c := &entry.Message.Content[i]
		if c.Type != "tool_result" {
			continue
		}
		ev := e.base(src, sha, line, entry, i)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolCallID = c.ToolUseID
		ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d", i)
		// A result correlated by tool_use_id to a prior Bash command.exec is a
		// command.result; only then is the exit code attributable to it. A result
		// for a Read/MCP/web call keeps tool.result, so file/MCP output is never
		// reclassified.
		if st.isCommandCall(c.ToolUseID) {
			ev.EventType = model.EventCommandResult
			if commandBlocks == 1 { // see the one-result rationale above
				ev.ExitCode = exit
				ev.DurationMs = duration
			}
		} else {
			ev.EventType = model.EventToolResult
		}
		if c.isError() {
			ev.Tags = []string{model.TagToolError}
		}
		res.Events = append(res.Events, ev)
		emitted = true
	}
	if emitted {
		return
	}

	// Some entries record the result only in the top-level toolUseResult, with an
	// empty content array. With no tool_use_id to correlate, the payload's own
	// shape is the evidence: an exit_code/stdout/stderr body is recognizably a
	// command result, so it is surfaced as command.result; anything else (a file
	// read's structuredPatch, an MCP response) stays tool.result.
	if entry.hasToolUseResult() {
		ev := e.base(src, sha, line, entry, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.Evidence.JSONPointer = "/toolUseResult"
		if entry.toolUseResultIsCommand() {
			ev.EventType = model.EventCommandResult
			ev.ExitCode = exit
			ev.DurationMs = duration
		} else {
			ev.EventType = model.EventToolResult
		}
		if entry.toolUseResultIsError() {
			ev.Tags = []string{model.TagToolError}
		}
		res.Events = append(res.Events, ev)
		return
	}

	text := entry.Message.text()
	if text == "" {
		return
	}
	ev := e.base(src, sha, line, entry, 0)
	ev.EventType = model.EventPromptUser
	ev.Actor = model.ActorUser
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, text)
	ev.Evidence.JSONPointer = "/message/content"
	res.Events = append(res.Events, ev)
}

// mapAssistant handles type:"assistant" entries. One assistant turn may carry
// several content blocks (text plus one or more tool_use calls); each becomes
// its own event, in block order, so the emitted stream is a faithful timeline
// and a tool call is a first-class, rule-matchable record.
func (e ClaudeExtractor) mapAssistant(res *Result, src Source, sha string, st *claudeState, line int, entry *claudeEntry, includeReasoning bool) {
	for i := range entry.Message.Content {
		c := &entry.Message.Content[i]
		switch c.Type {
		case "text":
			s := strings.TrimSpace(c.Text)
			if s == "" {
				continue
			}
			ev := e.base(src, sha, line, entry, i)
			ev.EventType = model.EventMessageAssistant
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceHigh
			setMessageContent(&ev, src, s)
			ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d", i)
			res.Events = append(res.Events, ev)
		case "tool_use":
			ev := e.base(src, sha, line, entry, i)
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceHigh
			ev.ToolCallID = c.ID
			ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d", i)
			classifyTool(&ev, c.Name, c.Input)
			if ev.EventType == model.EventCommandExec {
				st.noteCommandCall(c.ID)
			}
			res.Events = append(res.Events, ev)
		case "thinking":
			// Model reasoning is opt-in: it is not forensic evidence of an
			// action, only context, so it surfaces only when reasoning is requested.
			s := strings.TrimSpace(c.Thinking)
			if !includeReasoning || s == "" {
				continue
			}
			ev := e.base(src, sha, line, entry, i)
			ev.EventType = model.EventMessageReasoning
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceHigh
			setMessageContent(&ev, src, s)
			ev.Evidence.JSONPointer = fmt.Sprintf("/message/content/%d", i)
			res.Events = append(res.Events, ev)
		default:
			// image and any future block types are not activity we model yet;
			// ignore quietly to avoid diagnostic noise.
		}
	}
}

// elevatedPermissionMode reports whether a Claude permission mode reduces the
// interactive approval guardrails. Claude Code's permission docs define six
// modes; this splits them by whether the agent can act without a human in the
// loop:
//
//	elevated (auto-approves or bypasses prompts):
//	  "acceptEdits"       — file edits no longer prompt
//	  "auto"              — auto-approves tool calls (background safety checks)
//	  "bypassPermissions" — no prompts at all
//	not elevated (a human still gates action):
//	  "default"           — prompts on first use of each tool
//	  "plan"              — read-only analysis, no edits/execution
//	  "dontAsk"           — auto-DENIES unless pre-approved (more restrictive
//	                        than default, so it does not widen the agent's reach)
func elevatedPermissionMode(mode string) bool {
	switch mode {
	case "acceptEdits", "auto", "bypassPermissions":
		return true
	default:
		return false
	}
}

// mapPermissionMode handles the permission-mode-switch entries Claude Code
// writes whenever the session's permission mode changes — both type:"permission-
// mode" (value in "permissionMode") and type:"mode" (value in "mode", no
// timestamp). The caller supplies the mode value and the JSON pointer to it. The
// mode governs how much the agent can do without interactive approval, so a
// change is a security-posture event, not noise: it is surfaced as config.agent
// (a change to agent configuration, distinct from a per-request permission
// decision), carrying the new mode as the preview.
//
// This posture change is the ONLY permission signal the transcript persists; the
// permission.requested/approved/denied vocabulary stays reserved. The Claude
// transcript records no per-tool-call approve/deny decision — toolUseResult
// carries only execution data (stdout/stderr/exit_code/is_error/structuredPatch,
// never a decision/behavior field), and the PreToolUse hook's permissionDecision
// is consumed at runtime, not written as a transcript entry. So a per-request
// permission.* event would have to be synthesized, which this forensic parser
// does not do.
//
// A switch into a guardrail-removing mode (acceptEdits/bypassPermissions) is
// additionally tagged so a reviewer can enumerate the unattended-action windows.
// A record with no mode value is skipped rather than emitting an empty event. A
// timestamp-less entry inherits the last observed timestamp so it still lands in
// the timeline.
func (e ClaudeExtractor) mapPermissionMode(res *Result, src Source, sha string, line int, st *claudeState, entry *claudeEntry, value, pointer string) {
	mode := strings.TrimSpace(value)
	if mode == "" {
		return
	}
	if !st.permissionModeChanged(pointer, mode) {
		return
	}
	ev := e.base(src, sha, line, entry, 0)
	if ev.Timestamp == "" {
		ev.Timestamp = st.lastTimestamp
	}
	ev.EventType = model.EventConfigAgent
	ev.Actor = model.ActorSystem
	ev.Confidence = model.ConfidenceHigh
	ev.ContentPreview = preview(mode)
	ev.Evidence.JSONPointer = pointer
	if elevatedPermissionMode(mode) {
		ev.Tags = []string{model.TagPermissionModeElevated}
	}
	res.Events = append(res.Events, ev)
}

// mapPRLink handles type:"pr-link" entries, which Claude Code writes when a pull
// request is created/associated during the session. The PR URL is a concrete
// output/network artifact — a place the session's work left the box — so it is
// surfaced as a network.indicator carrying the url in the typed URL field, the
// same field WebFetch/MCP-fetch egress targets use. prNumber/prRepository are
// redundant with the URL and have no typed home, so the url alone is kept. An
// entry with no url is skipped rather than emitting an empty event.
func (e ClaudeExtractor) mapPRLink(res *Result, src Source, sha string, line int, entry *claudeEntry) {
	url := strings.TrimSpace(entry.PRURL)
	if url == "" {
		return
	}
	ev := e.base(src, sha, line, entry, 0)
	ev.EventType = model.EventNetworkIndicator
	ev.Actor = model.ActorSystem
	ev.Confidence = model.ConfidenceHigh
	ev.URL = networkTargetURL(url)
	ev.ContentPreview = preview(url)
	ev.Evidence.JSONPointer = "/prUrl"
	ev.Tags = []string{model.TagNetwork}
	res.Events = append(res.Events, ev)
}

// mapAgentName handles type:"agent-name" entries, a lightweight marker Claude
// Code writes to announce which named subagent/skill persona is driving the
// session. It carries no command, file, or tool payload — only the agent name
// and session id — so it is a change to agent configuration, the same home the
// permission-mode switch uses: config.agent. The name lands in the typed
// SubAgent field (not ContentPreview alone) so a reviewer can pivot on the
// persona without parsing the preview; the preview mirrors it for a quick read.
// Because config.agent sets neither command nor file_path, this event cannot
// match any built-in detection rule (all gate on command.exec / file.read), so
// the marker can never fabricate a finding. The line stamps no timestamp, so it
// inherits the last observed one to stay in the timeline. An entry with no
// agentName is skipped rather than emitting an empty event.
func (e ClaudeExtractor) mapAgentName(res *Result, src Source, sha string, line int, st *claudeState, entry *claudeEntry) {
	name := strings.TrimSpace(entry.AgentName)
	if name == "" {
		return
	}
	ev := e.base(src, sha, line, entry, 0)
	if ev.Timestamp == "" {
		ev.Timestamp = st.lastTimestamp
	}
	ev.EventType = model.EventConfigAgent
	ev.Actor = model.ActorSystem
	ev.Confidence = model.ConfidenceHigh
	ev.SubAgent = name
	ev.ContentPreview = preview(name)
	ev.Evidence.JSONPointer = "/agentName"
	res.Events = append(res.Events, ev)
}

// attachmentDeferredToolsDelta is the attachment subtype that records a change
// to the set of tools/capabilities available to the agent. The names are the
// MCP-flattened tool identifiers (mcp__<server>__<tool>) plus native tools.
const attachmentDeferredToolsDelta = "deferred_tools_delta"

// mapAttachment handles type:"attachment" entries. Most attachment subtypes are
// context injected into the model (IDE selections, queued-command echoes) with
// no forensic capability signal, and are ignored quietly. The exception is
// "deferred_tools_delta", which records a change to the tool/capability set the
// agent can call — including MCP-qualified tools (mcp__<server>__<tool>). That
// is configuration evidence: it bounds what the agent could do in the session,
// so it is surfaced as config.mcp (a change to the available tool surface),
// naming the added/removed tools in the preview. Confidence is medium: the
// grant is inferred from a context-injection record, not a dedicated config
// action, and tool use itself is still captured separately as tool.call. A
// delta carrying no names is skipped rather than emitting an empty event.
func (e ClaudeExtractor) mapAttachment(res *Result, src Source, sha string, line int, entry *claudeEntry) {
	if entry.Attachment.Type != attachmentDeferredToolsDelta {
		return
	}
	added := entry.Attachment.AddedNames
	removed := entry.Attachment.RemovedNames
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "added: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed: "+strings.Join(removed, ", "))
	}
	ev := e.base(src, sha, line, entry, 0)
	ev.EventType = model.EventConfigMCP
	ev.Actor = model.ActorSystem
	ev.Confidence = model.ConfidenceMedium
	ev.ContentPreview = preview(strings.Join(parts, "; "))
	ev.Evidence.JSONPointer = "/attachment"
	res.Events = append(res.Events, ev)
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from a transcript entry. block is the content-block index, used
// to keep EventID unique when one entry emits several events.
func (e ClaudeExtractor) base(src Source, sha string, line int, entry *claudeEntry, block int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       entry.eventID(src.Path, line, block),
		SourceAgent:   e.agent(),
		SourceType:    model.SourceArtifact,
		Timestamp:     entry.Timestamp,
		ProjectPath:   entry.CWD,
		SessionID:     entry.SessionID,
		SubAgent:      claudeSubAgent(entry.AgentID, src.Path),
		Evidence: model.Evidence{
			ArtifactType: e.artifact(),
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

func claudeSubAgent(agentID, path string) string {
	if agentID = strings.TrimSpace(agentID); agentID != "" {
		return agentID
	}
	slashed := "/" + strings.TrimLeft(strings.ReplaceAll(path, `\`, "/"), "/")
	const marker = "/subagents/"
	index := strings.LastIndex(slashed, marker)
	if index < 0 {
		return ""
	}
	name := slashed[index+len(marker):]
	if strings.Contains(name, "/") || !strings.HasSuffix(strings.ToLower(name), ".jsonl") {
		return ""
	}
	name = name[:len(name)-len(".jsonl")]
	if !strings.HasPrefix(name, "agent-") || len(name) == len("agent-") {
		return ""
	}
	return strings.TrimPrefix(name, "agent-")
}

// classifyTool maps a Claude tool_use block onto the normalized event
// vocabulary, pulling command and file-path fields from well-known tool inputs.
// Unknown tools fall back to a generic tool.call so coverage never silently
// drops a call.
func classifyTool(ev *model.Event, name string, input map[string]json.RawMessage) {
	ev.ToolName = name
	switch name {
	case "Bash":
		ev.EventType = model.EventCommandExec
		ev.Command = inputString(input, "command")
	case "Read", "NotebookRead":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstInputString(input, "file_path", "notebook_path")
	case "Write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = inputString(input, "file_path")
	case "Edit", "MultiEdit", "NotebookEdit", "Update":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstInputString(input, "file_path", "notebook_path")
	case "WebFetch":
		// Network egress: exactly what a DFIR reviewer hunts for. The WebFetch
		// tool input is {url, prompt} (per Claude Code's tool schema); the url is
		// the egress target, promoted to the typed URL field and previewed so the
		// indicator names WHAT left the box, not just that a fetch occurred.
		url := inputString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = networkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "WebSearch":
		// Network egress via search. The WebSearch input is {query, ...domains};
		// the query is the investigative lead, surfaced on a network indicator.
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(inputString(input, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case mcpFetchToolName:
		// Network egress via the canonical Model Context Protocol fetch server
		// (modelcontextprotocol/servers src/fetch): tool "fetch" on a server named
		// "fetch", which Claude Code qualifies as mcp__fetch__fetch. Its input is
		// {url, max_length?, start_index?, raw?} with url the egress target — the
		// same shape native WebFetch uses, and the server's own README flags it as
		// able to reach local/internal IPs. This is an EXACT-identity match on a
		// documented tool, not a heuristic sniff of arbitrary MCP names: an MCP
		// fetch leaves the box just like WebFetch, so it must surface on the same
		// network indicator a reviewer pivots on, naming the url that left. Other
		// MCP tools stay generic (default) — their egress, if any, is not
		// derivable from the name alone.
		url := inputString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = networkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		ev.MCPServer, ev.MCPTool = "fetch", "fetch"
	default:
		// BashOutput/KillShell (background-shell control) and every other tool
		// (Grep, Glob, Task, and MCP tools other than the canonical fetch server)
		// map to a generic call; the full mcp__ name is retained as evidence. An
		// MCP-qualified name (mcp__<server>__<tool>) additionally splits into the
		// typed server/tool fields so a rule or SIEM can pivot on either without
		// re-parsing the flattened name.
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
}

// previewMax bounds a retained content excerpt, in runes. Previews are
// convenience context for a reviewer, never a place to stash raw content;
// redaction on emission is the real guard.
const previewMax = model.ContentPreviewMaxRunes

func preview(s string) string {
	return model.NormalizeContentPreview(s)
}

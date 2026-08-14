package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// artifactGeminiChat is the Evidence.ArtifactType for Gemini CLI session
// history below ~/.gemini/tmp/<project>/.
const artifactGeminiChat = "gemini_chat"

// geminiLogsFile is the exact basename of Gemini CLI's auto-saved prompt
// history. It selects the LogEntry shape; every other Gemini transcript name
// (checkpoint-<tag>.json) carries the @google/genai Content conversation.
const geminiLogsFile = "logs.json"

// GeminiExtractor parses the current JSONL session journal plus legacy prompt
// logs and manual checkpoints under ~/.gemini/tmp/<project>/.
//
//   - logs.json — a whole-file JSON ARRAY of LogEntry objects, each recording a
//     single user-typed prompt ({type:"user", message:"..."}). No role, no
//     parts, no tool calls: only the prompt string. Each entry maps to one
//     prompt.user event with a /<i>/message JSON Pointer.
//   - checkpoint-<tag>.json — a manual /chat save carrying the full
//     conversation as @google/genai Content objects (role + ordered parts).
//     Current gemini-cli writes a JSON OBJECT {"history": Content[], ...};
//     legacy versions wrote a bare Content[] array. Both are accepted. A part
//     is text, a functionCall (a tool invocation), a functionResponse (a tool
//     result), or a kind numbat does not model.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value (the default cap).
type GeminiExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (GeminiExtractor) Agent() string { return model.AgentGeminiCLI }

// Extract parses a Gemini CLI session file. It reads the whole artifact (to
// stamp a content hash on every event's evidence) and selects a decoder by the
// file's basename and top-level JSON shape:
//
//   - logs.json decodes as []geminiLogEntry; each user entry becomes a
//     prompt.user event with a /<i>/message JSON Pointer.
//   - a checkpoint object {"history": Content[]} decodes through geminiCheckpoint;
//     events carry /history/<i>/parts/<j>/... pointers.
//   - a checkpoint bare Content[] array (legacy) decodes into []geminiMessage;
//     events carry /<i>/parts/<j>/... pointers.
//
// Within a Content message, parts are walked in order: text becomes a
// prompt/assistant message, functionCall becomes a tool/command/file/network
// event, and functionResponse becomes a correlated tool/command result. A file
// that decodes but yields no recognized content still records a diagnostic
// (a visible coverage gap, never a silent 0/0); a malformed or unexpected file
// fails safe with a diagnostic and no fabricated events.
func (e GeminiExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		// An empty file is a clean no-op, not a corruption: no events, no
		// diagnostic, matching the other extractors' empty-input contract.
		return res, nil
	}

	if strings.EqualFold(filepath.Base(src.Path), geminiLogsFile) {
		e.extractLogs(res, src, sha, trimmed)
		return res, nil
	}
	if isGeminiSessionPath(src.Path) {
		e.extractSession(res, src, sha, data)
		return res, nil
	}
	e.extractCheckpoint(res, src, sha, trimmed)
	return res, nil
}

// extractLogs decodes logs.json — a whole-file JSON ARRAY of LogEntry objects —
// and maps each user-typed prompt to a prompt.user event with a /<i>/message
// JSON Pointer into the original array. logs.json records ONLY user prompts (no
// role, no parts, no tool calls), so this is the sole event kind it produces. A
// non-array or malformed file fails safe with a diagnostic; an array that
// decodes but yields no recognized entry still records a diagnostic so the gap
// is visible rather than a silent 0/0.
func (e GeminiExtractor) extractLogs(res *Result, src Source, sha string, trimmed []byte) {
	if trimmed[0] != '[' {
		res.diag(src.Path, 0, "logs.json is not a JSON array")
		return
	}
	var entries []geminiLogEntry
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		res.diag(src.Path, 0, "malformed logs.json array")
		return
	}
	before := len(res.Events)
	for i := range entries {
		en := &entries[i]
		if en.Type != geminiLogEntryUser {
			// logs.json records only user prompts; an unexpected type is not a
			// transcript shape numbat models. Skip it rather than guess a role.
			continue
		}
		clean := strings.TrimSpace(en.Message)
		if clean == "" {
			continue
		}
		ev := e.base(src, sha, i, 0, 0)
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		ev.Confidence = model.ConfidenceHigh
		setMessageContent(&ev, src, clean)
		ev.Evidence.JSONPointer = fmt.Sprintf("/%d/message", i)
		res.Events = append(res.Events, ev)
	}
	if len(res.Events) == before {
		// The file decoded as a JSON array but held no recognized user prompt.
		// A forensic read must see that gap, not a silent empty result.
		res.diag(src.Path, 0, "logs.json contained no user prompts")
	}
}

// extractCheckpoint decodes a checkpoint-<tag>.json conversation in either of
// the two shapes gemini-cli has written: the current object
// {"history": Content[]} or a legacy bare Content[] array. The shape is chosen
// by the top-level JSON token so numbat is robust across versions. Events from
// the object form carry /history/<i>/... pointers; the legacy array form carries
// /<i>/... pointers. A malformed or unexpected top-level shape fails safe with a
// diagnostic; a well-formed file that yields no recognized content still records
// a diagnostic so an empty transcript is a visible gap, not a silent 0/0.
func (e GeminiExtractor) extractCheckpoint(res *Result, src Source, sha string, trimmed []byte) {
	switch trimmed[0] {
	case '{':
		var ckpt geminiCheckpoint
		if err := json.Unmarshal(trimmed, &ckpt); err != nil {
			res.diag(src.Path, 0, "malformed checkpoint object")
			return
		}
		e.emit(res, src, sha, "/history", ckpt.History)
	case '[':
		var msgs []geminiMessage
		if err := json.Unmarshal(trimmed, &msgs); err != nil {
			res.diag(src.Path, 0, "malformed checkpoint array")
			return
		}
		e.emit(res, src, sha, "", msgs)
	default:
		// Not an object or array: not a checkpoint shape numbat can trust (a
		// scalar, JSONL, truncated bytes). Fail safe with a visible coverage gap.
		res.diag(src.Path, 0, "checkpoint is neither a JSON object nor array")
		return
	}
	if len(res.Events) == 0 {
		// The file decoded cleanly but carried no recognized content (an empty
		// history, only unmodeled parts). Surface the gap rather than a silent 0/0.
		res.diag(src.Path, 0, "checkpoint contained no recognized content")
	}
}

// geminiPendingCall is a functionCall awaiting its functionResponse. The mapper
// records each call as it is emitted so a later functionResponse correlates back
// to it by array order (most-recent-unmatched-first) and by name, recovering the
// call's id and whether it was a shell command (so its result becomes a
// command.result, not a bare tool.result).
type geminiPendingCall struct {
	name    string
	id      string
	isShell bool
	matched bool
}

// emit walks a Content[] conversation in order and produces events. ptrRoot is
// the RFC-6901 prefix the message array is rooted at: "" for a legacy bare
// Content[] checkpoint (pointers /<i>/...) and "/history" for the current
// object checkpoint (pointers /history/<i>/...). A pending-call stack carries
// functionCall context forward so a functionResponse — which may appear in the
// same message or a later one — correlates to the call it answers.
func (e GeminiExtractor) emit(res *Result, src Source, sha, ptrRoot string, msgs []geminiMessage) {
	var pending []geminiPendingCall
	for msgIdx := range msgs {
		m := &msgs[msgIdx]
		for partIdx := range m.Parts {
			p := &m.Parts[partIdx]
			switch {
			case p.FunctionCall != nil:
				e.emitFunctionCall(res, src, sha, ptrRoot, msgIdx, partIdx, p.FunctionCall, &pending)
			case p.FunctionResponse != nil:
				e.emitFunctionResponse(res, src, sha, ptrRoot, msgIdx, partIdx, p.FunctionResponse, pending)
			case p.Text != "":
				e.emitText(res, src, sha, ptrRoot, m.Role, msgIdx, partIdx, p.Text)
			default:
				// An unmodeled part kind (inlineData, fileData, ...). Skipping it is
				// a documented false negative, not a silent drop: it carries no
				// forensic value numbat maps, and guessing would risk a false event.
			}
		}
	}
}

// geminiPartPointer builds the RFC-6901 JSON Pointer to a part field, rooted at
// ptrRoot (""=legacy array, "/history"=object checkpoint). The kind is the
// trailing token (text, functionCall, functionResponse).
func geminiPartPointer(ptrRoot string, msgIdx, partIdx int, kind string) string {
	return fmt.Sprintf("%s/%d/parts/%d/%s", ptrRoot, msgIdx, partIdx, kind)
}

// emitText maps a text part to a conversation event: a "user" role yields a
// prompt.user, a "model" role yields a message.assistant. A tool result is
// carried in a functionResponse part (handled separately), so a user-role text
// part is a genuine human prompt, not a result body.
func (e GeminiExtractor) emitText(res *Result, src Source, sha, ptrRoot, role string, msgIdx, partIdx int, text string) {
	clean := strings.TrimSpace(text)
	if clean == "" {
		return
	}
	ev := e.base(src, sha, msgIdx, partIdx, 0)
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, clean)
	ev.Evidence.JSONPointer = geminiPartPointer(ptrRoot, msgIdx, partIdx, "text")
	switch role {
	case geminiRoleUser:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
	case geminiRoleModel:
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
	default:
		// An unexpected role still carries text worth surfacing; attribute it to
		// the assistant at low confidence rather than dropping it or guessing a
		// user prompt.
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceLow
	}
	res.Events = append(res.Events, ev)
}

// emitFunctionCall maps a functionCall part to a tool invocation event and
// records it on the pending stack so its functionResponse can correlate back. A
// functionCall is an assistant action regardless of the carrying message's role,
// so the actor is always the assistant. The event type and any lifted argument
// come from classifyGeminiTool; the JSON Pointer locates the part within the
// whole-file array.
func (e GeminiExtractor) emitFunctionCall(res *Result, src Source, sha, ptrRoot string, msgIdx, partIdx int, fc *geminiFunctionCall, pending *[]geminiPendingCall) {
	ev := e.base(src, sha, msgIdx, partIdx, 0)
	ev.Actor = model.ActorAssistant
	ev.Confidence = model.ConfidenceHigh
	ev.Evidence.JSONPointer = geminiPartPointer(ptrRoot, msgIdx, partIdx, "functionCall")
	isShell := classifyGeminiTool(&ev, fc)
	res.Events = append(res.Events, ev)
	*pending = append(*pending, geminiPendingCall{name: fc.Name, id: fc.ID, isShell: isShell})
}

// emitFunctionResponse maps a functionResponse part to a tool result event,
// correlated to the functionCall it answers. Correlation is by array order
// (the most recent unmatched call wins) constrained by name, and by id when both
// the call and the response carry one. A response matching a shell call becomes
// a command.result (ordered after its command.exec, since the call part was
// emitted first); any other becomes a tool.result. Exit code and tool_error are
// read ONLY from structured response fields; a read's result body is never
// previewed so file content is never stored.
func (e GeminiExtractor) emitFunctionResponse(res *Result, src Source, sha, ptrRoot string, msgIdx, partIdx int, fr *geminiFunctionResponse, pending []geminiPendingCall) {
	call := correlateGeminiResponse(pending, fr)
	ev := e.base(src, sha, msgIdx, partIdx, 0)
	ev.Actor = model.ActorTool
	ev.Confidence = model.ConfidenceHigh
	ev.ToolName = fr.Name
	ev.ToolCallID = fr.ID
	ev.Evidence.JSONPointer = geminiPartPointer(ptrRoot, msgIdx, partIdx, "functionResponse")
	if ev.ToolCallID == "" && call != nil {
		ev.ToolCallID = call.id
	}

	isShell := fr.Name == geminiToolShell || (call != nil && call.isShell)
	isRead := geminiToolReturnsFileContent(fr.Name)
	if isShell {
		ev.EventType = model.EventCommandResult
	} else {
		ev.EventType = model.EventToolResult
		if server, tool, ok := splitMCPName(fr.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	// A read result body is file content; never store it. Other results are
	// previewed so the result names what came back, not just that one happened.
	if !isRead {
		ev.ContentPreview = preview(geminiResponsePreview(fr.Response))
	}
	if code, ok := geminiResponseExitCode(fr.Response); ok {
		ev.ExitCode = &code
	}
	if geminiResponseHasError(fr.Response) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
	res.Events = append(res.Events, ev)
}

// correlateGeminiResponse finds the functionCall a functionResponse answers and
// marks it matched so a second response cannot reuse it. The match is the most
// recent unmatched pending call whose name equals the response's name; when both
// the call and the response carry an id, the ids must also match. A nil result
// (no correlatable call) is fine: the response still emits a tool.result keyed
// by its own name/id, just without a recovered shell classification.
func correlateGeminiResponse(pending []geminiPendingCall, fr *geminiFunctionResponse) *geminiPendingCall {
	for i := len(pending) - 1; i >= 0; i-- {
		c := &pending[i]
		if c.matched || c.name != fr.Name {
			continue
		}
		if c.id != "" && fr.ID != "" && c.id != fr.ID {
			continue
		}
		c.matched = true
		return c
	}
	return nil
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from a Gemini part. msgIdx/partIdx fix the source position in
// the whole-file array; sub keeps the EventID unique if one part ever emits more
// than one event. Evidence.Line stays 0: the artifact is a whole-file array, not
// line-oriented, so the JSON Pointer (set by the caller) is the precise locator.
func (e GeminiExtractor) base(src Source, sha string, msgIdx, partIdx, sub int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       geminiEventID(src.Path, msgIdx, partIdx, sub),
		SourceAgent:   model.AgentGeminiCLI,
		SourceType:    model.SourceArtifact,
		Evidence: model.Evidence{
			ArtifactType: artifactGeminiChat,
			LocalPath:    src.Path,
			SHA256:       sha,
		},
	}
}

// classifyGeminiTool maps a Gemini functionCall onto the normalized event
// vocabulary, lifting the forensically salient argument (command, file path,
// search query, fetched URL) out of the tool's well-known arg keys. The mapping
// is deliberately NARROW and artifact-backed: only the handful of Gemini tool
// names with a documented, stable shape are promoted to a typed event; every
// other name — MCP tools, future built-ins — falls through to a generic
// tool.call with NO alias guessing, so coverage never silently drops a call and
// an unknown tool is never mislabeled. It returns whether the call is the shell
// tool so a correlated functionResponse becomes a command.result.
func classifyGeminiTool(ev *model.Event, fc *geminiFunctionCall) bool {
	ev.ToolName = fc.Name
	ev.ToolCallID = fc.ID
	switch fc.Name {
	case geminiToolShell:
		ev.EventType = model.EventCommandExec
		ev.Command = geminiArgString(fc.Args, geminiArgCommand)
		return true
	case geminiToolReadFile:
		ev.EventType = model.EventFileRead
		ev.FilePath = geminiArgString(fc.Args, geminiArgFile)
	case geminiToolWriteFile, geminiToolEdit:
		ev.EventType = model.EventFileWrite
		ev.FilePath = geminiArgString(fc.Args, geminiArgFile)
	case geminiToolWebFetch:
		// Network egress: exactly what a DFIR reviewer hunts for. web_fetch's
		// prompt arg is free text that embeds the URL(s) to fetch, so it is
		// previewed as the investigative lead; when a clean URL can be lifted out
		// of it, that URL is also promoted to the typed field. A prompt with no
		// parseable URL leaves URL empty rather than guessing.
		prompt := geminiArgString(fc.Args, geminiArgPrompt)
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(prompt)
		ev.URL = networkTargetURL(firstURL(prompt))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case geminiToolWebSearch:
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(geminiArgString(fc.Args, geminiArgQuery))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		// MCP tools and every other tool map to a generic call, preserving
		// coverage without promoting an unknown name to a typed alias. An
		// MCP-qualified name splits into the typed server/tool fields so a rule or
		// SIEM can pivot without re-parsing the flattened name.
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(fc.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	return false
}

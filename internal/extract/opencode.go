package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// OpenCodeExtractor parses one whole-file JSON record from OpenCode's earlier
// storage layouts. A part file (storage/part/<messageID>/<partID>.json) carries
// the tool/shell signal, and a
// message file (storage/message/<sessionID>/<messageID>.json) carries the role
// of a prompt/turn. The parser reads one such file and maps it to events.
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value (the default cap).
type OpenCodeExtractor struct {
	maxBytes int
}

// Agent identifies the events this extractor produces.
func (OpenCodeExtractor) Agent() string { return model.AgentOpenCode }

// Extract parses one OpenCode storage record. It reads the whole artifact (to
// stamp a content hash on every event's evidence) and dispatches on the
// top-level JSON object's discriminator: a part file (has a "type" field) is
// mapped by its part kind; a message file (has a "role" field) becomes a
// prompt.user / message.assistant. An empty file is a clean no-op; a file that
// decodes but carries no usable record records a DIAGNOSTIC so the coverage gap
// is visible rather than a silent 0/0; a malformed or unexpected file fails
// SAFE with a diagnostic and no fabricated events.
func (e OpenCodeExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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
	if trimmed[0] != '{' {
		// Every OpenCode storage record is a whole-file JSON OBJECT. A non-object
		// (a bare array, a scalar, JSONL, truncated bytes) is not a shape numbat
		// trusts; fail safe with a visible coverage gap.
		res.diag(src.Path, 0, "opencode record is not a JSON object")
		return res, nil
	}

	// Decode once into a tolerant view carrying both a part's "type" and a
	// message's "role"; the present discriminator selects the mapping. A single
	// raw decode (rather than two passes) keeps a malformed file a single
	// fail-safe diagnostic.
	var rec struct {
		Type string `json:"type"`
		openCodeMessage
	}
	if err := json.Unmarshal(trimmed, &rec); err != nil {
		res.diag(src.Path, 0, "malformed opencode record")
		return res, nil
	}

	switch {
	case rec.Type != "":
		e.extractPart(res, src, sha, trimmed)
	case rec.Role != "":
		e.extractMessage(res, src, sha, rec.openCodeMessage)
	default:
		// A valid JSON object with neither a part "type" nor a message "role"
		// (a session info file, or an unrecognized record) carries no event numbat
		// maps. Surface the gap rather than a silent empty result.
		res.diag(src.Path, 0, "opencode record has neither a part type nor a message role")
	}
	return res, nil
}

// extractMessage maps a message file to a conversation event by role: a "user"
// message becomes a prompt.user, an "assistant" message becomes a
// message.assistant. A message file carries no prose body of its own (the text
// lives in sibling part files), so no ContentPreview is set; the event records
// that a turn of this role occurred. An unrecognized role records a diagnostic
// so the gap is visible.
func (e OpenCodeExtractor) extractMessage(res *Result, src Source, sha string, message openCodeMessage) {
	ev := e.base(src, sha, 0, message.SessionID, epochMillisRFC3339(message.Time.Created))
	ev.Confidence = model.ConfidenceHigh
	ev.Evidence.JSONPointer = "/role"
	ev.ProjectPath = message.Path.CWD
	ev.Model, ev.ModelProvider = message.modelIdentity()
	switch message.Role {
	case openCodeRoleUser:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
	case openCodeRoleAssistant:
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
	default:
		// system/synthetic or a future role: not a turn numbat attributes to a
		// human or the assistant. Skip it as a visible gap rather than guess.
		res.diag(src.Path, 0, "opencode message has an unrecognized role")
		return
	}
	res.Events = append(res.Events, ev)
}

// extractPart maps a part file to events by its part kind. A tool part is the
// primary signal; a legacy shell part is a direct command/output; a patch part
// is a structured multi-file edit. A reasoning part is assistant-only in
// OpenCode's schema and is emitted when explicitly requested. A text part
// carries no role and remains a no-op until it can be joined to its message.
// An unmodeled part kind records a diagnostic so coverage never silently drops
// a part numbat is expected to map.
func (e OpenCodeExtractor) extractPart(res *Result, src Source, sha string, trimmed []byte) {
	var part openCodePart
	if err := json.Unmarshal(trimmed, &part); err != nil {
		res.diag(src.Path, 0, "malformed opencode part")
		return
	}
	switch part.Type {
	case openCodePartTool:
		e.emitToolPart(res, src, sha, &part)
	case openCodePartShell:
		e.emitShellPart(res, src, sha, &part)
	case openCodePartPatch:
		e.emitPatchPart(res, src, sha, &part)
	case openCodePartReasoning:
		if !src.IncludeReasoning || strings.TrimSpace(part.Text) == "" {
			return
		}
		ev := e.base(src, sha, 0, part.SessionID, epochMillisRFC3339(part.Time.Start))
		ev.EventType = model.EventMessageReasoning
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.Evidence.JSONPointer = "/text"
		setMessageContent(&ev, src, part.Text)
		res.Events = append(res.Events, ev)
	case openCodePartText:
		// Text parts can belong to user or assistant messages, but the part file
		// does not carry that role. Do not guess it from content or path.
	default:
		// A file, step-start/finish, snapshot, agent, retry, compaction, or
		// subtask part carries no forensic signal numbat maps. Surface the gap
		// rather than guessing an event for it.
		res.diag(src.Path, 0, "opencode part type is not modeled")
	}
}

// emitShellPart maps a legacy "shell" part — a direct command/output pair from
// an older OpenCode internal layout — to a command.exec followed by a correlated
// command.result. The exec is emitted FIRST so the result orders after it. The
// command text is the lead; the output is previewed on the result. No exit code
// is fabricated: a shell part carries none, so command.result leaves ExitCode
// nil. A shell part has no structured failure field, so it never carries a
// tool_error tag.
func (e OpenCodeExtractor) emitShellPart(res *Result, src Source, sha string, part *openCodePart) {
	exec := e.base(src, sha, 0, part.SessionID, "")
	exec.EventType = model.EventCommandExec
	exec.Actor = model.ActorAssistant
	exec.Confidence = model.ConfidenceHigh
	exec.Command = part.Command
	exec.ToolCallID = part.CallID
	exec.Evidence.JSONPointer = "/command"
	res.Events = append(res.Events, exec)

	result := e.base(src, sha, 1, part.SessionID, "")
	result.EventType = model.EventCommandResult
	result.Actor = model.ActorTool
	result.Confidence = model.ConfidenceHigh
	result.Command = part.Command
	result.ToolCallID = part.CallID
	result.ContentPreview = preview(part.Output)
	result.Evidence.JSONPointer = "/output"
	res.Events = append(res.Events, result)
}

// emitPatchPart maps a "patch" part — a structured multi-file edit — to one
// file.write per touched file, each carrying the patch's content hash as its
// diff digest (the digest stays local; only its hex travels). A patch with no
// listed files still records one generic file.write so the edit is not dropped.
// A patch part carries no per-file diff text or status, so no diff size and no
// tool_error tag.
func (e OpenCodeExtractor) emitPatchPart(res *Result, src Source, sha string, part *openCodePart) {
	digest := openCodeHexHash(part.Hash)
	if len(part.Files) == 0 {
		ev := e.base(src, sha, 0, part.SessionID, "")
		ev.EventType = model.EventFileWrite
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceMedium
		ev.ToolName = openCodeToolApplyPatch
		ev.DiffSHA256 = digest
		ev.Evidence.JSONPointer = "/hash"
		res.Events = append(res.Events, ev)
		return
	}
	for i, f := range part.Files {
		ev := e.base(src, sha, i, part.SessionID, "")
		ev.EventType = model.EventFileWrite
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceMedium
		ev.ToolName = openCodeToolApplyPatch
		ev.FilePath = f
		ev.DiffSHA256 = digest
		ev.Evidence.JSONPointer = fmt.Sprintf("/files/%d", i)
		res.Events = append(res.Events, ev)
	}
}

// emitToolPart maps a "tool" part to events. The part's state is a tagged union
// on state.status; a completed or error state carries BOTH the call input and
// the result, so a single part yields a call/exec event AND a correlated
// result event (call first, result after), keyed by callID. A pending/running
// state carries only the call input, so only the call/exec event is emitted.
// The tool id selects the typed mapping (NARROW, artifact-backed); an unknown
// id falls through to tool.call with NO alias promotion. tool_error is tagged
// on the result ONLY when state.status=="error" — never inferred.
func (e OpenCodeExtractor) emitToolPart(res *Result, src Source, sha string, part *openCodePart) {
	tool := part.Tool
	call := e.base(src, sha, 0, part.SessionID, epochMillisRFC3339(part.State.Time.Start))
	call.Actor = model.ActorAssistant
	call.Confidence = model.ConfidenceHigh
	call.ToolName = tool
	call.ToolCallID = part.CallID
	call.Evidence.JSONPointer = "/state/input"
	isShell, isRead := classifyOpenCodeTool(&call, tool, part.State.Input)
	res.Events = append(res.Events, call)

	status := part.State.Status
	if status != openCodeStatusCompleted && status != openCodeStatusError {
		// A pending/running part has no result yet: only the call is known. Emitting
		// a result would fabricate an outcome the artifact does not record.
		return
	}

	result := e.base(src, sha, 1, part.SessionID, epochMillisRFC3339(part.State.Time.End))
	result.Actor = model.ActorTool
	result.Confidence = model.ConfidenceHigh
	result.ToolName = tool
	result.ToolCallID = part.CallID
	if isShell {
		result.EventType = model.EventCommandResult
		result.Command = openCodeArgString(part.State.Input, openCodeArgCommand)
	} else {
		result.EventType = model.EventToolResult
		if server, mcpTool, ok := splitMCPName(tool); ok {
			result.MCPServer, result.MCPTool = server, mcpTool
		}
	}
	// A read result body is file content; never preview it so file content is
	// never stored. Other results preview the structured output so the result
	// names what came back.
	if !isRead {
		result.ContentPreview = preview(part.State.Output)
	}
	if status == openCodeStatusError {
		// The SOLE tool-error signal: a structured state.status=="error". A
		// completed state is success; a non-zero exit alone is not a tool-error.
		result.Tags = append(result.Tags, model.TagToolError)
	}
	result.Evidence.JSONPointer = "/state"
	res.Events = append(res.Events, result)
}

// base builds the evidence- and identity-stamped event skeleton shared by every
// event derived from an OpenCode record. sub keeps the EventID unique when one
// record emits more than one event (a tool part's call+result, a patch's
// per-file writes). Evidence.Line stays 0: the artifact is a whole-file object,
// not line-oriented, so the JSON Pointer (set by the caller) is the precise
// locator.
func (e OpenCodeExtractor) base(src Source, sha string, sub int, sessionID, timestamp string) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       openCodeEventID(src.Path, sub),
		SourceAgent:   model.AgentOpenCode,
		SourceType:    model.SourceArtifact,
		Timestamp:     timestamp,
		SessionID:     sessionID,
		Evidence: model.Evidence{
			ArtifactType: artifactOpenCode,
			LocalPath:    src.Path,
			SHA256:       sha,
		},
	}
}

// classifyOpenCodeTool maps an OpenCode tool id onto the normalized event
// vocabulary, lifting the forensically salient argument (command, file path,
// fetched URL, search query) out of the tool's well-known input keys. The
// mapping is deliberately NARROW and artifact-backed: only the handful of
// OpenCode built-in tool ids with a documented, stable input shape are promoted
// to a typed event; every other id — plugin tools, MCP tools, future built-ins
// — falls through to a generic tool.call with NO alias guessing, so coverage
// never silently drops a call and an unknown tool is never mislabeled. An
// MCP-qualified id splits into the typed server/tool fields. It returns whether
// the call is the shell tool (so a correlated result becomes a command.result)
// and whether it is the read tool (so a correlated result body is never
// previewed).
func classifyOpenCodeTool(ev *model.Event, tool string, input map[string]json.RawMessage) (isShell, isRead bool) {
	switch tool {
	case openCodeToolBash:
		ev.EventType = model.EventCommandExec
		ev.Command = openCodeArgString(input, openCodeArgCommand)
		return true, false
	case openCodeToolRead:
		ev.EventType = model.EventFileRead
		ev.FilePath = openCodeArgString(input, openCodeArgFilePath)
		return false, true
	case openCodeToolWrite, openCodeToolEdit:
		ev.EventType = model.EventFileWrite
		ev.FilePath = openCodeArgString(input, openCodeArgFilePath)
		return false, false
	case openCodeToolApplyPatch:
		// apply_patch's call carries no per-file path in a stable input key (the
		// patch body is free text); the structured file list lives in the patch
		// part. Record the requested write generically so the call is not dropped,
		// without guessing a path.
		ev.EventType = model.EventFileWrite
		return false, false
	case openCodeToolWebFetch:
		// Network egress: the webfetch tool requires an http(s) url. Promote the
		// raw value to the typed URL field ONLY when it is a real absolute
		// http(s) target — a tampered or malformed record carrying file://,
		// javascript:, data:, or junk leaves Event.URL empty and the value is kept
		// as a preview instead, never fabricated into a network target.
		ev.EventType = model.EventNetworkIndicator
		raw := openCodeArgString(input, openCodeArgURL)
		if httpURL := networkTargetURL(raw); httpURL != "" {
			ev.URL = httpURL
		} else if raw != "" {
			ev.ContentPreview = preview(raw)
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
		return false, false
	case openCodeToolWebSearch:
		// A web search performs outbound discovery but fetches no single url; the
		// query is the lead, and no url is fabricated.
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(openCodeArgString(input, openCodeArgQuery))
		ev.Tags = append(ev.Tags, model.TagNetwork)
		return false, false
	default:
		// Plugin tools, MCP tools, and every other id map to a generic call,
		// preserving coverage without promoting an unknown name to a typed alias.
		// An MCP-qualified name splits into the typed server/tool fields so a rule
		// or SIEM can pivot without re-parsing the flattened name.
		ev.EventType = model.EventToolCall
		if server, mcpTool, ok := splitMCPName(tool); ok {
			ev.MCPServer, ev.MCPTool = server, mcpTool
		}
		return false, false
	}
}

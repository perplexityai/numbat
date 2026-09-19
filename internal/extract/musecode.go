package extract

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// artifactMuseSessionJSONL is the Evidence.ArtifactType for Muse Code session
// transcripts (~/.local/share/muse/sessions/YYYY/MM/DD/<session-id>/session.jsonl
// and its nested subagent/<id>/session.jsonl transcripts).
const artifactMuseSessionJSONL = "muse_session_jsonl"

// Payload types that carry conversation-relevant content. Everything else is
// telemetry, cron/goal bookkeeping, or reminder machinery and is skipped —
// numbat maps only fields it has verified, never guesses at an unlisted type.
const (
	musePayloadMetadata   = "runtime.session.metadata"
	musePayloadSession    = "runtime.session"
	musePayloadSessionEnd = "session.end"
)

// Run event kinds that carry conversation content, keyed by payload.event.kind
// inside a musePayloadSession record whose payload.kind is "run". The runtime
// emits many more (diagnostics, trace records, reminder/task bookkeeping,
// todo snapshots); those are intentionally skipped rather than guessed at.
const (
	museEventStarted                     = "started"
	museEventReasoningCommitted          = "reasoning_committed"
	museEventAssistantMessageCommitted   = "assistant_message_committed"
	museEventAssistantToolCallsCommitted = "assistant_tool_calls_committed"
	museEventToolResultBatchCommitted    = "tool_result_batch_committed"
)

// museRetainedFrameKind is the outer wrapper observed around a small number of
// lines (confirmed against Muse Code 1.3.0, not documented in any source this
// adapter cites): a "retained frame" transaction carrying one or more ordinary
// envelope records as JSON-encoded strings. Every occurrence found so far
// wraps bookkeeping (a permission-format declaration), but the wrapper is
// unwrapped generically — rather than skipped outright — so a future payload
// type worth mapping is not silently dropped by this adapter.
const museRetainedFrameKind = "retained_frame"

// MuseCodeExtractor parses Muse Code's session.jsonl transcripts: an
// append-only, schema-versioned JSONL event log. The store layout, envelope,
// and payload shapes below were verified two ways: independently against real
// files this adapter's own author captured on Muse Code 1.3.0, and
// cross-checked against a third-party reverse-engineering effort
// (github.com/specstoryai/getspecstory, Apache-2.0,
// pkg/providers/musecode/MUSE-CODE-FORMAT.md) done against Muse Code 0.1.0.
// The core envelope and event catalog matched exactly across that ~13-version
// gap; the retained-frame wrapper above is the one addition found empirically
// that the third-party document does not mention. Muse Code's own docs do not
// publish this format (see docs/notes/muse-contract.md, not committed).
//
// The zero value is ready to use. maxBytes overrides the artifact size cap and
// exists for tests; production callers use the zero value.
type MuseCodeExtractor struct {
	maxBytes int
}

func (MuseCodeExtractor) Agent() string { return model.AgentMuseCode }

// museRecord is the envelope wrapping every ordinary line of a transcript.
type museRecord struct {
	Stream      museStream      `json:"stream"`
	RecordType  string          `json:"record_type"`
	PayloadType string          `json:"payload_type"`
	Payload     json.RawMessage `json:"payload"`
}

// museStream identifies which conversation a record belongs to. Records
// belonging to the file's own session (or, inside a subagent transcript, that
// subagent's own execution) carry stream.kind "session" and an id matching the
// file's own directory. Subagent/reminder task runs are ALSO interleaved into
// the parent's file under stream.kind "task"; those are skipped here because
// the corresponding subagent's own actions are recorded in full in its own
// nested transcript, which this same extractor parses separately when
// discovery walks into it.
type museStream struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// museRetainedFrame is the outer transaction wrapper; see museRetainedFrameKind.
type museRetainedFrame struct {
	RetainedFrame string           `json:"retained_frame"`
	Children      []museFrameChild `json:"children"`
}

type museFrameChild struct {
	RecordJSON string `json:"record_json"`
}

// museOmittedMarker is the tombstone left in place of a record the runtime
// chose not to retain durably (confirmed empirically against Muse Code 1.3.0,
// not documented in any source this adapter cites). Its own field name is
// "retained_marker" despite marking an omission — the record itself was not
// retained, but a marker noting that fact was.
type museOmittedMarker struct {
	RetainedMarker string `json:"retained_marker"`
}

// museMetadataPayload is the payload of a runtime.session.metadata record.
type museMetadataPayload struct {
	Record struct {
		WorkspaceRoot string `json:"workspace_root"`
		ProviderID    string `json:"provider_id"`
		ModelID       string `json:"model_id"`
		Build         struct {
			Semver string `json:"semver"`
		} `json:"build"`
	} `json:"record"`
}

// museRunPayload is the payload of a runtime.session record. Kind is "run"
// (model turns, mapped below) or "task" (execution bookkeeping, skipped).
type museRunPayload struct {
	Kind  string    `json:"kind"`
	Event museEvent `json:"event"`
}

// museEvent is the union of run-event shapes that carry conversation content;
// only the fields for the decoded Kind are populated.
type museEvent struct {
	Kind string `json:"kind"`

	// started
	Prompt string `json:"prompt"`

	// reasoning_committed / assistant_message_committed
	Text string `json:"text"`

	// assistant_tool_calls_committed
	ToolCalls []museToolCall `json:"tool_calls"`

	// tool_result_batch_committed
	Results []museToolResult `json:"results"`
}

// museToolCall is one tool invocation requested by the model. Args is a JSON
// *string*, not an object, matching the same live-hook tool_input encoding.
type museToolCall struct {
	CallID string `json:"call_id"`
	Name   string `json:"name"`
	Args   string `json:"args"`
}

// museToolResult is one tool outcome, matched to its call by ToolCallID.
type museToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Text       string `json:"text"`
}

// museBashResult decodes a bash tool result's text, which is itself a
// JSON-encoded object string (the same shape class as the live hook's
// tool_response/error fields — see resolver.museToolResponse in internal/hook).
type museBashResult struct {
	ExitCode       *int   `json:"exit_code"`
	TerminalStatus string `json:"terminal_status"`
}

// museState carries per-file context across records: the file's own session
// identity (derived from its path, not trusted from record content) and the
// tool name for each open call, so a later result can classify correctly and
// join to it.
type museState struct {
	rootSessionID string
	subAgent      string
	projectPath   string
	model         string
	modelProvider string
	metadataSeen  bool
	toolNames     map[string]string
}

func (e MuseCodeExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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

	rootSessionID, subAgent, streamID := museFileContext(src.Path)
	st := &museState{rootSessionID: rootSessionID, subAgent: subAgent}

	res := &Result{}
	br := bufio.NewReader(bytes.NewReader(data))
	for line := 1; ; line++ {
		raw, tooLong, readErr := readLine(br)
		if tooLong {
			res.diag(src.Path, line, "line exceeds size cap; skipped")
		} else if raw = bytes.TrimSpace(raw); len(raw) > 0 {
			e.mapLine(res, src, sha, st, streamID, line, raw)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return res, nil
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, readErr)
		}
	}
}

func (e MuseCodeExtractor) mapLine(res *Result, src Source, sha string, st *museState, streamID string, line int, raw []byte) {
	var record museRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	if record.PayloadType == "" {
		var frame museRetainedFrame
		if err := json.Unmarshal(raw, &frame); err == nil && frame.RetainedFrame != "" {
			for _, child := range frame.Children {
				var inner museRecord
				if err := json.Unmarshal([]byte(child.RecordJSON), &inner); err == nil && inner.PayloadType != "" {
					e.mapRecord(res, src, sha, st, streamID, line, inner)
				}
			}
			return
		}
		var marker museOmittedMarker
		if err := json.Unmarshal(raw, &marker); err == nil && marker.RetainedMarker != "" {
			// A tombstone for an ephemeral record the runtime explicitly chose
			// not to retain durably (confirmed empirically: every occurrence
			// found so far has omitted_record.durability "ephemeral" and
			// payload_kind "task" — bookkeeping this adapter already skips
			// when it IS retained). It carries no payload to map and is not
			// malformed, so it is silently skipped rather than diagnosed.
			return
		}
		res.diag(src.Path, line, "record missing payload_type")
		return
	}
	e.mapRecord(res, src, sha, st, streamID, line, record)
}

func (e MuseCodeExtractor) mapRecord(res *Result, src Source, sha string, st *museState, streamID string, line int, record museRecord) {
	if streamID != "" && record.Stream.ID != "" && record.Stream.ID != streamID {
		return // subagent/reminder task-stream noise interleaved into this file
	}

	switch record.PayloadType {
	case musePayloadMetadata:
		var payload museMetadataPayload
		if err := json.Unmarshal(record.Payload, &payload); err != nil {
			res.diag(src.Path, line, "malformed session metadata")
			return
		}
		if st.projectPath == "" {
			st.projectPath = payload.Record.WorkspaceRoot
		}
		if st.model == "" {
			st.model = payload.Record.ModelID
		}
		if st.modelProvider == "" {
			st.modelProvider = payload.Record.ProviderID
		}
		if st.metadataSeen {
			return // later copies only backfill blanked fields, above
		}
		st.metadataSeen = true
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceHigh
		res.Events = append(res.Events, ev)

	case musePayloadSessionEnd:
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventSessionEnd
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceHigh
		res.Events = append(res.Events, ev)

	case musePayloadSession:
		var payload museRunPayload
		if err := json.Unmarshal(record.Payload, &payload); err != nil {
			res.diag(src.Path, line, "malformed session run payload")
			return
		}
		if payload.Kind != "run" {
			return // "task": execution bookkeeping, not conversation content
		}
		e.mapRunEvent(res, src, sha, st, line, &payload.Event)
	}
}

func (e MuseCodeExtractor) mapRunEvent(res *Result, src Source, sha string, st *museState, line int, event *museEvent) {
	switch event.Kind {
	case museEventStarted:
		if strings.TrimSpace(event.Prompt) == "" {
			return
		}
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		ev.Confidence = model.ConfidenceHigh
		setMessageContent(&ev, src, event.Prompt)
		ev.Evidence.JSONPointer = "/payload/event/prompt"
		res.Events = append(res.Events, ev)

	case museEventReasoningCommitted:
		// text is usually empty because reasoning is encrypted for the Meta
		// provider (confirmed empirically); never fabricate a summary from an
		// empty field.
		if !src.IncludeReasoning || strings.TrimSpace(event.Text) == "" {
			return
		}
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventMessageReasoning
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		setMessageContent(&ev, src, event.Text)
		ev.Evidence.JSONPointer = "/payload/event/text"
		res.Events = append(res.Events, ev)

	case museEventAssistantMessageCommitted:
		if strings.TrimSpace(event.Text) == "" {
			return
		}
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		setMessageContent(&ev, src, event.Text)
		ev.Evidence.JSONPointer = "/payload/event/text"
		res.Events = append(res.Events, ev)

	case museEventAssistantToolCallsCommitted:
		for i, call := range event.ToolCalls {
			if call.Name == "" {
				continue
			}
			ev := e.base(src, sha, st, line, i)
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceHigh
			ev.ToolName = call.Name
			ev.ToolCallID = call.CallID
			ev.Evidence.JSONPointer = fmt.Sprintf("/payload/event/tool_calls/%d", i)
			classifyMuseTool(&ev, call.Name, call.Args)
			if call.CallID != "" {
				st.noteToolCall(call.CallID, call.Name)
			}
			res.Events = append(res.Events, ev)
		}

	case museEventToolResultBatchCommitted:
		for i, result := range event.Results {
			ev := e.base(src, sha, st, line, i)
			ev.Actor = model.ActorTool
			ev.Confidence = model.ConfidenceHigh
			name := st.toolNames[result.ToolCallID]
			ev.ToolName = name
			ev.ToolCallID = result.ToolCallID
			ev.Evidence.JSONPointer = fmt.Sprintf("/payload/event/results/%d", i)
			e.classifyMuseResult(&ev, name, result.Text)
			res.Events = append(res.Events, ev)
		}
	}
}

// classifyMuseTool maps the documented/verified native tool names to numbat's
// closed action vocabulary. Only names with a confirmed, unambiguous
// single-path argument are mapped; everything else (search, web_search,
// memory/goal/cron/subagent/todo tools, ...) stays generic tool.call rather
// than guessing a field name this adapter has not verified.
func classifyMuseTool(ev *model.Event, name, argsRaw string) {
	var args map[string]json.RawMessage
	_ = json.Unmarshal([]byte(argsRaw), &args)
	switch name {
	case "bash":
		ev.EventType = model.EventCommandExec
		ev.Command = museArgString(args, "command")
	case "read_file":
		ev.EventType = model.EventFileRead
		ev.FilePath = museArgString(args, "path")
	case "write_file", "edit_file":
		ev.EventType = model.EventFileWrite
		ev.FilePath = museArgString(args, "path")
	default:
		ev.EventType = model.EventToolCall
	}
}

// classifyMuseResult mirrors classifyMuseTool's tool-name family for the
// matching result, so a command's result stays command.result rather than a
// generic tool.result. For bash, the result text is itself a JSON-encoded
// object string; TagToolError is set from its own exit_code/terminal_status
// fields when that decodes, and from the two error-text prefixes this adapter
// has directly observed otherwise ("tool failed: ..." from the third-party
// format notes; "tool blocked by hook: ..." captured directly against a real
// numbat-denied action).
func (MuseCodeExtractor) classifyMuseResult(ev *model.Event, name, text string) {
	switch name {
	case "bash":
		ev.EventType = model.EventCommandResult
		var decoded museBashResult
		if err := json.Unmarshal([]byte(text), &decoded); err == nil {
			if decoded.ExitCode != nil {
				ev.ExitCode = decoded.ExitCode
			}
			if decoded.ExitCode != nil && *decoded.ExitCode != 0 || strings.EqualFold(decoded.TerminalStatus, "failed") {
				ev.Tags = append(ev.Tags, model.TagToolError)
			}
			return
		}
	case "":
		ev.EventType = model.EventToolResult
		return
	default:
		ev.EventType = model.EventToolResult
	}
	if strings.HasPrefix(text, "tool failed:") || strings.HasPrefix(text, "tool blocked by hook:") {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func museArgString(args map[string]json.RawMessage, key string) string {
	var value string
	if raw, ok := args[key]; ok {
		_ = json.Unmarshal(raw, &value)
	}
	return value
}

func (st *museState) noteToolCall(callID, name string) {
	if st.toolNames == nil {
		st.toolNames = map[string]string{}
	}
	st.toolNames[callID] = name
}

func (MuseCodeExtractor) base(src Source, sha string, st *museState, line, sub int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       museEventID(src.Path, line, sub),
		SourceAgent:   model.AgentMuseCode,
		SourceType:    model.SourceArtifact,
		ProjectPath:   st.projectPath,
		Model:         st.model,
		ModelProvider: st.modelProvider,
		SessionID:     st.rootSessionID,
		SubAgent:      st.subAgent,
		Evidence: model.Evidence{
			ArtifactType: artifactMuseSessionJSONL,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

// museFileContext extracts the root session id, the innermost subagent id (if
// this is a nested subagent transcript), and the stream id this file's own
// records should carry, from a
// sessions/YYYY/MM/DD/<session-id>/(subagent/<id>/)*session.jsonl path. All
// three come back "" when the path does not match that shape; the file is
// still parsed, just without session/subagent attribution.
func museFileContext(path string) (rootSessionID, subAgent, streamID string) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+5 < len(parts); i++ {
		if parts[i] != "sessions" || parts[i+1] == "" || parts[i+2] == "" || parts[i+3] == "" || parts[i+4] == "" {
			continue
		}
		rootSessionID = parts[i+4]
		streamID = rootSessionID
		rest := parts[i+5:]
		for len(rest) >= 3 && rest[0] == "subagent" && rest[1] != "" {
			subAgent = rest[1]
			streamID = subAgent
			rest = rest[2:]
		}
		return rootSessionID, subAgent, streamID
	}
	return "", "", ""
}

func museEventID(path string, line, sub int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, sub))
	return "muse-" + hex.EncodeToString(sum[:8])
}

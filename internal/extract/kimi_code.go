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

// artifactKimiWire is Kimi Code's persisted per-agent journal. The first line
// is metadata; later lines are flat wire operations. Both main and sub-agent
// journals use the same record language.
const artifactKimiWire = "kimi_wire"

const (
	kimiRecordMetadata    = "metadata"
	kimiRecordConfig      = "config.update"
	kimiRecordTurnPrompt  = "turn.prompt"
	kimiRecordAppendMsg   = "context.append_message"
	kimiRecordAppendEvent = "context.append_loop_event"
)

const (
	kimiLoopContentPart = "content.part"
	kimiLoopToolCall    = "tool.call"
	kimiLoopToolResult  = "tool.result"
)

// KimiCodeExtractor parses $KIMI_CODE_HOME/sessions/**/agents/*/wire.jsonl.
// maxBytes is a test seam for the shared production artifact limit.
type KimiCodeExtractor struct {
	maxBytes int
}

func (KimiCodeExtractor) Agent() string { return model.AgentKimiCode }

type kimiWireRecord struct {
	Type            string        `json:"type"`
	Time            int64         `json:"time"`
	ProtocolVersion string        `json:"protocol_version"`
	CreatedAt       int64         `json:"created_at"`
	CWD             string        `json:"cwd"`
	Input           []kimiContent `json:"input"`
	Origin          kimiOrigin    `json:"origin"`
	Event           kimiLoopEvent `json:"event"`
}

type kimiOrigin struct {
	Kind string `json:"kind"`
}

type kimiContent struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Think string `json:"think"`
}

type kimiLoopEvent struct {
	Type       string          `json:"type"`
	Part       kimiContent     `json:"part"`
	ToolCallID string          `json:"toolCallId"`
	Name       string          `json:"name"`
	Args       json.RawMessage `json:"args"`
	Result     kimiToolResult  `json:"result"`
}

type kimiToolResult struct {
	IsError bool `json:"isError"`
}

type kimiState struct {
	sessionID      string
	projectPath    string
	subAgent       string
	startIdx       int
	started        bool
	commandCallIDs map[string]struct{}
	toolNames      map[string]string
}

func newKimiState(path string) *kimiState {
	sessionID, subAgent := kimiPathContext(path)
	return &kimiState{sessionID: sessionID, subAgent: subAgent}
}

func (st *kimiState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCallIDs == nil {
		st.commandCallIDs = map[string]struct{}{}
	}
	st.commandCallIDs[id] = struct{}{}
}

func (st *kimiState) noteToolCall(id, name string) {
	if id == "" || name == "" {
		return
	}
	if st.toolNames == nil {
		st.toolNames = map[string]string{}
	}
	st.toolNames[id] = name
}

func (st *kimiState) toolName(id string) string {
	return st.toolNames[id]
}

func (st *kimiState) isCommandCall(id string) bool {
	_, ok := st.commandCallIDs[id]
	return ok
}

func (e KimiCodeExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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

	res := &Result{}
	st := newKimiState(src.Path)
	sha := model.HashContent(data)
	br := bufio.NewReader(bytes.NewReader(data))
	for line := 1; ; line++ {
		raw, tooLong, readErr := readLine(br)
		if tooLong {
			res.diag(src.Path, line, "line exceeds size cap; skipped")
		} else if raw = bytes.TrimSpace(raw); len(raw) > 0 {
			e.mapLine(res, src, sha, st, line, raw)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return res, nil
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, readErr)
		}
	}
}

func (e KimiCodeExtractor) mapLine(res *Result, src Source, sha string, st *kimiState, line int, raw []byte) {
	var record kimiWireRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	if record.Type == "" {
		res.diag(src.Path, line, "wire record missing type")
		return
	}

	switch record.Type {
	case kimiRecordMetadata:
		if record.ProtocolVersion == "" {
			res.diag(src.Path, line, "malformed wire metadata")
			return
		}
		ev := e.base(src, sha, st, line, epochMillisRFC3339(record.CreatedAt), 0)
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceHigh
		st.startIdx = len(res.Events)
		st.started = true
		res.Events = append(res.Events, ev)
	case kimiRecordConfig:
		st.projectPath = record.CWD
		if st.started && res.Events[st.startIdx].ProjectPath == "" {
			res.Events[st.startIdx].ProjectPath = record.CWD
		}
	case kimiRecordTurnPrompt:
		if record.Origin.Kind != "user" {
			return
		}
		for i, part := range record.Input {
			if part.Type != "text" || strings.TrimSpace(part.Text) == "" {
				continue
			}
			ev := e.base(src, sha, st, line, epochMillisRFC3339(record.Time), i)
			ev.EventType = model.EventPromptUser
			ev.Actor = model.ActorUser
			ev.Confidence = model.ConfidenceHigh
			setMessageContent(&ev, src, part.Text)
			ev.Evidence.JSONPointer = fmt.Sprintf("/input/%d", i)
			res.Events = append(res.Events, ev)
		}
	case kimiRecordAppendEvent:
		e.mapLoopEvent(res, src, sha, st, line, record.Time, &record.Event)
	case kimiRecordAppendMsg:
		// Current Kimi Code persists the user prompt both as turn.prompt and as
		// context.append_message. turn.prompt carries the origin discriminator,
		// so it is the canonical human-input record and this replay copy is not
		// emitted a second time. Assistant/tool output is persisted as loop events.
	default:
		// Other wire operations are state, capability, permission-mode, usage,
		// task, and compaction bookkeeping. They are valid journal language but
		// not direct evidence of an action, so they are intentionally quiet.
	}
}

func (e KimiCodeExtractor) mapLoopEvent(res *Result, src Source, sha string, st *kimiState, line int, ms int64, event *kimiLoopEvent) {
	ts := epochMillisRFC3339(ms)
	switch event.Type {
	case kimiLoopContentPart:
		switch event.Part.Type {
		case "text":
			if strings.TrimSpace(event.Part.Text) == "" {
				return
			}
			ev := e.base(src, sha, st, line, ts, 0)
			ev.EventType = model.EventMessageAssistant
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceHigh
			setMessageContent(&ev, src, event.Part.Text)
			ev.Evidence.JSONPointer = "/event/part"
			res.Events = append(res.Events, ev)
		case "think":
			if !src.IncludeReasoning || strings.TrimSpace(event.Part.Think) == "" {
				return
			}
			ev := e.base(src, sha, st, line, ts, 0)
			ev.EventType = model.EventMessageReasoning
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceHigh
			setMessageContent(&ev, src, event.Part.Think)
			ev.Evidence.JSONPointer = "/event/part"
			res.Events = append(res.Events, ev)
		}
	case kimiLoopToolCall:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = event.Name
		ev.ToolCallID = event.ToolCallID
		ev.Evidence.JSONPointer = "/event"
		classifyKimiTool(&ev, event.Name, event.Args)
		st.noteToolCall(event.ToolCallID, event.Name)
		if ev.EventType == model.EventCommandExec {
			st.noteCommandCall(event.ToolCallID)
		}
		res.Events = append(res.Events, ev)
	case kimiLoopToolResult:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventToolResult
		if st.isCommandCall(event.ToolCallID) {
			ev.EventType = model.EventCommandResult
		}
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = st.toolName(event.ToolCallID)
		ev.ToolCallID = event.ToolCallID
		ev.Evidence.JSONPointer = "/event/result"
		if event.Result.IsError {
			ev.Tags = []string{model.TagToolError}
		}
		res.Events = append(res.Events, ev)
	}
}

func classifyKimiTool(ev *model.Event, name string, raw json.RawMessage) {
	args := map[string]json.RawMessage{}
	_ = json.Unmarshal(raw, &args)
	switch name {
	case "Bash":
		ev.EventType = model.EventCommandExec
		ev.Command = kimiArgString(args, "command")
	case "Read":
		ev.EventType = model.EventFileRead
		ev.FilePath = kimiArgString(args, "path")
	case "Write", "Edit":
		ev.EventType = model.EventFileWrite
		ev.FilePath = kimiArgString(args, "path")
	case "FetchURL":
		ev.EventType = model.EventNetworkIndicator
		rawURL := kimiArgString(args, "url")
		ev.URL = networkTargetURL(rawURL)
		ev.ContentPreview = preview(rawURL)
		ev.Tags = []string{model.TagNetwork}
	default:
		ev.EventType = model.EventToolCall
	}
}

func kimiArgString(args map[string]json.RawMessage, key string) string {
	var value string
	if raw, ok := args[key]; ok {
		_ = json.Unmarshal(raw, &value)
	}
	return value
}

func (KimiCodeExtractor) base(src Source, sha string, st *kimiState, line int, ts string, sub int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       kimiEventID(src.Path, line, sub),
		SourceAgent:   model.AgentKimiCode,
		SourceType:    model.SourceArtifact,
		Timestamp:     ts,
		ProjectPath:   st.projectPath,
		SessionID:     st.sessionID,
		SubAgent:      st.subAgent,
		Evidence: model.Evidence{
			ArtifactType: artifactKimiWire,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

func kimiPathContext(path string) (sessionID, subAgent string) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+5 < len(parts); i++ {
		if parts[i] != "sessions" || parts[i+3] != "agents" || !strings.EqualFold(parts[i+5], "wire.jsonl") {
			continue
		}
		sessionID = parts[i+2]
		if parts[i+4] != "main" {
			subAgent = parts[i+4]
		}
		return sessionID, subAgent
	}
	return "", ""
}

func kimiEventID(path string, line, sub int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, sub))
	return "kimi-" + hex.EncodeToString(sum[:8])
}

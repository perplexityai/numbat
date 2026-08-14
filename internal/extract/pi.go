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
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// artifactPiSession is Pi's versioned JSONL session tree. A session starts with
// a type:"session" header, followed by tree-linked entries. Every branch stays
// in the same artifact, so parsing physical line order preserves the complete
// forensic record rather than selecting only the current leaf.
const artifactPiSession = "pi_session"

const (
	piEntrySession = "session"
	piEntryMessage = "message"
)

const (
	piRoleUser          = "user"
	piRoleAssistant     = "assistant"
	piRoleToolResult    = "toolResult"
	piRoleBashExecution = "bashExecution"
)

const (
	piBlockText     = "text"
	piBlockThinking = "thinking"
	piBlockToolCall = "toolCall"
)

// PiExtractor parses ~/.pi/agent/sessions/**/*.jsonl. maxBytes exists only so
// tests can exercise the production artifact-size boundary cheaply.
type PiExtractor struct {
	maxBytes int
}

func (PiExtractor) Agent() string { return model.AgentPi }

type piEntry struct {
	Type      string    `json:"type"`
	Version   int       `json:"version"`
	ID        string    `json:"id"`
	Timestamp string    `json:"timestamp"`
	CWD       string    `json:"cwd"`
	Message   piMessage `json:"message"`
}

type piMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCallID string          `json:"toolCallId"`
	ToolName   string          `json:"toolName"`
	Command    string          `json:"command"`
	Output     string          `json:"output"`
	ExitCode   *int            `json:"exitCode"`
	IsError    bool            `json:"isError"`
	Timestamp  int64           `json:"timestamp"`
}

type piContentBlock struct {
	Type      string                     `json:"type"`
	Text      string                     `json:"text"`
	Thinking  string                     `json:"thinking"`
	ID        string                     `json:"id"`
	Name      string                     `json:"name"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

type piState struct {
	sessionID      string
	projectPath    string
	commandCallIDs map[string]struct{}
}

func (st *piState) noteCommandCall(id string) {
	if id == "" {
		return
	}
	if st.commandCallIDs == nil {
		st.commandCallIDs = map[string]struct{}{}
	}
	st.commandCallIDs[id] = struct{}{}
}

func (st *piState) isCommandCall(id string) bool {
	_, ok := st.commandCallIDs[id]
	return ok
}

func (e PiExtractor) Extract(r io.Reader, src Source) (*Result, error) {
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
	st := &piState{}
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

func (e PiExtractor) mapLine(res *Result, src Source, sha string, st *piState, line int, raw []byte) {
	var entry piEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}

	switch entry.Type {
	case piEntrySession:
		if entry.ID == "" || entry.Version <= 0 {
			res.diag(src.Path, line, "malformed session header")
			return
		}
		st.sessionID = entry.ID
		st.projectPath = entry.CWD
		ev := e.base(src, sha, st, line, entry.Timestamp, 0)
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceHigh
		res.Events = append(res.Events, ev)
	case piEntryMessage:
		e.mapMessage(res, src, sha, st, line, &entry)
	case "model_change", "thinking_level_change", "compaction", "branch_summary", "custom":
		// Pi's documented context/tree metadata is not an observed action. In
		// particular, compaction and branch summaries are generated summaries;
		// emitting them would duplicate or synthesize evidence from prior rows.
	default:
		res.diag(src.Path, line, "unhandled entry type")
	}
}

func (e PiExtractor) mapMessage(res *Result, src Source, sha string, st *piState, line int, entry *piEntry) {
	ts := entry.Timestamp
	if ts == "" {
		ts = epochMillisRFC3339(entry.Message.Timestamp)
	}
	switch entry.Message.Role {
	case piRoleUser:
		blocks, ok := piContentBlocks(entry.Message.Content)
		if !ok {
			res.diag(src.Path, line, "malformed user message content")
			return
		}
		for i, block := range blocks {
			if block.Type != piBlockText || strings.TrimSpace(block.Text) == "" {
				continue
			}
			ev := e.base(src, sha, st, line, ts, i)
			ev.EventType = model.EventPromptUser
			ev.Actor = model.ActorUser
			ev.Confidence = model.ConfidenceHigh
			setMessageContent(&ev, src, block.Text)
			ev.Evidence.JSONPointer = piContentPointer(entry.Message.Content, i)
			res.Events = append(res.Events, ev)
		}
	case piRoleAssistant:
		blocks, ok := piContentBlocks(entry.Message.Content)
		if !ok {
			res.diag(src.Path, line, "malformed assistant message content")
			return
		}
		for i, block := range blocks {
			e.mapAssistantBlock(res, src, sha, st, line, ts, i, &block)
		}
	case piRoleToolResult:
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventToolResult
		if st.isCommandCall(entry.Message.ToolCallID) {
			ev.EventType = model.EventCommandResult
		}
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = entry.Message.ToolName
		ev.ToolCallID = entry.Message.ToolCallID
		ev.Evidence.JSONPointer = "/message"
		if entry.Message.IsError {
			ev.Tags = []string{model.TagToolError}
		}
		res.Events = append(res.Events, ev)
	case piRoleBashExecution:
		e.mapBashExecution(res, src, sha, st, line, ts, entry)
	default:
		res.diag(src.Path, line, "unhandled message role")
	}
}

func (e PiExtractor) mapAssistantBlock(res *Result, src Source, sha string, st *piState, line int, ts string, idx int, block *piContentBlock) {
	pointer := fmt.Sprintf("/message/content/%d", idx)
	switch block.Type {
	case piBlockText:
		if strings.TrimSpace(block.Text) == "" {
			return
		}
		ev := e.base(src, sha, st, line, ts, idx)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		setMessageContent(&ev, src, block.Text)
		ev.Evidence.JSONPointer = pointer
		res.Events = append(res.Events, ev)
	case piBlockThinking:
		if !src.IncludeReasoning || strings.TrimSpace(block.Thinking) == "" {
			return
		}
		ev := e.base(src, sha, st, line, ts, idx)
		ev.EventType = model.EventMessageReasoning
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		setMessageContent(&ev, src, block.Thinking)
		ev.Evidence.JSONPointer = pointer
		res.Events = append(res.Events, ev)
	case piBlockToolCall:
		ev := e.base(src, sha, st, line, ts, idx)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = block.Name
		ev.ToolCallID = block.ID
		ev.Evidence.JSONPointer = pointer
		classifyPiTool(&ev, block.Name, block.Arguments)
		if ev.EventType == model.EventCommandExec {
			st.noteCommandCall(block.ID)
		}
		res.Events = append(res.Events, ev)
	}
}

func (e PiExtractor) mapBashExecution(res *Result, src Source, sha string, st *piState, line int, ts string, entry *piEntry) {
	if entry.Message.Command != "" {
		ev := e.base(src, sha, st, line, ts, 0)
		ev.EventType = model.EventCommandExec
		ev.Actor = model.ActorUser
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = "bash"
		ev.Command = entry.Message.Command
		ev.Evidence.JSONPointer = "/message/command"
		res.Events = append(res.Events, ev)
	}
	if entry.Message.ExitCode != nil || entry.Message.Output != "" {
		ev := e.base(src, sha, st, line, ts, 1)
		ev.EventType = model.EventCommandResult
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = "bash"
		ev.ExitCode = entry.Message.ExitCode
		ev.Evidence.JSONPointer = "/message"
		if entry.Message.ExitCode != nil && *entry.Message.ExitCode != 0 {
			ev.Tags = []string{model.TagToolError}
		}
		res.Events = append(res.Events, ev)
	}
}

func classifyPiTool(ev *model.Event, name string, args map[string]json.RawMessage) {
	switch name {
	case "bash":
		ev.EventType = model.EventCommandExec
		ev.Command = piArgString(args, "command")
	case "read":
		ev.EventType = model.EventFileRead
		ev.FilePath = piArgString(args, "path")
	case "write", "edit":
		ev.EventType = model.EventFileWrite
		ev.FilePath = piArgString(args, "path")
	default:
		ev.EventType = model.EventToolCall
	}
}

func piArgString(args map[string]json.RawMessage, key string) string {
	var value string
	if raw, ok := args[key]; ok {
		_ = json.Unmarshal(raw, &value)
	}
	return value
}

func piContentBlocks(raw json.RawMessage) ([]piContentBlock, bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return []piContentBlock{{Type: piBlockText, Text: text}}, true
	}
	var blocks []piContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, false
	}
	return blocks, true
}

func piContentPointer(raw json.RawMessage, idx int) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return "/message/content"
	}
	return fmt.Sprintf("/message/content/%d", idx)
}

func (PiExtractor) base(src Source, sha string, st *piState, line int, ts string, sub int) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       piEventID(src.Path, line, sub),
		SourceAgent:   model.AgentPi,
		SourceType:    model.SourceArtifact,
		Timestamp:     ts,
		ProjectPath:   st.projectPath,
		SessionID:     st.sessionID,
		Evidence: model.Evidence{
			ArtifactType: artifactPiSession,
			LocalPath:    src.Path,
			Line:         line,
			SHA256:       sha,
		},
	}
}

func piEventID(path string, line, sub int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, sub))
	return "pi-" + hex.EncodeToString(sum[:8])
}

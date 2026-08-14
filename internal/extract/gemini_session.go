package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// Gemini CLI stores resumable main and subagent sessions under a chats
// directory. Current files are JSONL journals; older releases used one JSON
// object with the same metadata and message shapes.
func isGeminiSessionPath(path string) bool {
	slashed := filepath.ToSlash(path)
	return strings.Contains(slashed, "/chats/") || strings.HasPrefix(slashed, "chats/")
}

type geminiSessionMessage struct {
	ID        string                  `json:"id"`
	Timestamp string                  `json:"timestamp"`
	Type      string                  `json:"type"`
	Content   json.RawMessage         `json:"content"`
	ToolCalls []geminiSessionToolCall `json:"toolCalls"`
	Thoughts  []geminiSessionThought  `json:"thoughts"`
	Model     string                  `json:"model"`
}

type geminiSessionToolCall struct {
	ID            string                     `json:"id"`
	Name          string                     `json:"name"`
	Args          map[string]json.RawMessage `json:"args"`
	Result        json.RawMessage            `json:"result"`
	ResultDisplay json.RawMessage            `json:"resultDisplay"`
	Status        string                     `json:"status"`
	Timestamp     string                     `json:"timestamp"`
	AgentID       string                     `json:"agentId"`
}

type geminiSessionThought struct {
	Subject     string `json:"subject"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

type geminiSessionMessageState struct {
	message geminiSessionMessage
	line    int
	pointer string
	calls   map[string]geminiSessionCallState
	// approvals preserves transient awaiting_approval snapshots when a later
	// journal row replaces the same message with its final tool status.
	approvals map[string]geminiSessionApprovalState
}

type geminiSessionCallState struct {
	tool      geminiSessionToolCall
	line      int
	pointer   string
	timestamp string
}

type geminiSessionApprovalState struct {
	line      int
	pointer   string
	timestamp string
}

type geminiSessionState struct {
	sessionID    string
	startTime    string
	metadataLine int
	metadataPtr  string
	metadataKey  string
	messages     []geminiSessionMessageState
	messageIndex map[string]int
}

func (e GeminiExtractor) extractSession(res *Result, src Source, sha string, data []byte) {
	state := geminiSessionState{}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(trimmed) {
		e.applyGeminiSessionRecord(res, src.Path, &state, trimmed, 1)
	} else {
		for i, line := range bytes.Split(data, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			e.applyGeminiSessionRecord(res, src.Path, &state, line, i+1)
		}
	}

	if state.metadataLine > 0 {
		ev := e.sessionEvent(src, sha, "session", "start", state.metadataLine, state.metadataPtr+"/"+state.metadataKey)
		ev.Timestamp = state.startTime
		ev.SessionID = state.sessionID
		ev.Actor = model.ActorSystem
		ev.EventType = model.EventSessionStart
		res.Events = append(res.Events, ev)
	}
	activityBefore := len(res.Events)
	for _, message := range state.messages {
		e.emitGeminiSessionMessage(res, src, sha, state.sessionID, message)
	}
	if len(res.Events) == activityBefore {
		res.diag(src.Path, 0, "session journal contained no recognized activity")
	}
}

func (e GeminiExtractor) applyGeminiSessionRecord(res *Result, path string, state *geminiSessionState, raw []byte, line int) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		res.diag(path, line, "malformed session journal record")
		return
	}
	if _, ok := fields["$rewindTo"]; ok {
		// A rewind changes resume context, not what already happened. Retain
		// previously observed actions in the forensic timeline.
		return
	}
	if set, ok := fields["$set"]; ok {
		var updates map[string]json.RawMessage
		if json.Unmarshal(set, &updates) != nil {
			res.diag(path, line, "malformed session metadata update")
			return
		}
		e.applyGeminiSessionMetadata(res, path, state, updates, line, "/$set")
		return
	}
	if _, ok := fields["id"]; ok {
		e.applyGeminiSessionMessage(res, path, state, raw, line, "")
		return
	}
	if _, session := fields["sessionId"]; session {
		e.applyGeminiSessionMetadata(res, path, state, fields, line, "")
		return
	}
	res.diag(path, line, "unrecognized session journal record")
}

func (e GeminiExtractor) applyGeminiSessionMetadata(res *Result, path string, state *geminiSessionState, fields map[string]json.RawMessage, line int, pointer string) {
	if raw, ok := fields["sessionId"]; ok {
		_ = json.Unmarshal(raw, &state.sessionID)
	}
	if raw, ok := fields["startTime"]; ok {
		_ = json.Unmarshal(raw, &state.startTime)
	}
	if state.metadataLine == 0 {
		if _, ok := fields["startTime"]; ok {
			state.metadataLine, state.metadataPtr, state.metadataKey = line, pointer, "startTime"
		} else if _, ok := fields["sessionId"]; ok {
			state.metadataLine, state.metadataPtr, state.metadataKey = line, pointer, "sessionId"
		}
	}
	rawMessages, ok := fields["messages"]
	if !ok {
		return
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(rawMessages, &messages); err != nil {
		res.diag(path, line, "malformed messages checkpoint")
		return
	}
	for i, raw := range messages {
		e.applyGeminiSessionMessage(res, path, state, raw, line, fmt.Sprintf("%s/messages/%d", pointer, i))
	}
}

func (GeminiExtractor) applyGeminiSessionMessage(res *Result, path string, state *geminiSessionState, raw []byte, line int, pointer string) {
	var message geminiSessionMessage
	if err := json.Unmarshal(raw, &message); err != nil || message.ID == "" {
		res.diag(path, line, "malformed session message")
		return
	}
	messageState := geminiSessionMessageState{
		message:   message,
		line:      line,
		pointer:   pointer,
		calls:     make(map[string]geminiSessionCallState),
		approvals: make(map[string]geminiSessionApprovalState),
	}
	if state.messageIndex == nil {
		state.messageIndex = make(map[string]int)
	}
	if i, exists := state.messageIndex[message.ID]; exists {
		messageState.calls = state.messages[i].calls
		messageState.approvals = state.messages[i].approvals
		state.messages[i] = messageState
		recordGeminiSessionToolTransitions(&state.messages[i])
		return
	}
	recordGeminiSessionToolTransitions(&messageState)
	state.messageIndex[message.ID] = len(state.messages)
	state.messages = append(state.messages, messageState)
}

func recordGeminiSessionToolTransitions(state *geminiSessionMessageState) {
	for i, tool := range state.message.ToolCalls {
		key := geminiSessionToolKey(tool, i)
		ts := tool.Timestamp
		if ts == "" {
			ts = state.message.Timestamp
		}
		if _, exists := state.calls[key]; !exists {
			state.calls[key] = geminiSessionCallState{
				tool:      tool,
				line:      state.line,
				pointer:   fmt.Sprintf("%s/toolCalls/%d", state.pointer, i),
				timestamp: ts,
			}
		}
		if tool.Status != "awaiting_approval" {
			continue
		}
		if _, exists := state.approvals[key]; exists {
			continue
		}
		state.approvals[key] = geminiSessionApprovalState{
			line:      state.line,
			pointer:   fmt.Sprintf("%s/toolCalls/%d/status", state.pointer, i),
			timestamp: ts,
		}
	}
}

func geminiSessionToolKey(tool geminiSessionToolCall, index int) string {
	if tool.ID != "" {
		return tool.ID
	}
	return fmt.Sprintf("%s:%d", tool.Name, index)
}

func (e GeminiExtractor) emitGeminiSessionMessage(res *Result, src Source, sha, sessionID string, state geminiSessionMessageState) {
	message := state.message
	role := ""
	switch message.Type {
	case "user":
		role = geminiRoleUser
	case "gemini":
		role = geminiRoleModel
	default:
		return
	}

	parts := geminiSessionParts(message.Content)
	for i, part := range parts {
		if strings.TrimSpace(part.Text) == "" {
			continue
		}
		ev := e.sessionEvent(src, sha, message.ID, fmt.Sprintf("text:%d", i), state.line,
			geminiSessionContentPointer(message.Content, state.pointer, i))
		ev.Timestamp, ev.SessionID = message.Timestamp, sessionID
		setMessageContent(&ev, src, strings.TrimSpace(part.Text))
		if role == geminiRoleUser {
			ev.Actor, ev.EventType = model.ActorUser, model.EventPromptUser
		} else {
			ev.Actor, ev.EventType = model.ActorAssistant, model.EventMessageAssistant
		}
		e.stampGeminiSessionModel(&ev, src, message.Model)
		res.Events = append(res.Events, ev)
	}

	if src.fullProfile() {
		for i, thought := range message.Thoughts {
			content := strings.TrimSpace(strings.TrimSpace(thought.Subject+" ") + thought.Description)
			if content == "" {
				continue
			}
			ev := e.sessionEvent(src, sha, message.ID, fmt.Sprintf("thought:%d", i), state.line,
				fmt.Sprintf("%s/thoughts/%d", state.pointer, i))
			ev.Timestamp, ev.SessionID = thought.Timestamp, sessionID
			ev.Actor, ev.EventType = model.ActorAssistant, model.EventMessageReasoning
			setMessageContent(&ev, src, content)
			e.stampGeminiSessionModel(&ev, src, message.Model)
			res.Events = append(res.Events, ev)
		}
	}

	for i := range message.ToolCalls {
		e.emitGeminiSessionTool(res, src, sha, sessionID, message, state, i)
	}
}

func (e GeminiExtractor) emitGeminiSessionTool(res *Result, src Source, sha, sessionID string, message geminiSessionMessage, state geminiSessionMessageState, index int) {
	tool := &message.ToolCalls[index]
	if tool.Name == "" {
		res.diag(src.Path, state.line, "session tool call missing name")
		return
	}
	key := geminiSessionToolKey(*tool, index)
	ptr := fmt.Sprintf("%s/toolCalls/%d", state.pointer, index)
	sourceID := message.ID
	kindSuffix := fmt.Sprintf(":%d", index)
	if tool.ID != "" {
		sourceID += "/" + tool.ID
		kindSuffix = ""
	}
	ts := tool.Timestamp
	if ts == "" {
		ts = message.Timestamp
	}
	first := state.calls[key]
	call := e.sessionEvent(src, sha, sourceID, "tool"+kindSuffix, first.line, first.pointer)
	call.Timestamp, call.SessionID = first.timestamp, sessionID
	call.Actor, call.ToolCallID, call.SubAgent = model.ActorAssistant, first.tool.ID, first.tool.AgentID
	isShell := classifyGeminiTool(&call, &geminiFunctionCall{ID: first.tool.ID, Name: first.tool.Name, Args: first.tool.Args})
	e.stampGeminiSessionModel(&call, src, message.Model)
	res.Events = append(res.Events, call)

	if approval, ok := state.approvals[key]; ok {
		required := true
		ev := e.sessionEvent(src, sha, sourceID, "approval"+kindSuffix, approval.line, approval.pointer)
		ev.Timestamp, ev.SessionID = approval.timestamp, sessionID
		ev.Actor, ev.EventType = model.ActorAssistant, model.EventPermissionRequested
		ev.ToolName, ev.ToolCallID, ev.SubAgent = tool.Name, tool.ID, tool.AgentID
		ev.Decision, ev.ApprovalDecision, ev.ApprovalRequired = model.DecisionAsked, model.DecisionAsked, &required
		e.stampGeminiSessionModel(&ev, src, message.Model)
		res.Events = append(res.Events, ev)
	}
	if tool.Status == "awaiting_approval" {
		return
	}
	if tool.Status != "success" && tool.Status != "error" && tool.Status != "cancelled" {
		return
	}

	result := e.sessionEvent(src, sha, sourceID, "result"+kindSuffix, state.line, ptr+"/result")
	result.Timestamp, result.SessionID = ts, sessionID
	result.Actor, result.ToolName, result.ToolCallID = model.ActorTool, tool.Name, tool.ID
	result.SubAgent = tool.AgentID
	if isShell {
		result.EventType = model.EventCommandResult
		result.Command = geminiArgString(tool.Args, geminiArgCommand)
	} else {
		result.EventType = model.EventToolResult
		if server, name, ok := splitMCPName(tool.Name); ok {
			result.MCPServer, result.MCPTool = server, name
		}
	}
	if tool.Status == "error" {
		result.Tags = append(result.Tags, model.TagToolError)
	}
	if !geminiToolReturnsFileContent(tool.Name) {
		result.ContentPreview = preview(geminiSessionResultPreview(tool.Result, tool.ResultDisplay))
	}
	if response := geminiSessionFunctionResponse(tool.Result, tool.ID, tool.Name); response != nil {
		if code, ok := geminiResponseExitCode(response.Response); ok {
			result.ExitCode = &code
		}
		if geminiResponseHasError(response.Response) && tool.Status != "error" {
			result.Tags = append(result.Tags, model.TagToolError)
		}
	}
	e.stampGeminiSessionModel(&result, src, message.Model)
	res.Events = append(res.Events, result)
}

func geminiSessionParts(raw json.RawMessage) []geminiPart {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var text string
	if json.Unmarshal(trimmed, &text) == nil {
		return []geminiPart{{Text: text}}
	}
	var parts []geminiPart
	if json.Unmarshal(trimmed, &parts) == nil {
		return parts
	}
	var part geminiPart
	if json.Unmarshal(trimmed, &part) == nil {
		return []geminiPart{part}
	}
	return nil
}

func geminiSessionContentPointer(raw json.RawMessage, prefix string, index int) string {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '"' {
		return prefix + "/content"
	}
	return fmt.Sprintf("%s/content/%d/text", prefix, index)
}

func geminiSessionFunctionResponse(raw json.RawMessage, id, name string) *geminiFunctionResponse {
	parts := geminiSessionParts(raw)
	for i := range parts {
		part := &parts[i]
		if part.FunctionResponse == nil {
			continue
		}
		response := part.FunctionResponse
		if (id != "" && response.ID != "" && response.ID != id) ||
			(name != "" && response.Name != "" && response.Name != name) {
			continue
		}
		return response
	}
	return nil
}

func geminiSessionResultPreview(result, display json.RawMessage) string {
	if response := geminiSessionFunctionResponse(result, "", ""); response != nil {
		return geminiResponsePreview(response.Response)
	}
	var texts []string
	for _, part := range geminiSessionParts(result) {
		if text := strings.TrimSpace(part.Text); text != "" {
			texts = append(texts, text)
		}
	}
	if len(texts) > 0 {
		return strings.Join(texts, "\n")
	}
	var text string
	if json.Unmarshal(display, &text) == nil {
		return text
	}
	return ""
}

func (e GeminiExtractor) sessionEvent(src Source, sha, sourceID, kind string, line int, pointer string) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		CaseID:        src.CaseID,
		EventID:       geminiSessionEventID(src.Path, sourceID, kind),
		SourceAgent:   model.AgentGeminiCLI,
		SourceType:    model.SourceArtifact,
		Confidence:    model.ConfidenceHigh,
		Evidence: model.Evidence{
			ArtifactType: artifactGeminiChat,
			LocalPath:    src.Path,
			Line:         line,
			JSONPointer:  pointer,
			SHA256:       sha,
		},
	}
}

func (GeminiExtractor) stampGeminiSessionModel(ev *model.Event, src Source, name string) {
	if src.fullProfile() {
		ev.Model = name
	}
}

func geminiSessionEventID(path, sourceID, kind string) string {
	sum := sha256.Sum256([]byte("session\x00" + path + "\x00" + sourceID + "\x00" + kind))
	return "gemini-" + hex.EncodeToString(sum[:16])
}

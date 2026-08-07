package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// cursorEntry is a tolerant view of one Cursor agent-transcripts JSONL record.
// Cursor's at-rest transcript schema is NOT documented or stable (the records
// are written live and have been observed to carry redacted fields and to vary
// between builds), so every field is decoded defensively across the spelling
// variants seen in practice — mirroring how the live-hook resolver reads a
// loosely-typed Cursor payload rather than binding one rigid schema. Only the
// fields numbat maps are pulled out; anything else is ignored so an unrelated
// schema addition never breaks the parse. No field is synthesized: a value
// absent from the record stays empty.
type cursorEntry struct {
	// Type/Role discriminate the record. Cursor has used both spellings across
	// builds (a "type":"user"/"assistant"/"tool" tag and a message-style "role"),
	// so either is accepted; Type wins when both are present.
	Type string `json:"type"`
	Role string `json:"role"`

	// Identity / context. Each is read across the spellings observed in Cursor
	// transcripts and in its hook payloads; the first non-empty wins via the
	// accessor methods below.
	ID             string `json:"id"`
	BubbleID       string `json:"bubbleId"`
	ConversationID string `json:"conversationId"`
	SessionID      string `json:"sessionId"`
	Timestamp      any    `json:"timestamp"`
	CreatedAt      any    `json:"createdAt"`
	CWD            string `json:"cwd"`
	WorkspacePath  string `json:"workspacePath"`
	ProjectPath    string `json:"projectPath"`

	// Content is the free-text body of a user prompt or assistant message. Cursor
	// encodes it either as a plain string or as an array of typed blocks; the
	// custom unmarshaler below normalizes both, and also lifts any tool-call and
	// tool-result blocks out of an array body into ToolCalls/ToolResult.
	Content cursorContent `json:"content"`
	// Current Cursor builds wrap the same content body in a message object.
	Message cursorMessage `json:"message"`

	// Text is an alternate flat body some records carry instead of content.
	Text string `json:"text"`

	// ToolCalls / ToolResult are the top-level (non-array-content) encodings of a
	// tool invocation and its output. A record may carry a single ToolCall, a
	// list under ToolCalls, or a result under ToolResult/Output; all are decoded
	// tolerantly so a tool invocation surfaces however the build framed it.
	ToolCall   *cursorToolCall  `json:"toolCall"`
	ToolCalls  []cursorToolCall `json:"toolCalls"`
	ToolResult *cursorToolOut   `json:"toolResult"`
	Output     *cursorToolOut   `json:"output"`
}

// cursorMessage is the message envelope used by current Cursor transcripts.
type cursorMessage struct {
	Content cursorContent `json:"content"`
}

func (m *cursorMessage) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw[0] != '{' {
		return nil
	}
	type wire cursorMessage
	return json.Unmarshal(data, (*wire)(m))
}

// cursorContent is the normalized body of a Cursor record. Text holds the
// concatenated plain text; ToolCalls and ToolResults hold any tool-call /
// tool-result blocks lifted out of an array-shaped content body. TextPointer is
// the RFC 6901 pointer to the body in the SOURCE record: "/content" for a plain
// string body, or "/content/<i>" naming the single text block when an array
// body carries exactly one (so a lifted-block body still points at its real
// source location rather than the synthetic concatenation). Message-wrapped
// bodies gain their /message prefix when emitted.
//
// Order records the source-block order of the content[] body so the mapper can
// emit a call before its same-record result. Each element names which bucket
// (text/call/result) the next source block came from; the buckets are consumed
// in lockstep with this order. A plain-string or absent body leaves Order nil.
type cursorContent struct {
	Text        string
	TextPointer string
	ToolCalls   []cursorToolCall
	ToolResults []cursorToolOut
	Order       []cursorBlockKind
}

func (c *cursorContent) hasData() bool {
	return strings.TrimSpace(c.Text) != "" || len(c.ToolCalls) > 0 || len(c.ToolResults) > 0
}

// cursorBlockKind tags one entry in cursorContent.Order with the bucket the
// corresponding source block was lifted into.
type cursorBlockKind uint8

const (
	cursorBlockText cursorBlockKind = iota
	cursorBlockCall
	cursorBlockResult
)

// cursorToolCall is a tolerant view of a tool invocation block. Name and the
// input/args object are read across spellings; CallID correlates the call with
// its later result when the record assigns one. Pointer is the RFC 6901 pointer
// to this call in the SOURCE record (e.g. "/content/2", "/toolCall",
// "/toolCalls/0"); it is set by the accessors/unmarshaler, never decoded from
// the record. Message-wrapped content gains its /message prefix when emitted.
type cursorToolCall struct {
	Type    string                     `json:"type"`
	Name    string                     `json:"name"`
	Tool    string                     `json:"tool"`
	CallID  string                     `json:"callId"`
	ToolID  string                     `json:"toolCallId"`
	ID      string                     `json:"id"`
	Input   map[string]json.RawMessage `json:"input"`
	Args    map[string]json.RawMessage `json:"args"`
	Params  map[string]json.RawMessage `json:"parameters"`
	Pointer string                     `json:"-"`
}

// cursorToolOut is a tolerant view of a tool result block. The exit code and
// error flag are read only when the record carries them structurally; numbat
// never scrapes a prose body for a failure signal or an exit status. Pointer is
// the RFC 6901 pointer to this result in the SOURCE record (e.g. "/content/3",
// "/toolResult", "/output"); like cursorToolCall.Pointer it is assigned during
// normalization, never decoded.
type cursorToolOut struct {
	Type     string `json:"type"`
	CallID   string `json:"callId"`
	ToolID   string `json:"toolCallId"`
	ExitCode *int   `json:"exitCode"`
	ExitAlt  *int   `json:"exit_code"`
	IsError  *bool  `json:"isError"`
	IsErrAlt *bool  `json:"is_error"`
	Status   string `json:"status"`
	Pointer  string `json:"-"`
}

// cursorContentBlock is one block within an array-shaped content body. Cursor
// frames text, tool calls, and tool results as discriminated blocks; the
// type tag selects which shape applies.
type cursorContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`

	Name   string                     `json:"name"`
	Tool   string                     `json:"tool"`
	CallID string                     `json:"callId"`
	ToolID string                     `json:"toolCallId"`
	ID     string                     `json:"id"`
	Input  map[string]json.RawMessage `json:"input"`
	Args   map[string]json.RawMessage `json:"args"`
	Params map[string]json.RawMessage `json:"parameters"`

	ExitCode *int   `json:"exitCode"`
	ExitAlt  *int   `json:"exit_code"`
	IsError  *bool  `json:"isError"`
	IsErrAlt *bool  `json:"is_error"`
	Status   string `json:"status"`
}

// UnmarshalJSON normalizes the two content encodings Cursor emits:
//
//	"content": "a plain prompt"   → Text
//	"content": [ {type:"text"},   → Text concatenated; tool_call/tool_use and
//	             {type:"tool_call"}, ...]  tool_result blocks lifted into the
//	                                       ToolCalls / ToolResults slices
//
// A missing or null content yields an empty body rather than an error, keeping
// the parse tolerant of partial records.
func (c *cursorContent) UnmarshalJSON(b []byte) error {
	raw := strings.TrimSpace(string(b))
	if raw == "" || raw == "null" {
		return nil
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		c.Text = s
		c.TextPointer = "/content"
		return nil
	case '[':
		var blocks []cursorContentBlock
		if err := json.Unmarshal(b, &blocks); err != nil {
			return err
		}
		var text strings.Builder
		textBlocks := 0
		lastTextIdx := -1
		for i := range blocks {
			blk := &blocks[i]
			ptr := fmt.Sprintf("/content/%d", i)
			switch blk.Type {
			case "tool_call", "tool_use", "toolCall", "function_call":
				c.ToolCalls = append(c.ToolCalls, cursorToolCall{
					Type: blk.Type, Name: blk.Name, Tool: blk.Tool,
					CallID: blk.CallID, ToolID: blk.ToolID, ID: blk.ID,
					Input: blk.Input, Args: blk.Args, Params: blk.Params,
					Pointer: ptr,
				})
				c.Order = append(c.Order, cursorBlockCall)
			case "tool_result", "tool_output", "toolResult", "function_call_output":
				c.ToolResults = append(c.ToolResults, cursorToolOut{
					Type: blk.Type, CallID: blk.CallID, ToolID: blk.ToolID,
					ExitCode: blk.ExitCode, ExitAlt: blk.ExitAlt,
					IsError: blk.IsError, IsErrAlt: blk.IsErrAlt, Status: blk.Status,
					Pointer: ptr,
				})
				c.Order = append(c.Order, cursorBlockResult)
			default:
				if s := strings.TrimSpace(blk.Text); s != "" {
					if text.Len() > 0 {
						text.WriteByte(' ')
					}
					text.WriteString(s)
					textBlocks++
					lastTextIdx = i
					c.Order = append(c.Order, cursorBlockText)
				}
			}
		}
		c.Text = text.String()
		// Point at the real source block only when a single text block carries the
		// body; when several are concatenated there is no one source location to
		// name, so fall back to the array container "/content".
		if textBlocks == 1 {
			c.TextPointer = fmt.Sprintf("/content/%d", lastTextIdx)
		} else if textBlocks > 1 {
			c.TextPointer = "/content"
		}
		return nil
	default:
		// A non-string, non-array content (e.g. an object) carries no body numbat
		// maps; leave it empty rather than failing the whole record.
		return nil
	}
}

// kind reports the record's role, preferring the explicit type tag over the
// message-style role and lowercasing so "User"/"USER"/"user" collapse.
func (e *cursorEntry) kind() string {
	if e.Type != "" {
		return strings.ToLower(e.Type)
	}
	return strings.ToLower(e.Role)
}

// sessionID resolves the conversation/session identity across spellings.
func (e *cursorEntry) sessionID() string {
	return firstNonEmpty(e.ConversationID, e.SessionID)
}

// project resolves the working directory / project path across spellings.
func (e *cursorEntry) project() string {
	return firstNonEmpty(e.CWD, e.WorkspacePath, e.ProjectPath)
}

// time resolves the record timestamp. Cursor has written it both as an RFC3339
// string and as a numeric epoch (seconds or milliseconds); a string is returned
// as-is and a number is left untouched only when it is a clean RFC3339 string,
// since numbat's Timestamp field is RFC3339 and a bare epoch number is not one.
// A numeric epoch therefore yields "" rather than a fabricated/format-guessed
// timestamp — the record still lands in artifact order, it just carries no time.
func (e *cursorEntry) time() string {
	if s := timeString(e.Timestamp); s != "" {
		return s
	}
	return timeString(e.CreatedAt)
}

// content returns the record's content body. Older transcripts store it at the
// top level; current builds place it under message.
func (e *cursorEntry) content() *cursorContent {
	if e.Content.hasData() {
		return &e.Content
	}
	return &e.Message.Content
}

// contentPointer maps a normalized content pointer back to its source location.
func (e *cursorEntry) contentPointer(pointer string) string {
	if e.Content.hasData() || (pointer != "/content" && !strings.HasPrefix(pointer, "/content/")) {
		return pointer
	}
	return "/message" + pointer
}

// timeString returns v as a timestamp only when it is already a string; a
// numeric epoch returns "" (see time() for why numbat does not guess a format).
func timeString(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// text returns the record's body, preferring the structured content text over
// the flat Text field, together with the RFC 6901 pointer to it in the SOURCE
// record. Content pointers reflect either the top-level or message-wrapped body;
// the flat fallback points at "/text".
func (e *cursorEntry) text() (string, string) {
	content := e.content()
	if s := strings.TrimSpace(content.Text); s != "" {
		return s, e.contentPointer(content.TextPointer)
	}
	if s := strings.TrimSpace(e.Text); s != "" {
		return s, "/text"
	}
	return "", ""
}

// toolCalls returns every tool invocation the record carries, gathered from the
// array-content blocks, the top-level toolCalls list, and a single top-level
// toolCall, in that order. Content-block pointers are adjusted at emission; the
// top-level list points at "/toolCalls/<i>", and a lone call at "/toolCall".
func (e *cursorEntry) toolCalls() []cursorToolCall {
	var calls []cursorToolCall
	calls = append(calls, e.content().ToolCalls...)
	for i := range e.ToolCalls {
		tc := e.ToolCalls[i]
		tc.Pointer = fmt.Sprintf("/toolCalls/%d", i)
		calls = append(calls, tc)
	}
	if e.ToolCall != nil {
		tc := *e.ToolCall
		tc.Pointer = "/toolCall"
		calls = append(calls, tc)
	}
	return calls
}

// topLevelCalls returns only the calls framed at the top level of the record
// (the toolCalls list and a lone toolCall), each stamped with its source pointer.
// Content-embedded calls are walked separately in source order by mapLine.
func (e *cursorEntry) topLevelCalls() []cursorToolCall {
	var calls []cursorToolCall
	for i := range e.ToolCalls {
		tc := e.ToolCalls[i]
		tc.Pointer = fmt.Sprintf("/toolCalls/%d", i)
		calls = append(calls, tc)
	}
	if e.ToolCall != nil {
		tc := *e.ToolCall
		tc.Pointer = "/toolCall"
		calls = append(calls, tc)
	}
	return calls
}

// topLevelResults returns only the results framed at the top level of the record
// (toolResult and output), each stamped with its source pointer. Content-embedded
// results are walked separately in source order by mapLine.
func (e *cursorEntry) topLevelResults() []cursorToolOut {
	var outs []cursorToolOut
	if e.ToolResult != nil {
		to := *e.ToolResult
		to.Pointer = "/toolResult"
		outs = append(outs, to)
	}
	if e.Output != nil {
		to := *e.Output
		to.Pointer = "/output"
		outs = append(outs, to)
	}
	return outs
}

// name resolves the invoked tool's name across spellings.
func (tc *cursorToolCall) name() string { return firstNonEmpty(tc.Name, tc.Tool) }

// callID resolves the tool call's correlation id across spellings.
func (tc *cursorToolCall) callID() string { return firstNonEmpty(tc.CallID, tc.ToolID, tc.ID) }

// input resolves the tool's argument object across spellings, returning the
// first non-empty of input/args/parameters.
func (tc *cursorToolCall) input() map[string]json.RawMessage {
	for _, m := range []map[string]json.RawMessage{tc.Input, tc.Args, tc.Params} {
		if len(m) > 0 {
			return m
		}
	}
	return nil
}

// callID resolves the result's correlation id across spellings.
func (to *cursorToolOut) callID() string { return firstNonEmpty(to.CallID, to.ToolID) }

// exitCode returns the structured process exit code, or nil when the record
// carries none (so a clean exit 0 stays distinct from absent). It is read only
// from a structured field, never scraped from output text.
func (to *cursorToolOut) exitCode() *int {
	if to.ExitCode != nil {
		return to.ExitCode
	}
	return to.ExitAlt
}

// errored reports whether the result is structurally marked as a failure: an
// is_error flag, or a status of "error". A non-zero exit code alone is NOT
// treated as an error here (a command may exit non-zero by design and still be
// a clean record); the exit code rides on the command.result for a rule to
// judge. This mirrors the explicit-only failure policy the other parsers use.
func (to *cursorToolOut) errored() bool {
	if to.IsError != nil {
		return *to.IsError
	}
	if to.IsErrAlt != nil {
		return *to.IsErrAlt
	}
	return strings.EqualFold(strings.TrimSpace(to.Status), "error")
}

// eventID returns a stable, unique id for an event derived from this record.
// One record can emit several events (a message plus tool calls), so the block
// index is folded in. A record id is used when present; otherwise the artifact
// path and line stand in so ids stay deterministic and reproducible.
func (e *cursorEntry) eventID(path string, line, block int) string {
	if id := firstNonEmpty(e.ID, e.BubbleID); id != "" {
		return fmt.Sprintf("%s#%d", id, block)
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, block))
	return "cursor-" + hex.EncodeToString(sum[:8])
}

// firstNonEmpty returns the first non-empty, trimmed string among its args.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

// cursorInputString returns the string value of a tool input field, coercing a
// JSON number to its string form so a numeric argument is not silently dropped.
// It returns "" when the field is absent or not a scalar.
func cursorInputString(input map[string]json.RawMessage, key string) string {
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

// cursorFirstInputString returns the first non-empty string among the given
// input keys, in order.
func cursorFirstInputString(input map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := cursorInputString(input, k); s != "" {
			return s
		}
	}
	return ""
}

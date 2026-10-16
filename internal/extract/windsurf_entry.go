package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// windsurfEntry is a tolerant view of one Windsurf (Cascade) at-rest transcript
// record (~/.windsurf/transcripts/<trajectory_id>.jsonl, one JSON object per
// line, written by Windsurf's post_cascade_response_with_transcript hook).
//
// Windsurf's at-rest transcript schema is NOT documented or stable: the records
// are written live and have varied between builds, so every field is decoded
// defensively across the spelling variants seen in practice — mirroring how the
// live-hook resolver reads a loosely-typed Windsurf payload rather than binding
// one rigid schema. Only the fields numbat maps are pulled out; anything else is
// ignored so an unrelated schema addition never breaks the parse. No field is
// synthesized: a value absent from the record stays empty.
type windsurfEntry struct {
	// Type/Role discriminate the record. Windsurf has used both a "role" tag
	// (user/assistant) and a "type" tag across builds, so either is accepted;
	// Type wins when both are present.
	Type string `json:"type"`
	Role string `json:"role"`

	// Identity / context. Windsurf keys the transcript file by trajectory id and
	// stamps the record with the cascade/trajectory id and the active workspace;
	// each is read across the spellings observed, first non-empty winning.
	ID            string `json:"id"`
	MessageID     string `json:"messageId"`
	TrajectoryID  string `json:"trajectoryId"`
	CascadeID     string `json:"cascadeId"`
	ConversAll    string `json:"conversationId"`
	Timestamp     any    `json:"timestamp"`
	CreatedAt     any    `json:"createdAt"`
	CWD           string `json:"cwd"`
	WorkspacePath string `json:"workspacePath"`
	ProjectPath   string `json:"projectPath"`

	// Content is the free-text body of a user prompt or assistant message. Windsurf
	// encodes it either as a plain string or as an array of typed blocks; the
	// custom unmarshaler normalizes both and lifts any tool-call / tool-result
	// blocks out of an array body into ToolCalls / ToolResults.
	Content windsurfContent `json:"content"`

	// Text is an alternate flat body some records carry instead of content.
	Text string `json:"text"`

	// ToolCall(s) / ToolResult / Output are the top-level (non-array-content)
	// encodings of a tool invocation and its output. A record may carry a single
	// toolCall, a list under toolCalls, or a result under toolResult/output; all
	// are decoded tolerantly so a tool invocation surfaces however the build
	// framed it.
	ToolCall   *windsurfToolCall  `json:"toolCall"`
	ToolCalls  []windsurfToolCall `json:"toolCalls"`
	ToolResult *windsurfToolOut   `json:"toolResult"`
	Output     *windsurfToolOut   `json:"output"`
}

// windsurfContent is the normalized body of a Windsurf record. Text holds the
// concatenated plain text; ToolCalls and ToolResults hold any tool-call /
// tool-result blocks lifted out of an array-shaped content body. TextPointer is
// the RFC 6901 pointer to the body in the SOURCE record: "/content" for a plain
// string body, or "/content/<i>" naming the single text block when an array
// body carries exactly one. Order records the source-block order so the mapper
// can emit a call before its same-record result.
type windsurfContent struct {
	Text        string
	TextPointer string
	ToolCalls   []windsurfToolCall
	ToolResults []windsurfToolOut
	Order       []windsurfBlockKind
}

// windsurfBlockKind tags one entry in windsurfContent.Order with the bucket the
// corresponding source block was lifted into.
type windsurfBlockKind uint8

const (
	windsurfBlockText windsurfBlockKind = iota
	windsurfBlockCall
	windsurfBlockResult
)

// windsurfToolCall is a tolerant view of a tool invocation block. Name and the
// input/args object are read across spellings; CallID correlates the call with
// its later result when the record assigns one. Pointer is the RFC 6901 pointer
// to this call in the SOURCE record (e.g. "/content/2", "/toolCall",
// "/toolCalls/0"); it is set by the accessors/unmarshaler, never decoded from
// the record, so the emitted evidence reference is always source-faithful.
type windsurfToolCall struct {
	Type    string                     `json:"type"`
	Name    string                     `json:"name"`
	Tool    string                     `json:"tool"`
	Action  string                     `json:"action"`
	CallID  string                     `json:"callId"`
	ToolID  string                     `json:"toolCallId"`
	ID      string                     `json:"id"`
	Input   map[string]json.RawMessage `json:"input"`
	Args    map[string]json.RawMessage `json:"args"`
	Params  map[string]json.RawMessage `json:"parameters"`
	Pointer string                     `json:"-"`
}

// windsurfToolOut is a tolerant view of a tool result block. The exit code and
// error flag are read only when the record carries them structurally; numbat
// never scrapes a prose body for a failure signal or an exit status. Pointer is
// the RFC 6901 pointer to this result in the SOURCE record (e.g. "/content/3",
// "/toolResult", "/output"); like windsurfToolCall.Pointer it is assigned during
// normalization, never decoded.
type windsurfToolOut struct {
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

// windsurfContentBlock is one block within an array-shaped content body. Windsurf
// frames text, tool calls, and tool results as discriminated blocks; the type
// tag selects which shape applies.
type windsurfContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`

	Name   string                     `json:"name"`
	Tool   string                     `json:"tool"`
	Action string                     `json:"action"`
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

// UnmarshalJSON normalizes the two content encodings Windsurf emits:
//
//	"content": "a plain prompt"   → Text
//	"content": [ {type:"text"},   → Text concatenated; tool_call/tool_use and
//	             {type:"tool_call"}, ...]  tool_result blocks lifted into the
//	                                       ToolCalls / ToolResults slices
//
// A missing or null content yields an empty body rather than an error, keeping
// the parse tolerant of partial records.
func (c *windsurfContent) UnmarshalJSON(b []byte) error {
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
		var blocks []windsurfContentBlock
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
				c.ToolCalls = append(c.ToolCalls, windsurfToolCall{
					Type: blk.Type, Name: blk.Name, Tool: blk.Tool, Action: blk.Action,
					CallID: blk.CallID, ToolID: blk.ToolID, ID: blk.ID,
					Input: blk.Input, Args: blk.Args, Params: blk.Params,
					Pointer: ptr,
				})
				c.Order = append(c.Order, windsurfBlockCall)
			case "tool_result", "tool_output", "toolResult", "function_call_output":
				c.ToolResults = append(c.ToolResults, windsurfToolOut{
					Type: blk.Type, CallID: blk.CallID, ToolID: blk.ToolID,
					ExitCode: blk.ExitCode, ExitAlt: blk.ExitAlt,
					IsError: blk.IsError, IsErrAlt: blk.IsErrAlt, Status: blk.Status,
					Pointer: ptr,
				})
				c.Order = append(c.Order, windsurfBlockResult)
			default:
				if s := strings.TrimSpace(blk.Text); s != "" {
					if text.Len() > 0 {
						text.WriteByte(' ')
					}
					text.WriteString(s)
					textBlocks++
					lastTextIdx = i
					c.Order = append(c.Order, windsurfBlockText)
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
func (e *windsurfEntry) kind() string {
	if e.Type != "" {
		return strings.ToLower(e.Type)
	}
	return strings.ToLower(e.Role)
}

// sessionID resolves the trajectory/cascade/conversation identity across
// spellings.
func (e *windsurfEntry) sessionID() string {
	return firstNonEmpty(e.TrajectoryID, e.CascadeID, e.ConversAll)
}

// project resolves the working directory / workspace path across spellings.
func (e *windsurfEntry) project() string {
	return firstNonEmpty(e.CWD, e.WorkspacePath, e.ProjectPath)
}

// time resolves the record timestamp. Windsurf has written it both as an RFC3339
// string and as a numeric epoch; only a string is returned (as-is), since
// numbat's Timestamp field is RFC3339 and a bare epoch number is not one. A
// numeric epoch therefore yields "" rather than a fabricated/format-guessed
// timestamp — the record still lands in artifact order, it just carries no time.
func (e *windsurfEntry) time() string {
	if s := timeString(e.Timestamp); s != "" {
		return s
	}
	return timeString(e.CreatedAt)
}

// text returns the record's body, preferring the structured content text over
// the flat Text field, together with the RFC 6901 pointer to it in the SOURCE
// record. The content body points at "/content" or "/content/<i>" (set by the
// unmarshaler); the flat fallback points at "/text".
func (e *windsurfEntry) text() (string, string) {
	if s := strings.TrimSpace(e.Content.Text); s != "" {
		return s, e.Content.TextPointer
	}
	if s := strings.TrimSpace(e.Text); s != "" {
		return s, "/text"
	}
	return "", ""
}

// toolCalls returns every tool invocation the record carries, gathered from the
// array-content blocks, the top-level toolCalls list, and a single top-level
// toolCall, in that order. Each call carries its source pointer.
func (e *windsurfEntry) toolCalls() []windsurfToolCall {
	var calls []windsurfToolCall
	calls = append(calls, e.Content.ToolCalls...)
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
func (e *windsurfEntry) topLevelCalls() []windsurfToolCall {
	var calls []windsurfToolCall
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
func (e *windsurfEntry) topLevelResults() []windsurfToolOut {
	var outs []windsurfToolOut
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
func (tc *windsurfToolCall) name() string { return firstNonEmpty(tc.Name, tc.Tool, tc.Action) }

// callID resolves the tool call's correlation id across spellings.
func (tc *windsurfToolCall) callID() string { return firstNonEmpty(tc.CallID, tc.ToolID, tc.ID) }

// input resolves the tool's argument object across spellings, returning the
// first present object of input/args/parameters.
func (tc *windsurfToolCall) input() map[string]json.RawMessage {
	for _, m := range []map[string]json.RawMessage{tc.Input, tc.Args, tc.Params} {
		if m != nil {
			return m
		}
	}
	return nil
}

// callID resolves the result's correlation id across spellings.
func (to *windsurfToolOut) callID() string { return firstNonEmpty(to.CallID, to.ToolID) }

// exitCode returns the structured process exit code, or nil when the record
// carries none (so a clean exit 0 stays distinct from absent). It is read only
// from a structured field, never scraped from output text.
func (to *windsurfToolOut) exitCode() *int {
	if to.ExitCode != nil {
		return to.ExitCode
	}
	return to.ExitAlt
}

// errored reports whether the result is structurally marked as a failure: an
// is_error flag, or a status of "error". A non-zero exit code alone is NOT
// treated as an error here (a command may exit non-zero by design); the exit
// code rides on the command.result for a rule to judge. This mirrors the
// explicit-only failure policy the other parsers use.
func (to *windsurfToolOut) errored() bool {
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
func (e *windsurfEntry) eventID(path string, line, block int) string {
	if id := firstNonEmpty(e.ID, e.MessageID); id != "" {
		return fmt.Sprintf("%s#%d", id, block)
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d:%d", path, line, block))
	return "windsurf-" + hex.EncodeToString(sum[:8])
}

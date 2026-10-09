package model

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"unicode/utf8"
)

// ToolPayloadMaxBytes matches the maximum supported JSONL record size.
const ToolPayloadMaxBytes = 16 << 20

// toolPayload keeps the original JSON representation out of default marshaling.
// Source readers and this bound cap memory; the rule engine also caps CEL cost.
type toolPayload struct {
	text      string
	bytes     int
	truncated bool
}

func captureToolPayload(value any) toolPayload {
	if value == nil {
		return toolPayload{}
	}
	v := reflect.ValueOf(value)
	if (v.Kind() == reflect.Map || v.Kind() == reflect.Slice || v.Kind() == reflect.Pointer) && v.IsNil() {
		return toolPayload{}
	}
	var raw []byte
	var err error
	if b, ok := value.(json.RawMessage); ok {
		if len(b) == 0 {
			return toolPayload{}
		}
		raw = b
	} else {
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(value)
		raw = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	if err != nil {
		return toolPayload{text: "[payload unavailable: encoding error]", truncated: true}
	}
	text, truncated := LimitToolPayload(string(raw))
	return toolPayload{text: text, bytes: len(raw), truncated: truncated}
}

// SetToolInput retains the source arguments, including unknown keys, for rules
// and explicit content output. JSON input is passed as json.RawMessage; a Go
// string remains a JSON string, even if it happens to contain JSON syntax.
func (e *Event) SetToolInput(value any) {
	e.ToolInput, e.ToolInputBytes, e.ToolInputTruncated = "", 0, false
	e.toolInput = captureToolPayload(value)
}

// SetToolResult retains the source result with the same contract as SetToolInput.
func (e *Event) SetToolResult(value any) {
	e.ToolResult, e.ToolResultBytes, e.ToolResultTruncated = "", 0, false
	e.toolResult = captureToolPayload(value)
}

// CopyToolContentFrom shares immutable retained payloads when one source call
// expands into several normalized actions, avoiding a body copy per file.
func (e *Event) CopyToolContentFrom(source Event) {
	e.toolInput, e.toolResult = source.toolInput, source.toolResult
	e.ToolInput, e.ToolInputBytes, e.ToolInputTruncated = source.ToolInput, source.ToolInputBytes, source.ToolInputTruncated
	e.ToolResult, e.ToolResultBytes, e.ToolResultTruncated = source.ToolResult, source.ToolResultBytes, source.ToolResultTruncated
}

func (e Event) ToolInputForAnalysis() string {
	if e.toolInput.text != "" {
		return e.toolInput.text
	}
	return e.ToolInput
}

func (e Event) ToolInputBytesForAnalysis() int {
	if e.toolInput.text != "" {
		return e.toolInput.bytes
	}
	return e.ToolInputBytes
}

func (e Event) ToolInputTruncatedForAnalysis() bool {
	return e.toolInput.truncated || e.ToolInputTruncated
}

func (e Event) ToolResultForAnalysis() string {
	if e.toolResult.text != "" {
		return e.toolResult.text
	}
	return e.ToolResult
}

func (e Event) ToolResultBytesForAnalysis() int {
	if e.toolResult.text != "" {
		return e.toolResult.bytes
	}
	return e.ToolResultBytes
}

func (e Event) ToolResultTruncatedForAnalysis() bool {
	return e.toolResult.truncated || e.ToolResultTruncated
}

// LimitToolPayload retains a valid UTF-8 prefix and explicitly marks omission.
func LimitToolPayload(text string) (string, bool) {
	if len(text) <= ToolPayloadMaxBytes {
		return text, false
	}
	end := ToolPayloadMaxBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return strings.Clone(text[:end]), true
}

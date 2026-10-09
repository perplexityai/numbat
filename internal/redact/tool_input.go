package redact

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

const (
	toolInputMaxBytes = 64 * 1024
	toolInputOmitted  = "[tool input omitted: size limit]"
)

// ToolInputPreview masks credentials before truncation, while complete values
// can still be recognized. It never retains the input for full-content output.
func ToolInputPreview(input any) (string, bool) {
	var raw []byte
	switch v := input.(type) {
	case nil:
		return "", false
	case string:
		if len(v) > toolInputMaxBytes {
			return toolInputOmitted, true
		}
		raw = []byte(v)
	case json.RawMessage:
		raw = v
	default:
		var err error
		raw, err = json.Marshal(input)
		if err != nil {
			return "", true
		}
	}
	if len(raw) > toolInputMaxBytes {
		return toolInputOmitted, true
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	var text string
	if json.Valid(raw) {
		masked, err := JSON(raw)
		if err != nil {
			return "", true
		}
		if raw[0] == '"' {
			if err := json.Unmarshal(masked, &text); err != nil {
				return "", true
			}
		} else {
			text = string(masked)
		}
	} else if raw[0] == '{' || raw[0] == '[' || raw[0] == '"' {
		return "", true // Damaged JSON cannot be safely masked by field name.
	} else {
		text = String(string(raw))
	}
	text = strings.Join(strings.Fields(strings.ToValidUTF8(text, "\uFFFD")), " ")
	preview := model.NormalizeContentPreview(text)
	truncated := preview != text
	if preview == "" && truncated {
		preview = "[tool input omitted: preview limit]"
	}
	return preview, truncated
}

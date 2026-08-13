package model

import (
	"strings"
	"unicode/utf8"
)

// ContentPreviewMaxRunes bounds normalized content excerpts.
const ContentPreviewMaxRunes = 200

// ContentMaxBytes bounds a message body retained for local analysis or
// explicit full-content output.
const ContentMaxBytes = 1 << 20

// NormalizeContentPreview collapses whitespace and keeps only complete tokens
// within the limit. It is used for generic context that may feed indicator
// extraction, where cutting a token could fabricate a domain, hash, or address.
func NormalizeContentPreview(s string) string {
	preview, _ := normalizeContentPreview(s, false)
	return preview
}

// NormalizeContentPreviewWithTruncation returns the normalized preview and
// whether text was omitted. If the first token crosses the limit, it retains a
// rune-safe prefix instead of dropping the entire preview.
func NormalizeContentPreviewWithTruncation(s string) (string, bool) {
	return normalizeContentPreview(s, true)
}

func normalizeContentPreview(s string, keepLongPrefix bool) (string, bool) {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) <= ContentPreviewMaxRunes {
		return s, false
	}
	if runes[ContentPreviewMaxRunes] == ' ' {
		return string(runes[:ContentPreviewMaxRunes]), true
	}
	for i := ContentPreviewMaxRunes - 1; i >= 0; i-- {
		if runes[i] == ' ' {
			return string(runes[:i]), true
		}
	}
	if keepLongPrefix {
		return string(runes[:ContentPreviewMaxRunes]), true
	}
	return "", true
}

// LimitContent returns valid UTF-8 no larger than ContentMaxBytes and reports
// whether bytes were omitted.
func LimitContent(s string) (string, bool) {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= ContentMaxBytes {
		return s, false
	}
	end := ContentMaxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return strings.Clone(s[:end]), true
}

package model

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeContentPreview(t *testing.T) {
	exact := strings.Repeat("x", ContentPreviewMaxRunes)
	tests := map[string]struct {
		input string
		want  string
	}{
		"short normalized":   {"first\n  second", "first second"},
		"exact token":        {exact + " trailing", exact},
		"partial token":      {"prefix " + strings.Repeat("x", ContentPreviewMaxRunes), "prefix"},
		"only long token":    {strings.Repeat("x", ContentPreviewMaxRunes+1), ""},
		"multibyte boundary": {strings.Repeat("世 ", ContentPreviewMaxRunes), strings.TrimSpace(strings.Repeat("世 ", 100))},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := NormalizeContentPreview(tc.input)
			if got != tc.want {
				t.Fatalf("preview = %q, want %q", got, tc.want)
			}
			if !utf8.ValidString(got) || len([]rune(got)) > ContentPreviewMaxRunes {
				t.Fatalf("preview is invalid or over limit: %q", got)
			}
		})
	}
}

func TestEventAnalysisContentIsNotSerialized(t *testing.T) {
	var ev Event
	ev.SetContent("preview "+strings.Repeat("x", ContentPreviewMaxRunes)+" secret-tail", true)
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-tail") {
		t.Fatalf("analysis content leaked into JSON: %s", b)
	}
	if !strings.Contains(ev.ContentForAnalysis(), "secret-tail") {
		t.Fatal("analysis content was not retained")
	}
}

func TestNormalizeContentPreviewReportsTruncation(t *testing.T) {
	if got, truncated := NormalizeContentPreviewWithTruncation("short"); got != "short" || truncated {
		t.Fatalf("short = %q/%t, want short/false", got, truncated)
	}
	long := strings.Repeat("x", ContentPreviewMaxRunes+1)
	if got, truncated := NormalizeContentPreviewWithTruncation(long); got != long[:ContentPreviewMaxRunes] || !truncated {
		t.Fatalf("long = %q/%t, want bounded/true", got, truncated)
	}
}

func TestLimitContentPreservesUTF8Boundary(t *testing.T) {
	raw := strings.Repeat("x", ContentMaxBytes-1) + "世"
	got, truncated := LimitContent(raw)
	if !truncated || len(got) > ContentMaxBytes || !utf8.ValidString(got) {
		t.Fatalf("LimitContent = %d bytes valid=%t truncated=%t", len(got), utf8.ValidString(got), truncated)
	}
}

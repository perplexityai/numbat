package redact

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestToolInputPreview(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input any
		want  string
	}{
		{"absent", nil, ""},
		{"null", json.RawMessage(`null`), ""},
		{"object", map[string]any{"url": "https://example.com", "action": "navigate"}, `{"action":"navigate","url":"https://example.com"}`},
		{"encoded", ` { "url": "https://example.com", "action": "navigate" } `, `{"action":"navigate","url":"https://example.com"}`},
		{"raw", json.RawMessage(`{"id":9007199254740993}`), `{"id":9007199254740993}`},
		{"text", "SELECT\n  1", "SELECT 1"},
		{"string", `"SELECT 1"`, "SELECT 1"},
		{"broken JSON", `{"password":"unfinished`, ""},
		{"trailing data", `{"password":"secret"} tail`, ""},
		{"credentials", `{"password":"a\"b","nested":{"api_key":["secret"]},"headers":{"Authorization":"Basic private","Cookie":"session=value"}}`, `{"headers":{"Authorization":"[redacted]","Cookie":"[redacted]"},"nested":{"api_key":"[redacted]"},"password":"[redacted]"}`},
		{"escaped key", `{"pass\u0077ord":"private"}`, `{"password":"[redacted]"}`},
		{"array", `[{"token":"secret"},{"query":"docs"}]`, `[{"token":"[redacted]"},{"query":"docs"}]`},
		{"URL credential", `{"url":"https://example.com/?token=private"}`, `{"url":"https://example.com/?token=[redacted]"}`},
		{"UTF-8", strings.Repeat("界", 300), "[tool input omitted: preview limit]"},
		{"invalid UTF-8", "a\xffb", "a\uFFFDb"},
		{"oversize", strings.Repeat("x", toolInputMaxBytes+1), toolInputOmitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := ToolInputPreview(tc.input); got != tc.want {
				t.Fatalf("preview = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestToolInputPreviewMasksBeforeTruncation(t *testing.T) {
	for _, input := range []any{
		strings.Repeat("x", 195) + " sk-abcdefghijklmnopqrstuvwxyz0123456789",
		map[string]any{"password": strings.Repeat("private", 100)},
		map[string]any{"note": strings.Repeat("界", 180) + " sk-abcdefghijklmnopqrstuvwxyz0123456789"},
	} {
		got, _ := ToolInputPreview(input)
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > 200 {
			t.Fatalf("invalid preview: %q", got)
		}
		if strings.Contains(got, "sk-") || strings.Contains(got, "private") {
			t.Fatalf("secret fragment survived: %q", got)
		}
	}
}

func TestToolInputPreviewDoesNotMutateInput(t *testing.T) {
	input := map[string]any{"password": "private", "nested": []any{map[string]any{"token": "private"}}}
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ToolInputPreview(input)
	after, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("input changed")
	}
}

func FuzzToolInputPreview(f *testing.F) {
	for _, seed := range []string{`{"password":"a\"b"}`, `{"code":"await tab.goto(url)"}`, "SELECT 1", "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, _ := ToolInputPreview(s)
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > 200 {
			t.Fatalf("invalid preview: %q", got)
		}
	})
}

func TestToolInputPreviewTruncation(t *testing.T) {
	prefix := strings.Repeat("x", 180)
	for _, tc := range []struct {
		input     string
		want      string
		truncated bool
	}{
		{`{"query":"docs"}`, `{"query":"docs"}`, false},
		{prefix + " https://example.com/long-path", prefix, true},
		{strings.Repeat("x", 201), "[tool input omitted: preview limit]", true},
		{strings.Repeat("x", toolInputMaxBytes+1), toolInputOmitted, true},
		{`{"password":"unfinished`, "", true},
		{`{"input_tokens":42}`, `{"input_tokens":42}`, false},
	} {
		got, truncated := ToolInputPreview(tc.input)
		if got != tc.want || truncated != tc.truncated {
			t.Fatalf("preview = %q/%t, want %q/%t", got, truncated, tc.want, tc.truncated)
		}
	}
}

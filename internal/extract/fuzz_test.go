package extract

import (
	"strings"
	"testing"
)

// extractSeeds are short, varied artifact bodies fed to every parser: a couple
// of well-formed transcript lines, then malformed, truncated, and hostile
// shapes. Each parser must treat any of them as tolerable input and never
// panic — a malformed record becomes a Diagnostic, not a crash.
var extractSeeds = []string{
	"",
	"\n",
	"{",
	"not json at all",
	"{}",
	`{"type":"user"}`,
	`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}}`,
	`{"timestamp":"2026-06-02T10:00:00Z","type":"session_meta","payload":{"id":"t1","cwd":"/p"}}`,
	`{"sessionId":"s","projectHash":"h","kind":"main"}`,
	"{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n{truncated",
	"\x00\x01\x02\xff",
}

// fuzzExtractor feeds f's corpus to one extractor and asserts it never panics.
// The Source carries only metadata; the parser reads bytes from the reader.
func fuzzExtractor(f *testing.F, e Extractor) {
	for _, s := range extractSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		// A malformed artifact must yield a Result+Diagnostics or a read
		// error, never a panic.
		_, _ = e.Extract(strings.NewReader(body), Source{Path: "/fuzz/artifact"})
	})
}

func FuzzClaudeExtract(f *testing.F) { fuzzExtractor(f, ClaudeExtractor{}) }

func FuzzCodexExtract(f *testing.F) {
	f.Add(promptRetractionHistory)
	fuzzExtractor(f, CodexExtractor{})
}

func FuzzGeminiExtract(f *testing.F) { fuzzExtractor(f, GeminiExtractor{}) }

func FuzzGeminiSessionExtract(f *testing.F) {
	for _, seed := range extractSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		_, _ = (GeminiExtractor{}).Extract(strings.NewReader(body), Source{Path: "/fuzz/.gemini/tmp/p/chats/session.jsonl"})
	})
}

func FuzzCursorExtract(f *testing.F) { fuzzExtractor(f, CursorExtractor{}) }

func FuzzWindsurfExtract(f *testing.F) { fuzzExtractor(f, WindsurfExtractor{}) }

func FuzzOpenCodeExtract(f *testing.F) { fuzzExtractor(f, OpenCodeExtractor{}) }

func FuzzOpenClawExtract(f *testing.F) { fuzzExtractor(f, OpenClawExtractor{}) }

func FuzzPiExtract(f *testing.F) { fuzzExtractor(f, PiExtractor{}) }

func FuzzKimiCodeExtract(f *testing.F) { fuzzExtractor(f, KimiCodeExtractor{}) }

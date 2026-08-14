package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/discover"
	"github.com/perplexityai/numbat/internal/extract"
)

// TestTimelineReadArtifactRecoversFromParserPanic proves timeline's parse step
// shares scan's panic fence: a parser that panics on adversarial input becomes a
// stderr diagnostic and an ok=false skip — the call returns cleanly instead of
// crashing the run. It reuses the package-local panicExtractor (scan_test.go) and
// overrides the timeline extractor seam to route to it.
func TestTimelineReadArtifactRecoversFromParserPanic(t *testing.T) {
	prev := timelineExtractorFor
	timelineExtractorFor = func(agent string) (extract.Extractor, bool) {
		if agent == "panic-agent" {
			return panicExtractor{}, true
		}
		return prev(agent)
	}
	t.Cleanup(func() { timelineExtractorFor = prev })

	dir := t.TempDir()
	p := filepath.Join(dir, "corrupt.jsonl")
	if err := os.WriteFile(p, []byte("anything\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	evs, ok := readArtifactEvents(discover.Artifact{Path: p, Agent: "panic-agent"}, "", false, false, &stderr)
	if ok {
		t.Fatal("a panicking parser must yield ok=false (skipped), not a clean read")
	}
	if evs != nil {
		t.Fatalf("a recovered panic must yield no events, got %d", len(evs))
	}
	if !strings.Contains(stderr.String(), "parse") || !strings.Contains(stderr.String(), "panic") {
		t.Fatalf("stderr = %q, want a parse/panic diagnostic", stderr.String())
	}
}

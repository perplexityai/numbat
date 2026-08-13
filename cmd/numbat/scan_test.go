package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/perplexityai/numbat/internal/discover"
	"github.com/perplexityai/numbat/internal/extract"
	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
)

// newTestScannerPipeline builds the shared pipeline the same way runScan does,
// so a directly-constructed scanner in a test runs events through the identical
// per-event core. The engine is nil because these tests select only events.
func newTestScannerPipeline(sc *scanner, em *output.Emitter, now time.Time) *pipeline.Pipeline {
	return pipeline.New(nil, em, pipeline.Selection{
		Events:     sc.sel.events,
		Findings:   sc.sel.findings,
		Indicators: sc.sel.indicators,
	}, finding.Options{Now: now}, sc.indicators)
}

// a transcript whose assistant turn reads .env (file.read) and cats it
// (command.exec) — both fire the built-in secrets rule — plus a benign Grep.
const scanTranscript = `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-06-02T10:00:00Z","cwd":"/home/dev/proj","message":{"role":"user","content":"read the env"}}
{"type":"assistant","uuid":"a1","sessionId":"s1","timestamp":"2026-06-02T10:00:01Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/home/dev/proj/.env"}},{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"cat .env"}},{"type":"tool_use","id":"t3","name":"Grep","input":{"pattern":"x"}}]}}`

func writeTranscript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	return p
}

func diagnosticMessage(t *testing.T, raw string) string {
	t.Helper()
	var record struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &record); err != nil {
		t.Fatalf("decode diagnostic: %v", err)
	}
	return record.Message
}

// decodeFindings parses the NDJSON stdout stream and returns only the finding
// records. The stream now also carries a terminal scan_summary (and, under other
// --emit selections, events/indicators); decodeFindings filters by record_type
// so a finding-count assertion is unaffected by the always-present summary.
func decodeFindings(t *testing.T, out string) []model.Finding {
	t.Helper()
	var fs []model.Finding
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var rt struct {
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal([]byte(line), &rt); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		if rt.RecordType != "finding" {
			continue
		}
		var f model.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("finding line not JSON: %v\n%s", err, line)
		}
		fs = append(fs, f)
	}
	return fs
}

func TestScanEmitsFindings(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out, errb, code := runCLI("scan", "--path", p, "--case-id", "c-1")
	if code != 0 {
		t.Fatalf("exit = %d (err=%s)", code, errb)
	}
	fs := decodeFindings(t, out)
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2 (.env read + cat .env):\n%s", len(fs), out)
	}
	for _, f := range fs {
		if f.RuleID != "secrets.agent_read_env" || f.Severity != model.SeverityMedium {
			t.Errorf("finding rule/severity wrong: %+v", f)
		}
		if f.CaseID != "c-1" {
			t.Errorf("case_id = %q, want c-1", f.CaseID)
		}
		if f.SourceType != model.SourceArtifact {
			t.Errorf("source_type = %q, want artifact", f.SourceType)
		}
		if f.Timestamp != "2026-06-02T10:00:01Z" {
			t.Errorf("timestamp = %q, want matched activity time", f.Timestamp)
		}
		if _, err := time.Parse(time.RFC3339Nano, f.DetectedAt); err != nil {
			t.Errorf("detected_at = %q: %v", f.DetectedAt, err)
		}
		if f.Redacted {
			t.Error("redacted should be false when emitted finding fields were unchanged")
		}
		if !strings.HasPrefix(f.ProjectPathHash, "sha256:") || strings.Contains(f.ProjectPathHash, "/home/dev") {
			t.Errorf("project path not hashed: %q", f.ProjectPathHash)
		}
		if len(f.EvidenceRefs) != 1 || f.EvidenceRefs[0].LocalPath != p {
			t.Errorf("evidence ref wrong: %+v", f.EvidenceRefs)
		}
	}
	// Diagnostics, not findings, carry the completion summary, and they go to
	// stderr so they never pollute the NDJSON findings stream on stdout.
	if !strings.Contains(errb, "scan complete") || !strings.Contains(errb, "2 findings") {
		t.Errorf("stderr missing completion diagnostic: %q", errb)
	}
	// Diagnostics go to stderr, never to the stdout record stream. The stream
	// does carry a terminal scan_summary record, but no "diagnostic" record.
	if strings.Contains(out, `"record_type":"diagnostic"`) {
		t.Errorf("diagnostics leaked into stdout record stream:\n%s", out)
	}
}

func TestScanCustomRuleSeesPromptBeyondPreview(t *testing.T) {
	prompt := strings.Repeat("padding ", 40) + "needle-after-preview"
	entry, err := json.Marshal(map[string]any{
		"type": "user", "uuid": "u1", "sessionId": "s1",
		"message": map[string]any{"role": "user", "content": prompt},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := writeTranscript(t, string(entry))
	rulesDir := t.TempDir()
	ruleBody := `id: test.prompt_content
version: "1"
title: Prompt content
severity: high
expr: event.event_type == "prompt.user" && event.content.contains("needle-after-preview")
`
	if err := os.WriteFile(filepath.Join(rulesDir, "prompt_content.yaml"), []byte(ruleBody), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("scan", "--path", artifact, "--rules-dir", rulesDir, "--no-builtin-rules")
	if code != 0 {
		t.Fatalf("exit = %d (err=%s)", code, errb)
	}
	findings := decodeFindings(t, out)
	if len(findings) != 1 || findings[0].RuleID != "test.prompt_content" {
		t.Fatalf("findings = %+v, want prompt content match", findings)
	}
}

func TestScanDirectoryRecursive(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "projects", "p")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "s.jsonl"), []byte(scanTranscript), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, _, code := runCLI("scan", "--path", root)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if len(decodeFindings(t, out)) != 2 {
		t.Fatalf("recursive scan findings:\n%s", out)
	}
}

// End-to-end: a zstd-compressed Codex rollout under .codex/sessions is
// discovered, transparently decompressed by discover.Open, parsed by the Codex
// extractor, and evaluated by the rule engine. The rollout's shell call cats
// .env, which fires the built-in secrets rule — proving the whole pipeline
// (discovery -> decompression -> Codex parse -> rule eval) is wired together.
func TestScanCodexZstdEndToEnd(t *testing.T) {
	const rollout = `{"timestamp":"2026-06-02T10:00:00Z","type":"session_meta","payload":{"id":"thread-1","cwd":"/home/dev/proj"}}
{"timestamp":"2026-06-02T10:00:01Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":\"cat .env\"}"}}`

	root := t.TempDir()
	sub := filepath.Join(root, ".codex", "sessions", "2026", "06", "02")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("new zstd writer: %v", err)
	}
	if _, err := enc.Write([]byte(rollout)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close encoder: %v", err)
	}
	zpath := filepath.Join(sub, "rollout-2026-06-02T10-00-00-thread-1.jsonl.zst")
	if err := os.WriteFile(zpath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write zst: %v", err)
	}

	out, errb, code := runCLI("scan", "--path", root, "--case-id", "c-zst")
	if code != 0 {
		t.Fatalf("exit = %d (err=%s)", code, errb)
	}
	fs := decodeFindings(t, out)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1 (cat .env from a zstd codex rollout):\n%s\nstderr:%s", len(fs), out, errb)
	}
	if fs[0].RuleID != "secrets.agent_read_env" || fs[0].CaseID != "c-zst" {
		t.Errorf("finding = %+v, want secrets.agent_read_env / c-zst", fs[0])
	}
}

func TestScanBenignTranscriptNoFindings(t *testing.T) {
	body := `{"type":"assistant","uuid":"a1","sessionId":"s1","cwd":"/p","message":{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{"file_path":"/p/main.go"}}]}}`
	p := writeTranscript(t, body)
	out, _, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if fs := decodeFindings(t, out); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0:\n%s", len(fs), out)
	}
}

// A malformed line is a per-line diagnostic; the scan still completes (exit 0)
// and still reports findings from the good lines.
func TestScanTolerantOfMalformedLine(t *testing.T) {
	body := strings.Join([]string{
		`{not json`,
		`{"type":"assistant","uuid":"a1","cwd":"/p","message":{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{"file_path":"/p/.env"}}]}}`,
	}, "\n")
	p := writeTranscript(t, body)
	out, errb, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d (err=%s)", code, errb)
	}
	if len(decodeFindings(t, out)) != 1 {
		t.Fatalf("want one finding despite the bad line:\n%s", out)
	}
	if !strings.Contains(errb, "malformed JSON line") {
		t.Errorf("stderr missing parse diagnostic: %q", errb)
	}
}

// Pointing scan at a single non-artifact file classifies nothing, so no
// artifact is scanned and the run exits 1 (nothing scanned), with no findings.
func TestScanNonArtifactPathExitsOne(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, errb, code := runCLI("scan", "--path", p)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if len(decodeFindings(t, out)) != 0 {
		t.Fatalf("non-artifact path should yield no findings:\n%s", out)
	}
	if !strings.Contains(errb, "no agent artifacts found to scan") {
		t.Errorf("stderr = %q, want a no-artifacts message", errb)
	}
}

// A single missing explicit root is reported as a diagnostic and, because no
// artifact was scanned anywhere, the run exits 1 so a wrapper can tell
// "nothing was scanned" apart from "scanned, found nothing".
func TestScanMissingPathExitsOne(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	out, errb, code := runCLI("scan", "--path", missing)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if len(decodeFindings(t, out)) != 0 {
		t.Fatalf("want no findings for a missing root:\n%s", out)
	}
	if !strings.Contains(errb, "scan root") || !strings.Contains(errb, "no agent artifacts found to scan") {
		t.Errorf("stderr missing expected diagnostics: %q", errb)
	}
}

// A discovered artifact that cannot be opened or decoded is not a successful
// scan. The summary reports error and the process exits 1 so automation does
// not promote an empty, unusable run.
func TestScanDiscoveredButUnparsedArtifactExitsOne(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, ".codex", "sessions", "2026", "06", "19", "rollout-bad.jsonl.zst")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte("not zstd"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, errb, code := runCLI("scan", "--path", root)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (err=%s, out=%s)", code, errb, out)
	}
	if len(decodeFindings(t, out)) != 0 {
		t.Fatalf("want no findings for an unreadable artifact:\n%s", out)
	}
	summary := decodeSummary(t, out)
	if summary.Status != "error" || summary.ArtifactsScanned != 0 {
		t.Fatalf("summary = %+v, want status=error artifacts_scanned=0", summary)
	}
	if !strings.Contains(errb, "parse") {
		t.Errorf("stderr missing parse diagnostic: %q", errb)
	}
}

// A run with one good root and one missing root still scans the good root and
// exits 0; the missing root is only a diagnostic.
func TestScanMixedGoodAndMissingRootExitsZero(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	missing := filepath.Join(t.TempDir(), "nope")
	out, errb, code := runCLI("scan", "--path", missing, "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%s)", code, errb)
	}
	if len(decodeFindings(t, out)) != 2 {
		t.Fatalf("want findings from the good root despite the missing one:\n%s", out)
	}
	if !strings.Contains(errb, "scan root") {
		t.Errorf("stderr missing diagnostic for the missing root: %q", errb)
	}
}

// An empty directory is discovered but yields no artifacts, so the scan exits 1
// (nothing was scanned).
func TestScanEmptyDirExitsOne(t *testing.T) {
	_, errb, code := runCLI("scan", "--path", t.TempDir())
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "no agent artifacts found to scan") {
		t.Errorf("stderr = %q, want a no-artifacts message", errb)
	}
}

// Positional arguments are rejected: a forensic tool must not silently ignore a
// path the user typed and then scan unrelated default data instead.
func TestScanRejectsPositionalArgs(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out, errb, code := runCLI("scan", p)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if len(decodeFindings(t, out)) != 0 {
		t.Fatalf("positional arg must not be scanned:\n%s", out)
	}
	if !strings.Contains(errb, "unexpected argument") {
		t.Errorf("stderr missing usage error: %q", errb)
	}
}

// `scan --help` prints usage and exits 0.
func TestScanHelpExitsZero(t *testing.T) {
	_, errb, code := runCLI("scan", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(errb, "usage: numbat scan") {
		t.Errorf("stderr missing usage: %q", errb)
	}
}

func TestScanMultiplePaths(t *testing.T) {
	p1 := writeTranscript(t, scanTranscript)
	p2 := writeTranscript(t, scanTranscript)
	out, _, code := runCLI("scan", "--path", p1, "--path", p2)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := len(decodeFindings(t, out)); got != 4 {
		t.Fatalf("got %d findings across two paths, want 4:\n%s", got, out)
	}
}

func TestScanDeduplicatesRepeatedAndOverlappingPaths(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out, errb, code := runCLI("scan", "--path", filepath.Dir(p), "--path", p, "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	if got := len(decodeFindings(t, out)); got != 2 {
		t.Fatalf("got %d findings, want 2 from one physical artifact:\n%s", got, out)
	}
	if got := decodeSummary(t, out).ArtifactsScanned; got != 1 {
		t.Fatalf("artifacts_scanned = %d, want 1", got)
	}
}

func TestScanAgentLimitsDefaultDiscovery(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")

	claudeDir := filepath.Join(home, ".claude", "projects", "project")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "session.jsonl"), []byte(scanTranscript), 0o600); err != nil {
		t.Fatal(err)
	}

	codexDir := filepath.Join(home, ".codex", "sessions", "2026", "06", "02")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const codex = `{"timestamp":"2026-06-02T10:00:00Z","type":"session_meta","payload":{"id":"thread-1","cwd":"/home/dev/proj"}}
{"timestamp":"2026-06-02T10:00:01Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":\"cat .env\"}"}}`
	if err := os.WriteFile(filepath.Join(codexDir, "rollout.jsonl"), []byte(codex), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errb, code := runCLI("scan", "--agent", "codex")
	if code != 0 {
		t.Fatalf("Codex-only exit = %d (stderr=%s)", code, errb)
	}
	findings := decodeFindings(t, out)
	if len(findings) != 1 || findings[0].SourceAgent != model.AgentCodex {
		t.Fatalf("Codex-only findings = %+v", findings)
	}

	out, errb, code = runCLI("scan", "--agent", "claude", "--agent", "codex")
	if code != 0 {
		t.Fatalf("multi-agent exit = %d (stderr=%s)", code, errb)
	}
	if got := len(decodeFindings(t, out)); got != 3 {
		t.Fatalf("multi-agent findings = %d, want 3:\n%s", got, out)
	}
}

func TestScanEmptyDefaultRootsExitsOne(t *testing.T) {
	// With no --path and a HOME that has no agent dirs, scan reports that it
	// found nothing to do and exits non-zero so a wrapper can react.
	home := t.TempDir()
	setTestHome(t, home)
	out, errb, code := runCLI("scan")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "no agent artifacts found") {
		t.Errorf("stderr = %q, want a no-artifacts message", errb)
	}
	// Even this early-failure path (no discoverable roots, before any artifact is
	// scanned) must end with a terminal scan_summary so a receiver always sees a
	// bounding record. Status is error: nothing was scanned.
	s := decodeSummary(t, out)
	if s.Status != "error" {
		t.Errorf("status = %q, want error", s.Status)
	}
	if s.ArtifactsScanned != 0 {
		t.Errorf("artifacts_scanned = %d, want 0", s.ArtifactsScanned)
	}
}

type failOnRecordTypeWriter struct {
	bytes.Buffer
	recordType string
	failed     bool
}

func (w *failOnRecordTypeWriter) Write(p []byte) (int, error) {
	needle := []byte(`"record_type":"` + w.recordType + `"`)
	if !w.failed && bytes.Contains(p, needle) {
		w.failed = true
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

func TestScanSummaryWriteErrorExitsOne(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out := failOnRecordTypeWriter{recordType: "scan_summary"}
	var errb bytes.Buffer

	code := run([]string{"scan", "--path", p}, bytes.NewReader(nil), &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when the terminal summary cannot be written", code)
	}
	if !strings.Contains(errb.String(), "emit scan summary") {
		t.Fatalf("stderr = %q, want summary delivery diagnostic", errb.String())
	}
}

func TestScanRecordWriteErrorMarksPartialAndExitsOne(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out := failOnRecordTypeWriter{recordType: "finding"}
	var errb bytes.Buffer

	code := run([]string{"scan", "--path", p}, bytes.NewReader(nil), &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when finding records cannot be written", code)
	}
	s := decodeSummary(t, out.String())
	if s.Status != "partial" {
		t.Fatalf("summary status = %q, want partial after record delivery failure", s.Status)
	}
	if !strings.Contains(errb.String(), "emit finding") {
		t.Fatalf("stderr = %q, want per-record emit diagnostic", errb.String())
	}
}

// The stdout stream is valid NDJSON: one JSON object per line, each parseable
// independently. The stream is the two findings plus the always-emitted
// terminal scan_summary, so a generic record decode yields three records.
func TestScanFindingsAreValidNDJSON(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out, _, _ := runCLI("scan", "--path", p)
	dec := json.NewDecoder(bytes.NewReader([]byte(out)))
	n := 0
	for dec.More() {
		var rec map[string]json.RawMessage
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("NDJSON decode failed at record %d: %v", n, err)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("decoded %d records, want 3 (2 findings + scan_summary)", n)
	}
	// Exactly two of the records are findings.
	if got := len(decodeFindings(t, out)); got != 2 {
		t.Fatalf("got %d finding records, want 2", got)
	}
}

// scanArtifact splits outcomes into parsed vs failed: a good artifact increments
// parsed, an artifact with no extractor (or any pre-event error) increments
// failed. The split is what drives the scan_summary status, so it is asserted
// directly here where both branches are reachable without a 512MB file.
func TestScanArtifactParsedFailedCounts(t *testing.T) {
	good := writeTranscript(t, scanTranscript)
	var rec, diag bytes.Buffer
	em := output.New(&rec, &diag, "run-test")
	sc := &scanner{
		emit: em,
		sel:  emitSelection{events: true},
	}
	sc.pipe = newTestScannerPipeline(sc, em, time.Unix(0, 0))
	// A discovered artifact with no registered extractor: the no-extractor branch
	// must count as failed, not silently vanish.
	sc.scanArtifact(discover.Artifact{Path: "/x/unknown.log", Agent: "no-such-agent"})
	if sc.parsed != 0 || sc.failed != 1 {
		t.Fatalf("after bogus agent: parsed=%d failed=%d, want 0/1", sc.parsed, sc.failed)
	}
	// A real Claude transcript parses cleanly: parsed increments, failed unchanged.
	sc.scanArtifact(discover.Artifact{Path: good, Agent: model.AgentClaudeCode})
	if sc.parsed != 1 || sc.failed != 1 {
		t.Fatalf("after good artifact: parsed=%d failed=%d, want 1/1", sc.parsed, sc.failed)
	}
}

// panicExtractor is a parser that always panics, standing in for a corrupt or
// malicious transcript whose parser crashes mid-extract (before any record is
// built or emitted).
type panicExtractor struct{}

func (panicExtractor) Agent() string { return "panic-agent" }
func (panicExtractor) Extract(io.Reader, extract.Source) (*extract.Result, error) {
	panic("boom: corrupt transcript")
}

// emitPanicEventID is the sentinel EventID the post-extract panic case stamps on
// its one event; the panicking sink keys on it to crash only that artifact's emit.
const emitPanicEventID = "panic-during-emit-sentinel"

// extractThenPanicEmit is a parser that succeeds and returns one event carrying
// the sentinel EventID. It models the harder case: the parse/build phase completes
// cleanly, then a panic strikes DURING streaming emit of that artifact's records.
type extractThenPanicEmit struct{}

func (extractThenPanicEmit) Agent() string { return "panic-emit-agent" }
func (extractThenPanicEmit) Extract(io.Reader, extract.Source) (*extract.Result, error) {
	return &extract.Result{Events: []model.Event{{
		EventID:     emitPanicEventID,
		SourceAgent: "panic-emit-agent",
		EventType:   model.EventPromptUser,
	}}}, nil
}

// panicSink is a records sink that panics on any write whose bytes contain the
// sentinel, and writes everything else through to inner. It is the seam for a
// panic that occurs AFTER extraction returns, during the emit stream.
type panicSink struct{ inner *bytes.Buffer }

func (s panicSink) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(emitPanicEventID)) {
		panic("boom: sink failure mid-emit")
	}
	return s.inner.Write(p)
}
func (panicSink) Close() error { return nil }

// recordSources decodes the NDJSON record stream and returns the local_path of
// every event/finding record, so a test can assert which artifacts contributed
// records to stdout.
func recordSources(t *testing.T, out string) []string {
	t.Helper()
	var srcs []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			Evidence struct {
				LocalPath string `json:"local_path"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		if r.Evidence.LocalPath != "" {
			srcs = append(srcs, r.Evidence.LocalPath)
		}
	}
	return srcs
}

// A panic while extracting one artifact must be caught and treated as a skip: the
// artifact is counted as failed (not parsed), a diagnostic names it, the scan keeps
// running, and a well-formed artifact in the same batch still emits its events. The
// panicking artifact must contribute ZERO records to stdout, since it crashed before
// any record was built. This is the per-artifact panic fence — one bad transcript
// can crash its own parser but never the whole scan.
func TestScanArtifactPanicIsSkippedScanContinues(t *testing.T) {
	bad := writeTranscript(t, "anything")
	good := writeTranscript(t, scanTranscript)

	var rec, diag bytes.Buffer
	em := output.New(&rec, &diag, "run-test")
	sc := &scanner{emit: em, sel: emitSelection{events: true}}
	sc.pipe = newTestScannerPipeline(sc, em, time.Unix(0, 0))
	// Route the panic agent to the panicking parser; everything else uses the real
	// registry so the well-formed Claude artifact parses normally.
	sc.lookup = func(agent string) (extract.Extractor, bool) {
		if agent == "panic-agent" {
			return panicExtractor{}, true
		}
		return extract.For(agent)
	}

	// The panicking artifact must not crash the call.
	sc.scanArtifact(discover.Artifact{Path: bad, Agent: "panic-agent"})
	if sc.failed != 1 || sc.parsed != 0 {
		t.Fatalf("after panicking artifact: parsed=%d failed=%d, want 0/1", sc.parsed, sc.failed)
	}
	// The well-formed artifact in the same batch still parses and emits.
	sc.scanArtifact(discover.Artifact{Path: good, Agent: model.AgentClaudeCode})
	if sc.parsed != 1 || sc.failed != 1 {
		t.Fatalf("after good artifact: parsed=%d failed=%d, want 1/1", sc.parsed, sc.failed)
	}

	// The skip diagnostic names the artifact and goes to the diag stream (stderr),
	// never the stdout record stream.
	message := diagnosticMessage(t, diag.String())
	if !strings.Contains(message, strconv.Quote(bad)) || !strings.Contains(message, "panic") {
		t.Errorf("diagnostics missing panic-skip for %q:\n%s", bad, diag.String())
	}
	if strings.Contains(rec.String(), "panic") {
		t.Errorf("panic diagnostic leaked into stdout record stream:\n%s", rec.String())
	}
	// The well-formed artifact's events still reached stdout, and the bad artifact
	// contributed zero records — it crashed before building any.
	srcs := recordSources(t, rec.String())
	var goodSeen bool
	for _, s := range srcs {
		if s == bad {
			t.Errorf("panicking artifact %q leaked a record to stdout", bad)
		}
		if s == good {
			goodSeen = true
		}
	}
	if !goodSeen {
		t.Errorf("well-formed artifact emitted no records after a sibling panicked:\n%s", rec.String())
	}
}

// The harder case: a panic AFTER extraction returns, during the streaming emit of
// that artifact's records. The fence must still catch it, count the artifact failed
// exactly once and NOT parsed, and let a well-formed artifact in the same batch emit
// normally. Output for the panicking artifact is best-effort (the emit already
// streamed), so this asserts the accounting and continuation, not zero stdout bytes.
func TestScanArtifactPanicDuringEmitIsFailedNotParsed(t *testing.T) {
	bad := writeTranscript(t, "anything")
	good := writeTranscript(t, scanTranscript)

	var rec, diag bytes.Buffer
	// The records sink panics when it sees the sentinel event, modeling a crash mid
	// stream; all other records (the good artifact's) flow through to rec.
	em := output.NewWithSink(panicSink{inner: &rec}, &diag, "run-test")
	sc := &scanner{emit: em, sel: emitSelection{events: true}}
	sc.pipe = newTestScannerPipeline(sc, em, time.Unix(0, 0))
	sc.lookup = func(agent string) (extract.Extractor, bool) {
		if agent == "panic-emit-agent" {
			return extractThenPanicEmit{}, true
		}
		return extract.For(agent)
	}

	// Extraction succeeds, then the emit panics — the fence must catch it.
	sc.scanArtifact(discover.Artifact{Path: bad, Agent: "panic-emit-agent"})
	if sc.failed != 1 || sc.parsed != 0 {
		t.Fatalf("after emit-phase panic: parsed=%d failed=%d, want 0/1 (failed, not parsed)", sc.parsed, sc.failed)
	}
	// A well-formed artifact in the same batch still parses and emits.
	sc.scanArtifact(discover.Artifact{Path: good, Agent: model.AgentClaudeCode})
	if sc.parsed != 1 || sc.failed != 1 {
		t.Fatalf("after good artifact: parsed=%d failed=%d, want 1/1", sc.parsed, sc.failed)
	}

	message := diagnosticMessage(t, diag.String())
	if !strings.Contains(message, strconv.Quote(bad)) || !strings.Contains(message, "panic") {
		t.Errorf("diagnostics missing panic-skip for %q:\n%s", bad, diag.String())
	}
	// The good artifact's records still reached stdout.
	srcs := recordSources(t, rec.String())
	var goodSeen bool
	for _, s := range srcs {
		if s == good {
			goodSeen = true
		}
	}
	if !goodSeen {
		t.Errorf("well-formed artifact emitted no records after a sibling panicked mid-emit:\n%s", rec.String())
	}
}

// With a discovered artifact that fails to parse alongside one that succeeds, the
// run reports status "partial" and ArtifactsScanned counts only the parsed one —
// it must never claim it parsed a file it could not. A directory holding a valid
// transcript and a classified-but-broken sibling is the realistic shape; here it
// is asserted at the scanner level since the parse-failure branch is internal.
func TestScanSummaryPartialStatusCountsParsedOnly(t *testing.T) {
	good := writeTranscript(t, scanTranscript)
	var rec, diag bytes.Buffer
	em := output.New(&rec, &diag, "run-test")
	sc := &scanner{emit: em, sel: emitSelection{events: true}}
	sc.pipe = newTestScannerPipeline(sc, em, time.Unix(0, 0))

	sc.scanArtifact(discover.Artifact{Path: good, Agent: model.AgentClaudeCode})
	sc.scanArtifact(discover.Artifact{Path: "/x/unknown.log", Agent: "no-such-agent"})

	status := output.StatusComplete
	switch {
	case sc.parsed == 0:
		status = output.StatusError
	case sc.failed > 0:
		status = output.StatusPartial
	}
	if status != output.StatusPartial {
		t.Errorf("status = %q, want partial (parsed=%d failed=%d)", status, sc.parsed, sc.failed)
	}
	if sc.parsed != 1 {
		t.Errorf("parsed = %d, want 1 (ArtifactsScanned reports parsed only)", sc.parsed)
	}
}

// A run that discovers a real artifact and parses it cleanly reports status
// "complete", ArtifactsScanned equal to the parsed count, and a diagnostics
// count that includes the terminal "scan complete" note (snapshot is taken after
// it is emitted, so the summary does not undercount its own diagnostics).
func TestScanSummaryCompleteStatusAndDiagCount(t *testing.T) {
	p := writeTranscript(t, scanTranscript)
	out, errb, code := runCLI("scan", "--path", p, "--case-id", "c-1")
	if code != 0 {
		t.Fatalf("exit = %d (err=%s)", code, errb)
	}
	s := decodeSummary(t, out)
	if s.Status != "complete" {
		t.Errorf("status = %q, want complete", s.Status)
	}
	if s.ArtifactsScanned != 1 {
		t.Errorf("artifacts_scanned = %d, want 1 (one parsed transcript)", s.ArtifactsScanned)
	}
	if s.FindingsEmitted != 2 {
		t.Errorf("findings_emitted = %d, want 2", s.FindingsEmitted)
	}
	// At least the terminal "scan complete" diagnostic must be counted; a snapshot
	// taken before it would report 0.
	if s.Diagnostics < 1 {
		t.Errorf("diagnostics = %d, want >=1 (terminal scan-complete note counted)", s.Diagnostics)
	}
}

// A run that discovers no artifact reports status "error" (nothing parsed) and
// still emits a terminal scan_summary before the non-zero exit, so a receiver
// always sees a bounding record even on the failure path.
func TestScanSummaryErrorStatusOnNoArtifacts(t *testing.T) {
	out, _, code := runCLI("scan", "--path", t.TempDir())
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	s := decodeSummary(t, out)
	if s.Status != "error" {
		t.Errorf("status = %q, want error", s.Status)
	}
	if s.ArtifactsScanned != 0 {
		t.Errorf("artifacts_scanned = %d, want 0", s.ArtifactsScanned)
	}
}

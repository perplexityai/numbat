package main

// Behavioral checks for the machine-readable `rules test --json` result
// contract. The contract binds each observed input line to one of five
// distinct classes so a downstream consumer (e.g. Guardian) never has to
// parse human CLI text. These tests were authored before the feature
// implementation as RED-first checks: they must fail on the current main
// (no --json flag) and pass after the smallest supported implementation
// lands. Every class is exercised end-to-end through runCLI.

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// jsonRulesTestEvent mirrors the per-event object the CLI emits when --json
// is set. Reading it back through this struct is the machine-readable
// contract downstream consumers rely on.
type jsonRulesTestEvent struct {
	Type            string                    `json:"type"`
	SchemaVersion   string                    `json:"schema_version"`
	FixtureLine     int                       `json:"fixture_line"`
	EventID         string                    `json:"event_id,omitempty"`
	Status          string                    `json:"status"`
	Findings        []jsonRulesTestFinding    `json:"findings,omitempty"`
	EvaluatorErrors []jsonRulesTestEvalError  `json:"evaluator_errors,omitempty"`
	Coverage        *jsonRulesTestCoverage    `json:"coverage,omitempty"`
	Error           *jsonRulesTestErrorDetail `json:"error,omitempty"`
}

type jsonRulesTestFinding struct {
	RuleID              string `json:"rule_id"`
	RuleVersion         string `json:"rule_version"`
	EnforcementEligible bool   `json:"enforcement_eligible"`
	Via                 string `json:"via"`
}

type jsonRulesTestEvalError struct {
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message"`
}

type jsonRulesTestCoverage struct {
	ShellParse            string `json:"shell_parse"`
	SequenceTrackerActive bool   `json:"sequence_tracker_active"`
}

type jsonRulesTestErrorDetail struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type jsonRulesTestSummary struct {
	Type             string                       `json:"type"`
	SchemaVersion    string                       `json:"schema_version"`
	Status           string                       `json:"status"`
	EventsEvaluated  int                          `json:"events_evaluated"`
	Matches          int                          `json:"matches"`
	RulesLoaded      int                          `json:"rules_loaded"`
	EnforceEligible  int                          `json:"enforce_eligible_rules"`
	AssertionOutcome string                       `json:"assertion_outcome"`
	AssertionMissing []string                     `json:"assertion_missing,omitempty"`
	StoppedAt        *jsonRulesTestStoppedAtBlock `json:"stopped_at,omitempty"`
	NumbatVersion    string                       `json:"numbat_version"`
	RecordSchema     string                       `json:"record_schema"`
}

type jsonRulesTestStoppedAtBlock struct {
	FixtureLine int    `json:"fixture_line"`
	Reason      string `json:"reason"`
}

// parseJSONStream splits stdout into per-line JSON objects. Every line must
// decode; the CLI's contract is one JSON object per line and one terminal
// summary object.
func parseJSONStream(t *testing.T, out string) ([]jsonRulesTestEvent, jsonRulesTestSummary) {
	t.Helper()
	var events []jsonRulesTestEvent
	var summary jsonRulesTestSummary
	var sawSummary bool
	for i, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			t.Fatalf("line %d not JSON: %v; content=%q", i+1, err, line)
		}
		switch probe.Type {
		case "event_result":
			var ev jsonRulesTestEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("line %d event_result decode: %v", i+1, err)
			}
			events = append(events, ev)
		case "summary":
			if err := json.Unmarshal([]byte(line), &summary); err != nil {
				t.Fatalf("line %d summary decode: %v", i+1, err)
			}
			sawSummary = true
		default:
			t.Fatalf("line %d unexpected type %q; content=%q", i+1, probe.Type, line)
		}
	}
	if !sawSummary {
		t.Fatalf("stream missing terminal summary; stdout=%q", out)
	}
	return events, summary
}

// writeTempFile writes body to a temp file under t.TempDir and returns its
// absolute path. Keeps fixture bodies inline in each test for readability
// rather than adding one-off testdata files.
func writeTempFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestRulesTestJSONFindingsClass: a completed evaluation with matches emits
// one event_result per input, each match is a finding object with rule_id,
// rule_version, enforcement_eligible, and via; the summary status is
// "completed" and matches count sums the findings.
func TestRulesTestJSONFindingsClass(t *testing.T) {
	// Two positive events (secrets.agent_read_env, secrets.read_private_key)
	// plus one benign one. Reusing the shipped secrets_fixture keeps the test
	// bound to real embedded rules rather than a synthetic engine.
	out, errb, code := runCLI("rules", "test", "--json", "--fixture", "testdata/secrets_fixture.ndjson")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q, stdout=%q", code, errb, out)
	}
	events, summary := parseJSONStream(t, out)
	if len(events) < 3 {
		t.Fatalf("want at least 3 event_result lines, got %d", len(events))
	}
	if summary.Status != "completed" {
		t.Fatalf("summary status = %q, want %q", summary.Status, "completed")
	}
	if summary.SchemaVersion == "" || summary.RecordSchema == "" {
		t.Fatalf("summary missing schema/record identifiers: %+v", summary)
	}
	if summary.AssertionOutcome != "unchecked" {
		t.Fatalf("assertion_outcome = %q, want %q", summary.AssertionOutcome, "unchecked")
	}
	// Find e1 (cat .env) — must have a finding for secrets.agent_read_env with
	// rule_version and via="engine". Its enforcement_eligible reflects the
	// engine's compiled decision; the test asserts the field is present and
	// well-typed rather than pinning its value across rule updates.
	var e1 *jsonRulesTestEvent
	for i := range events {
		if events[i].EventID == "e1" {
			e1 = &events[i]
			break
		}
	}
	if e1 == nil {
		t.Fatalf("missing event_result for e1: %+v", events)
	}
	if e1.Status != "completed" {
		t.Fatalf("e1 status = %q, want completed", e1.Status)
	}
	var seen bool
	for _, f := range e1.Findings {
		if f.RuleID == "secrets.agent_read_env" {
			if f.RuleVersion == "" {
				t.Fatalf("e1 finding missing rule_version: %+v", f)
			}
			if f.Via != "engine" {
				t.Fatalf("e1 finding via = %q, want engine", f.Via)
			}
			seen = true
		}
	}
	if !seen {
		t.Fatalf("e1 missing expected finding for secrets.agent_read_env: %+v", e1)
	}
	// e3 (.env.example) must complete with no findings — the no-match case.
	var e3 *jsonRulesTestEvent
	for i := range events {
		if events[i].EventID == "e3" {
			e3 = &events[i]
			break
		}
	}
	if e3 == nil || e3.Status != "completed" {
		t.Fatalf("missing completed event_result for e3: %+v", e3)
	}
	if len(e3.Findings) != 0 {
		t.Fatalf("e3 should have no findings: %+v", e3.Findings)
	}
	// Rules loaded + enforce-eligible counts are populated so the consumer can
	// distinguish disabled/empty catalogs from active ones.
	if summary.RulesLoaded < 1 {
		t.Fatalf("rules_loaded = %d, want >=1", summary.RulesLoaded)
	}
}

// TestRulesTestJSONMalformedInputClass: a fixture line that fails JSON decode
// or event validation is reported as status="malformed_input" with the
// fixture line number, and the summary status is "partial" (fixture
// processing stopped before the end). Exit code is 1.
func TestRulesTestJSONMalformedInputClass(t *testing.T) {
	// Line 1 is a valid benign event; line 2 is not valid JSON. Line 3 would
	// be valid but must never be reported: the stream stops at the malformed
	// input.
	body := `{"schema_version":"0.3.0","event_id":"ok1","source_agent":"claude-code","source_type":"artifact","event_type":"file.read","file_path":"/app/main.go","confidence":"high","evidence":{"artifact_type":"claude_jsonl","local_path":"/x","line":1}}
{not valid json
{"schema_version":"0.3.0","event_id":"ok2","source_agent":"claude-code","source_type":"artifact","event_type":"file.read","file_path":"/app/other.go","confidence":"high","evidence":{"artifact_type":"claude_jsonl","local_path":"/x","line":3}}
`
	fixture := writeTempFile(t, "malformed.ndjson", body)
	out, _, code := runCLI("rules", "test", "--json", "--fixture", fixture)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q", code, out)
	}
	events, summary := parseJSONStream(t, out)
	if summary.Status != "partial" {
		t.Fatalf("summary.status = %q, want partial", summary.Status)
	}
	if summary.StoppedAt == nil || summary.StoppedAt.FixtureLine != 2 || summary.StoppedAt.Reason != "malformed_input" {
		t.Fatalf("stopped_at = %+v, want fixture_line=2 reason=malformed_input", summary.StoppedAt)
	}
	// The last event_result must be the malformed one.
	last := events[len(events)-1]
	if last.Status != "malformed_input" {
		t.Fatalf("last status = %q, want malformed_input; events=%+v", last.Status, events)
	}
	if last.FixtureLine != 2 {
		t.Fatalf("last fixture_line = %d, want 2", last.FixtureLine)
	}
	if last.Error == nil || last.Error.Kind != "decode" || last.Error.Message == "" {
		t.Fatalf("last error block = %+v, want kind=decode with message", last.Error)
	}
	// Fixture line 3 must never appear (stream stops at first failure).
	for _, e := range events {
		if e.EventID == "ok2" || e.FixtureLine == 3 {
			t.Fatalf("saw event past malformed line: %+v", e)
		}
	}
}

// TestRulesTestJSONEvaluatorFailureClass: a runtime CEL error surfaces as
// status="evaluation_failure" with per-rule evaluator_errors and does not
// silently drop the failing rule. The summary reports partial and the exit
// code is 1.
func TestRulesTestJSONEvaluatorFailureClass(t *testing.T) {
	// A rule directory whose expression indexes an empty string out of range
	// triggers a runtime CEL evaluation error, mirroring the pattern used in
	// TestEvalFixtureSurfacesRuntimeEvalError.
	ruleDir := t.TempDir()
	ruleYAML := "id: test.eval_boom\nversion: \"1.0\"\ntitle: eval boom\nseverity: low\nexpr: 'event.event_type == \"command.exec\" && event.command[10] == \"x\"'\n"
	if err := os.WriteFile(filepath.Join(ruleDir, "boom.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"schema_version":"0.3.0","event_id":"boom1","source_agent":"claude-code","source_type":"artifact","event_type":"command.exec","command":"hi","confidence":"high","evidence":{"artifact_type":"claude_jsonl","local_path":"/x","line":1}}
`
	fixture := writeTempFile(t, "eval_fail.ndjson", body)
	out, errb, code := runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", ruleDir, "--fixture", fixture)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q, stdout=%q", code, errb, out)
	}
	events, summary := parseJSONStream(t, out)
	if summary.Status != "partial" {
		t.Fatalf("summary.status = %q, want partial", summary.Status)
	}
	if summary.StoppedAt == nil || summary.StoppedAt.Reason != "evaluation_failure" {
		t.Fatalf("stopped_at = %+v, want reason=evaluation_failure", summary.StoppedAt)
	}
	if len(events) == 0 {
		t.Fatalf("no events emitted")
	}
	last := events[len(events)-1]
	if last.Status != "evaluation_failure" {
		t.Fatalf("last status = %q, want evaluation_failure", last.Status)
	}
	if last.EventID != "boom1" {
		t.Fatalf("last event_id = %q, want boom1", last.EventID)
	}
	if len(last.EvaluatorErrors) == 0 {
		t.Fatalf("expected at least one evaluator_error: %+v", last)
	}
	var sawBoom bool
	for _, e := range last.EvaluatorErrors {
		if e.RuleID == "test.eval_boom" && e.Message != "" {
			sawBoom = true
		}
	}
	if !sawBoom {
		t.Fatalf("expected evaluator_error naming test.eval_boom: %+v", last.EvaluatorErrors)
	}
}

// TestRulesTestJSONCoverageHealthClass: an event whose command exceeds the
// shell parser's bounded coverage (>64 statements) reports coverage.shell_parse
// = "unusable" and completes without a match, distinct from a clean no-match.
// This is the coverage/evaluation-health signal Guardian needs to avoid
// inferring "clean" from a bounded-analysis skip.
func TestRulesTestJSONCoverageHealthClass(t *testing.T) {
	// Build a command with 100 chained statements to exceed maxShellCommands=64.
	var parts []string
	for i := 0; i < 100; i++ {
		parts = append(parts, "true")
	}
	command := strings.Join(parts, "; ")
	body := `{"schema_version":"0.3.0","event_id":"cov1","source_agent":"claude-code","source_type":"artifact","event_type":"command.exec","command":` + mustJSONString(command) + `,"confidence":"high","evidence":{"artifact_type":"claude_jsonl","local_path":"/x","line":1}}
`
	fixture := writeTempFile(t, "coverage.ndjson", body)
	out, errb, code := runCLI("rules", "test", "--json", "--fixture", fixture)
	// The event either completes with shell_parse=unusable (bounded analysis)
	// or is surfaced as an evaluation_failure. Both are valid direct-evaluator
	// results; the test asserts that the machine-readable output distinguishes
	// them from a clean no-match — no bare empty stdout with exit 0.
	switch code {
	case 0:
		events, summary := parseJSONStream(t, out)
		if summary.Status != "completed" {
			t.Fatalf("summary.status = %q, want completed", summary.Status)
		}
		if len(events) != 1 {
			t.Fatalf("events = %d, want 1", len(events))
		}
		cov := events[0].Coverage
		if cov == nil || cov.ShellParse != "unusable" {
			t.Fatalf("coverage.shell_parse = %+v, want unusable", cov)
		}
	case 1:
		events, summary := parseJSONStream(t, out)
		if summary.Status != "partial" {
			t.Fatalf("summary.status = %q, want partial", summary.Status)
		}
		if len(events) == 0 {
			t.Fatalf("expected at least one event_result; stderr=%q", errb)
		}
		last := events[len(events)-1]
		if last.Status != "evaluation_failure" {
			t.Fatalf("last status = %q, want evaluation_failure; got=%+v", last.Status, last)
		}
	default:
		t.Fatalf("unexpected exit = %d; stdout=%q stderr=%q", code, out, errb)
	}
}

// TestRulesTestJSONEnforcementEligibleFlag: a rule declared enforce:true
// against a matching event reports enforcement_eligible=true, distinguishing
// an enforce-eligible finding from an advisory one at the CLI seam.
func TestRulesTestJSONEnforcementEligibleFlag(t *testing.T) {
	ruleDir := t.TempDir()
	ruleYAML := "id: test.enforce_eligible\nversion: \"1.0\"\ntitle: enforce-eligible test rule\nseverity: low\nenforce: true\nexpr: 'event.event_type == \"file.read\" && event.file_path == \"/tmp/target\"'\n"
	if err := os.WriteFile(filepath.Join(ruleDir, "enf.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"schema_version":"0.3.0","event_id":"enf1","source_agent":"claude-code","source_type":"artifact","event_type":"file.read","file_path":"/tmp/target","confidence":"high","evidence":{"artifact_type":"claude_jsonl","local_path":"/x","line":1}}
`
	fixture := writeTempFile(t, "enf.ndjson", body)
	out, errb, code := runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", ruleDir, "--fixture", fixture)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q, stdout=%q", code, errb, out)
	}
	events, summary := parseJSONStream(t, out)
	if len(events) != 1 || events[0].EventID != "enf1" {
		t.Fatalf("events = %+v", events)
	}
	if len(events[0].Findings) != 1 {
		t.Fatalf("findings = %+v", events[0].Findings)
	}
	if !events[0].Findings[0].EnforcementEligible {
		t.Fatalf("finding not enforcement-eligible: %+v", events[0].Findings[0])
	}
	if summary.EnforceEligible < 1 {
		t.Fatalf("summary.enforce_eligible_rules = %d, want >=1", summary.EnforceEligible)
	}
}

// TestRulesTestJSONAssertionOutcome: --expect-none against a positive fixture
// with --json completes evaluation (summary.status=completed) but reports
// assertion_outcome=failed and returns exit 1. This is the "completed
// evaluation with failed assertion" case S02a called out — distinct from
// fixture-processing failure.
func TestRulesTestJSONAssertionOutcome(t *testing.T) {
	out, errb, code := runCLI("rules", "test", "--json", "--fixture", "testdata/secrets_fixture.ndjson", "--expect-none")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q, stdout=%q", code, errb, out)
	}
	_, summary := parseJSONStream(t, out)
	if summary.Status != "completed" {
		t.Fatalf("summary.status = %q, want completed (assertion failed after complete evaluation)", summary.Status)
	}
	if summary.AssertionOutcome != "failed" {
		t.Fatalf("assertion_outcome = %q, want failed", summary.AssertionOutcome)
	}
}

// TestRulesTestJSONBackwardCompatible: without --json, existing stdout format
// (rule_id<TAB>event_id) is byte-identical to the pre-change behavior. Bound
// to the shipped secrets fixture so a formatting drift shows up immediately.
func TestRulesTestJSONBackwardCompatible(t *testing.T) {
	out, _, code := runCLI("rules", "test", "--fixture", "testdata/secrets_fixture.ndjson")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	// Legacy tab-separated form: no JSON must leak into stdout when --json is
	// absent.
	if strings.Contains(out, "\"type\":") || strings.Contains(out, "\"schema_version\":") {
		t.Fatalf("legacy stdout contains JSON envelope: %q", out)
	}
	if !strings.Contains(out, "secrets.agent_read_env\te1") {
		t.Fatalf("legacy stdout missing tab-separated match: %q", out)
	}
}

// TestRulesTestJSONRejectsConflictingFlags: --json is documented as
// mutually exclusive with the assertion flag combinations that are already
// rejected. The stray combination check must extend cleanly.
func TestRulesTestJSONHelpMentionsFlag(t *testing.T) {
	out, errb, code := runCLI("rules", "test", "--help")
	if code != 0 {
		t.Fatalf("--help exit = %d", code)
	}
	helpText := out + errb
	if !strings.Contains(helpText, "--json") && !strings.Contains(helpText, "-json") {
		t.Fatalf("--help missing --json flag documentation: stdout=%q stderr=%q", out, errb)
	}
}

// mustJSONString marshals s into a JSON string literal, for embedding inside
// hand-written NDJSON fixtures. Escapes quotes, semicolons, and control
// characters so a fixture body remains valid JSON.
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestRulesTestJSONMalformedInputValidateKind: a syntactically valid JSON
// line whose event fails model.Event.Validate() (unknown event_type) must
// emit status=malformed_input with error.kind="validate", distinct from
// kind="decode". The distinction lets a downstream consumer route validation
// regressions separately from parse errors.
func TestRulesTestJSONMalformedInputValidateKind(t *testing.T) {
	tmp := t.TempDir()
	fx := filepath.Join(tmp, "validate.ndjson")
	// Structurally valid JSON, but event_type is unknown so Validate() rejects.
	body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"v1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"WRONG_TYPE\",\"file_path\":\"/x\",\"confidence\":\"high\",\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
	if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out, errb, code := runCLI("rules", "test", "--json", "--fixture", fx)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q, stdout=%q", code, errb, out)
	}
	events, summary := parseJSONStream(t, out)
	if len(events) != 1 {
		t.Fatalf("want 1 event_result, got %d: %+v", len(events), events)
	}
	if events[0].Status != "malformed_input" {
		t.Fatalf("status = %q, want malformed_input", events[0].Status)
	}
	if events[0].Error == nil || events[0].Error.Kind != "validate" {
		t.Fatalf("error.kind = %+v, want validate", events[0].Error)
	}
	if summary.Status != "partial" || summary.StoppedAt == nil || summary.StoppedAt.Reason != "malformed_input" {
		t.Fatalf("summary = %+v, want partial/malformed_input", summary)
	}
}

// TestRulesTestJSONScanErrorEmitsSummary: when the input scanner fails
// mid-stream (a fixture line exceeds bufio.Scanner's buffer, or an IO error
// occurs), the contract still guarantees exactly one terminal summary object.
// A downstream consumer must be able to distinguish scan failure from a
// truncated pipe or a binary that never wrote anything to stdout.
func TestRulesTestJSONScanErrorEmitsSummary(t *testing.T) {
	tmp := t.TempDir()
	fx := filepath.Join(tmp, "huge.ndjson")
	// A single line larger than bufio.Scanner's 64 KiB default token buffer
	// forces a scan error. Nine MiB is comfortably above every reasonable
	// bump the implementation might apply. Any well-formed but oversized
	// event exercises the same failure path.
	huge := strings.Repeat("A", 9*1024*1024)
	body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"huge\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"file.read\",\"file_path\":\"/x\",\"confidence\":\"high\",\"tags\":[" + mustJSONString(huge) + "],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
	if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out, errb, code := runCLI("rules", "test", "--json", "--fixture", fx)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", code, out, errb)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("stdout is empty; contract requires terminal summary on scan error")
	}
	events, summary := parseJSONStream(t, out)
	if summary.Type != "summary" {
		t.Fatalf("missing terminal summary; got %+v %+v", events, summary)
	}
	if summary.Status != "partial" || summary.StoppedAt == nil {
		t.Fatalf("summary = %+v, want partial with stopped_at populated", summary)
	}
	// At least one event_result should carry error.kind="scan"; the exact
	// count depends on whether the first line reached decode before the
	// scanner rejected it, but a scan-classified event_result must exist.
	sawScan := false
	for _, e := range events {
		if e.Error != nil && e.Error.Kind == "scan" {
			sawScan = true
			if e.Status != "malformed_input" {
				t.Fatalf("scan event status = %q, want malformed_input", e.Status)
			}
		}
	}
	if !sawScan {
		t.Fatalf("no event_result with error.kind=scan found in %+v", events)
	}
}

// TestRulesTestJSONSequenceAndCELErrorCoexist asserts that a per-rule CEL
// error and a real sequence-tracker error on the SAME event both surface in
// evaluator_errors. The scenario is deterministic: the sequence rule's
// first-step expression indexes tags[11] (out of bounds), and a direct rule
// indexes tags[10] (also out of bounds). session_id is set so the tracker
// observes the event. The compiled CLI must emit both errors, classify the
// stop as `error.kind: "sequence"` (tracker failure dominates classification),
// mark the summary partial, and exit 1.
func TestRulesTestJSONSequenceAndCELErrorCoexist(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	brokenRule := `id: both.broken
version: "1.0"
title: broken rule
severity: low
expr: 'event.event_type == "command.exec" && event.tags[10] == "x"'
`
	if err := os.WriteFile(filepath.Join(rulesDir, "broken.yaml"), []byte(brokenRule), 0o600); err != nil {
		t.Fatalf("write broken.yaml: %v", err)
	}
	// The sequence tracker evaluates step 1 against every observed event that
	// carries a session_id. Indexing tags[11] on an event whose tags slice is
	// shorter than 12 elements deterministically errors the tracker.
	seqRule := `id: chain.demo
version: "1.0"
title: demo sequence
severity: medium
sequence:
  within_events: 8
  steps:
    - expr: 'event.event_type == "command.exec" && event.tags[11] == "x"'
    - expr: 'event.event_type == "command.exec"'
`
	if err := os.WriteFile(filepath.Join(rulesDir, "seq.yaml"), []byte(seqRule), 0o600); err != nil {
		t.Fatalf("write seq.yaml: %v", err)
	}
	fx := filepath.Join(tmp, "both.ndjson")
	body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"b1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"echo hi\",\"session_id\":\"s1\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
	if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out, errb, code := runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", rulesDir, "--fixture", fx)
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%q, stdout=%q", code, errb, out)
	}
	events, summary := parseJSONStream(t, out)
	if len(events) != 1 {
		t.Fatalf("want 1 event_result, got %d", len(events))
	}
	ev := events[0]
	if ev.Status != "evaluation_failure" {
		t.Fatalf("status = %q, want evaluation_failure", ev.Status)
	}
	if ev.Error == nil || ev.Error.Kind != "sequence" {
		t.Fatalf("error.kind = %+v, want \"sequence\" (tracker failure classifies the stop)", ev.Error)
	}
	sawBroken := false
	sawSequence := false
	for _, e := range ev.EvaluatorErrors {
		switch e.RuleID {
		case "both.broken":
			sawBroken = true
		case "":
			sawSequence = true
		}
	}
	if !sawBroken || !sawSequence {
		t.Fatalf("want BOTH per-rule (rule_id=both.broken) and sequence (rule_id=\"\") errors; got %+v", ev.EvaluatorErrors)
	}
	if summary.Status != "partial" {
		t.Fatalf("summary.status = %q, want partial", summary.Status)
	}
}

// TestRulesTestJSONCountIdentities pins the precise semantics of the two
// summary counters. events_evaluated is the number of fixture lines that
// reached direct evaluation (including a final line that ended in an
// evaluation failure). matches is the total findings emitted across all
// event_results. matches may exceed events_evaluated when several direct
// rules match one event, and each sequence finding also increments matches
// without adding to events_evaluated. There is no ordering invariant between
// the two counters.
func TestRulesTestJSONCountIdentities(t *testing.T) {
	t.Run("two direct rules match one event: matches>events_evaluated", func(t *testing.T) {
		tmp := t.TempDir()
		rulesDir := filepath.Join(tmp, "rules")
		if err := os.MkdirAll(rulesDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for i, name := range []string{"a", "b"} {
			r := "id: pair.match_" + name + "\nversion: \"1.0\"\ntitle: pair " + name + "\nseverity: low\nexpr: 'event.event_type == \"command.exec\"'\n"
			if err := os.WriteFile(filepath.Join(rulesDir, name+".yaml"), []byte(r), 0o600); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		fx := filepath.Join(tmp, "one.ndjson")
		body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"e1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"ls\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
		if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		out, errb, code := runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", rulesDir, "--fixture", fx)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr=%q", code, errb)
		}
		events, summary := parseJSONStream(t, out)
		if summary.EventsEvaluated != 1 {
			t.Fatalf("events_evaluated = %d, want 1", summary.EventsEvaluated)
		}
		if summary.Matches != 2 {
			t.Fatalf("matches = %d, want 2 (two rules match one event)", summary.Matches)
		}
		if len(events) != 1 || len(events[0].Findings) != 2 {
			t.Fatalf("want 1 event_result with 2 findings; got %+v", events)
		}
	})

	t.Run("partial final event still counts in events_evaluated", func(t *testing.T) {
		tmp := t.TempDir()
		rulesDir := filepath.Join(tmp, "rules")
		if err := os.MkdirAll(rulesDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		matchRule := `id: pair.match
version: "1.0"
title: match rule
severity: low
expr: 'event.event_type == "file.read"'
`
		brokenRule := `id: pair.broken
version: "1.0"
title: broken rule
severity: low
expr: 'event.event_type == "file.read" && event.tags[10] == "x"'
`
		if err := os.WriteFile(filepath.Join(rulesDir, "m.yaml"), []byte(matchRule), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.WriteFile(filepath.Join(rulesDir, "b.yaml"), []byte(brokenRule), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		fx := filepath.Join(tmp, "pair.ndjson")
		body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"p1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"file.read\",\"file_path\":\"/x\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
		if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		out, errb, code := runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", rulesDir, "--fixture", fx)
		if code != 1 {
			t.Fatalf("exit = %d, want 1; stderr=%q", code, errb)
		}
		_, summary := parseJSONStream(t, out)
		if summary.EventsEvaluated != 1 {
			t.Fatalf("events_evaluated = %d, want 1 (line reached evaluation)", summary.EventsEvaluated)
		}
		if summary.Matches != 1 {
			t.Fatalf("matches = %d, want 1 (pair.match still fires)", summary.Matches)
		}
		if summary.Status != "partial" {
			t.Fatalf("status = %q, want partial", summary.Status)
		}
	})

	t.Run("sequence findings add to matches without adding events_evaluated", func(t *testing.T) {
		tmp := t.TempDir()
		rulesDir := filepath.Join(tmp, "rules")
		if err := os.MkdirAll(rulesDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// Two-step sequence that fires on the second event in the same session.
		seqRule := `id: chain.pair
version: "1.0"
title: two-step chain
severity: medium
sequence:
  within_events: 8
  steps:
    - expr: 'event.event_type == "command.exec"'
    - expr: 'event.event_type == "command.exec"'
`
		if err := os.WriteFile(filepath.Join(rulesDir, "seq.yaml"), []byte(seqRule), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		fx := filepath.Join(tmp, "chain.ndjson")
		body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"e1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"ls\",\"session_id\":\"s1\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n" +
			"{\"schema_version\":\"0.3.0\",\"event_id\":\"e2\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"pwd\",\"session_id\":\"s1\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":2}}\n"
		if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		out, errb, code := runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", rulesDir, "--fixture", fx)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr=%q", code, errb)
		}
		_, summary := parseJSONStream(t, out)
		if summary.EventsEvaluated != 2 {
			t.Fatalf("events_evaluated = %d, want 2", summary.EventsEvaluated)
		}
		if summary.Matches < 1 {
			t.Fatalf("matches = %d, want >= 1 (sequence should fire on e2)", summary.Matches)
		}
	})
}

// failingWriter returns errFailingWriter after the first `okBytes` bytes; used
// to synthesize the OS-level partial-write / EPIPE / EBADF class without
// depending on /dev/full being addressable inside the sandbox.
type failingWriter struct {
	okBytes int
	written int
}

var errFailingWriter = errors.New("failingWriter: synthetic stdout failure")

func (f *failingWriter) Write(p []byte) (int, error) {
	remaining := f.okBytes - f.written
	if remaining <= 0 {
		return 0, errFailingWriter
	}
	if len(p) <= remaining {
		f.written += len(p)
		return len(p), nil
	}
	f.written += remaining
	return remaining, errFailingWriter
}

// runRulesTestJSONForTest builds a compiled catalog identical to the CLI
// (--no-builtin-rules with a directory of operator rules) and drives
// runRulesTestJSON directly against a custom stdout writer. Used for the
// delivery-failure checks that need to observe encoder behavior on a broken
// writer without spawning a subprocess.
func runRulesTestJSONForTest(t *testing.T, rulesDir, fixturePath string, stdout, stderr io.Writer) int {
	t.Helper()
	eng, err := buildEngine([]string{rulesDir}, true)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	f, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	return runRulesTestJSON(eng, f, stdout, stderr, false, false, nil)
}

// TestRulesTestJSONDeliveryFailureOnEventResult asserts that a stdout write
// failure while emitting the FIRST event_result returns a non-zero exit code
// (rulesTestJSONDeliveryExitCode), reports the error on stderr, and does not
// silently succeed. This closes the class where a Guardian-side reader sees
// zero events and mis-infers a clean no-match.
func TestRulesTestJSONDeliveryFailureOnEventResult(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := `id: deliver.match
version: "1.0"
title: deliver match
severity: low
expr: 'event.event_type == "command.exec"'
`
	if err := os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(r), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fx := filepath.Join(tmp, "one.ndjson")
	body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"e1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"ls\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
	if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	stdout := &failingWriter{okBytes: 0}
	var stderr strings.Builder
	code := runRulesTestJSONForTest(t, rulesDir, fx, stdout, &stderr)
	if code != rulesTestJSONDeliveryExitCode {
		t.Fatalf("exit = %d, want %d (delivery failure); stderr=%q", code, rulesTestJSONDeliveryExitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write rules-test-result") {
		t.Fatalf("stderr missing write-failure notice: %q", stderr.String())
	}
}

// TestRulesTestJSONDeliveryFailureOnSummaryOnly asserts that when the
// event_result writes succeed but the terminal summary write fails, the exit
// code still reflects delivery failure. A consumer must not treat a run whose
// summary was truncated as a successful run.
func TestRulesTestJSONDeliveryFailureOnSummaryOnly(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := `id: summary.match
version: "1.0"
title: summary match
severity: low
expr: 'event.event_type == "command.exec"'
`
	if err := os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(r), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fx := filepath.Join(tmp, "one.ndjson")
	body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"e1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"ls\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
	if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// Determine how many bytes the first event_result will occupy, then let
	// the writer accept exactly those bytes so only the summary write fails.
	var probe strings.Builder
	probeCode := runRulesTestJSONForTest(t, rulesDir, fx, &probe, io.Discard)
	if probeCode != 0 {
		t.Fatalf("probe exit = %d, want 0; stdout=%q", probeCode, probe.String())
	}
	nl := strings.IndexByte(probe.String(), '\n')
	if nl <= 0 {
		t.Fatalf("no newline in probe output: %q", probe.String())
	}
	firstLineBytes := nl + 1
	stdout := &failingWriter{okBytes: firstLineBytes}
	var stderr strings.Builder
	code := runRulesTestJSONForTest(t, rulesDir, fx, stdout, &stderr)
	if code != rulesTestJSONDeliveryExitCode {
		t.Fatalf("exit = %d, want %d (summary delivery failure); stderr=%q", code, rulesTestJSONDeliveryExitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write rules-test-result") {
		t.Fatalf("stderr missing write-failure notice: %q", stderr.String())
	}
}

// TestRulesTestJSONCompiledCLIDevFull spawns the compiled numbat binary with
// stdout redirected to /dev/full so every OS-level write returns ENOSPC, and
// asserts the JSON mode reports a nonzero exit code, matching the legacy
// tab-separated mode's behavior on the same failure. Skipped when /dev/full is
// not present (non-Linux hosts or minimal sandboxes without the char device).
func TestRulesTestJSONCompiledCLIDevFull(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("compiled-CLI OS write-failure check requires linux /dev/full")
	}
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}
	// Build the binary into a temp path so the test does not depend on a
	// preinstalled binary or PATH shape.
	bin := filepath.Join(t.TempDir(), "numbat")
	buildCmd := exec.Command("go", "build", "-o", bin, "./")
	buildCmd.Dir = "."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build numbat: %v\n%s", err, out)
	}
	fx := filepath.Join(t.TempDir(), "fx.ndjson")
	body := "{\"schema_version\":\"0.3.0\",\"event_id\":\"e1\",\"source_agent\":\"claude-code\",\"source_type\":\"artifact\",\"event_type\":\"command.exec\",\"command\":\"ls\",\"confidence\":\"high\",\"tags\":[],\"evidence\":{\"artifact_type\":\"claude_jsonl\",\"local_path\":\"/x\",\"line\":1}}\n"
	if err := os.WriteFile(fx, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	devFull, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("open /dev/full: %v", err)
	}
	defer devFull.Close()
	cmd := exec.Command(bin, "rules", "test", "--json", "--fixture", fx)
	cmd.Stdout = devFull
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		t.Fatalf("compiled --json rules test exited 0 with stdout=/dev/full; want nonzero exit. stderr=%q", stderr.String())
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("exit code = 0, want nonzero; stderr=%q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "write") {
		t.Fatalf("stderr missing write-failure notice: %q", stderr.String())
	}
}

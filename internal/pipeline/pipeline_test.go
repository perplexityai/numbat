package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/rule"
)

// testEngine compiles a one-rule engine that fires on command.exec events. It is
// the minimal real engine the parity test needs, so Process and a direct
// Eval+FromMatch run against identical compiled rules.
func testEngine(t *testing.T) *rule.Engine {
	t.Helper()
	enabled := true
	eng, err := rule.NewEngine([]rule.Source{{
		Name: "test",
		Rules: []rule.Rule{{
			ID:       "test.exec",
			Title:    "command executed",
			Severity: "medium",
			Version:  "1",
			Expr:     `event.event_type == "command.exec"`,
			Tags:     []string{"exec"},
			Enabled:  &enabled,
		}},
	}})
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}
	return eng
}

func sampleEvent() model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		EventID:       "ev-1",
		SourceAgent:   model.AgentClaudeCode,
		SourceType:    model.SourceArtifact,
		Timestamp:     "2026-06-02T10:00:00Z",
		SessionID:     "s1",
		Actor:         model.ActorAssistant,
		EventType:     model.EventCommandExec,
		Command:       "cat /etc/passwd",
		Confidence:    model.ConfidenceHigh,
		Evidence:      model.Evidence{ArtifactType: "claude_jsonl", LocalPath: "/x/a.jsonl", Line: 7},
	}
}

// findingLines returns the finding records emitted onto buf, decoded as generic
// maps so the comparison covers every field the emitter wrote.
func findingLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		if rec["record_type"] == output.RecordFinding {
			out = append(out, rec)
		}
	}
	return out
}

// TestProcessMatchesDirectPath ensures the shared pipeline preserves the direct
// engine-to-finding output contract used by scan, hooks, and OTLP ingestion.
func TestProcessMatchesDirectPath(t *testing.T) {
	eng := testEngine(t)
	ev := sampleEvent()
	now := time.Unix(1_700_000_000, 0).UTC()
	fopts := finding.Options{Now: now}

	// Direct path: exactly what scanArtifact did inline before the refactor.
	var directBuf, directDiag bytes.Buffer
	directEm := output.New(&directBuf, &directDiag, "run-x")
	matches, err := eng.Eval(ev)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	for _, m := range matches {
		if err := directEm.EmitFinding(finding.FromMatch(m, fopts)); err != nil {
			t.Fatalf("emit finding: %v", err)
		}
	}

	// Pipeline path: same engine, same options, through Process.
	var pipeBuf, pipeDiag bytes.Buffer
	pipeEm := output.New(&pipeBuf, &pipeDiag, "run-x")
	p := New(eng, pipeEm, Selection{Findings: true}, fopts, nil)
	if err := p.Process(ev, "/x/a.jsonl"); err != nil {
		t.Fatalf("process: %v", err)
	}

	direct := findingLines(t, &directBuf)
	piped := findingLines(t, &pipeBuf)
	if len(direct) != 1 || len(piped) != 1 {
		t.Fatalf("finding counts: direct=%d piped=%d, want 1/1", len(direct), len(piped))
	}
	db, _ := json.Marshal(direct[0])
	pb, _ := json.Marshal(piped[0])
	if string(db) != string(pb) {
		t.Fatalf("Process finding differs from direct path:\n direct: %s\n piped:  %s", db, pb)
	}
}

func TestUniqueErrorMessage(t *testing.T) {
	got := uniqueErrorMessage(
		errors.Join(errors.New("same"), errors.New("first only")),
		errors.Join(errors.New("same"), errors.New("second only")),
	)
	if want := "same\nfirst only\nsecond only"; got != want {
		t.Fatalf("uniqueErrorMessage = %q, want %q", got, want)
	}
}

// enforceEngine compiles a two-rule engine: a clean explicitly enforceable
// rule that fires on command.exec, plus an optional second rule whose expr
// errors at eval time (indexing past a short string). withEvalError selects
// whether the erroring sibling is included.
func enforceEngine(t *testing.T, withEvalError bool) *rule.Engine {
	t.Helper()
	enforce := true
	rules := []rule.Rule{{
		ID:       "test.enforce_block",
		Title:    "explicitly enforceable",
		Severity: model.SeverityMedium,
		Version:  "1",
		Expr:     `event.event_type == "command.exec"`,
		Enforce:  &enforce,
	}}
	if withEvalError {
		rules = append(rules, rule.Rule{
			ID:       "test.eval_boom",
			Title:    "errors at eval",
			Severity: model.SeverityHigh,
			Version:  "1",
			Expr:     `event.command.size() > 50 ? false : event.command[50] == "x"`,
		})
	}
	eng, err := rule.NewEngine([]rule.Source{{Name: "test", Rules: rules}})
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}
	return eng
}

// errSink is a Sink whose Write always fails, so EmitFinding returns an error on
// every record. It models a findings-sink write failure during an otherwise
// clean enforce match: the run is no longer fully clean, so the enforce signal
// must be withheld even though the match itself was eligible.
type errSink struct{}

func (errSink) Write([]byte) (int, error) { return 0, fmt.Errorf("sink write failed") }
func (errSink) Close() error              { return nil }

// A sibling rule error cannot turn into a bypass for an independently clean,
// explicitly enforceable match.
func TestProcessEnforceSurvivesSiblingEvalError(t *testing.T) {
	eng := enforceEngine(t, true)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	dec := &EnforceDecision{}
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil).WithEnforce(dec)
	if err := p.Process(sampleEvent(), "src"); err != nil {
		t.Fatal(err)
	}
	if !dec.Blocked {
		t.Fatalf("Blocked = false, want true: sibling eval error suppressed a clean enforce match")
	}
	if dec.Tainted {
		t.Fatal("Tainted = true after an unrelated evaluation error")
	}
	if got := em.Stats().FindingsEmitted; got != 1 {
		t.Fatalf("findings emitted = %d, want 1", got)
	}
}

// TestProcessEnforceWithheldOnEmitError proves a clean explicitly enforceable
// match whose finding fails to write must not record a block. A findings-sink
// write failure makes the run uncertain, so Blocked stays false and the hook
// falls open.
func TestProcessEnforceWithheldOnEmitError(t *testing.T) {
	eng := enforceEngine(t, false)
	em := output.NewWithSink(errSink{}, &bytes.Buffer{}, "run-x")
	dec := &EnforceDecision{}
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil).WithEnforce(dec)
	if err := p.Process(sampleEvent(), "src"); err != nil {
		t.Fatal(err)
	}
	if dec.Blocked {
		t.Fatalf("Blocked = true, want false: an EmitFinding failure must withhold the enforce signal")
	}
}

// TestProcessEnforceRecordedOnCleanRun pins the positive direction: a single
// clean explicitly enforceable match with no errors does record a block, so
// the withholding fix has not broken the one path that may legitimately deny.
func TestProcessEnforceRecordedOnCleanRun(t *testing.T) {
	eng := enforceEngine(t, false)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	dec := &EnforceDecision{}
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil).WithEnforce(dec)
	ev := sampleEvent()
	ev.SessionTreeID = "tree-1"
	ev.ParentSessionID = "parent-1"
	ev.SubAgent = "reviewer"
	ev.SubAgentID = "child-1"
	if err := p.Process(ev, "src"); err != nil {
		t.Fatal(err)
	}
	if !dec.Blocked {
		t.Fatalf("Blocked = false, want true: a fully-clean enforce-eligible match must record a block")
	}
	if dec.Tainted {
		t.Fatal("Tainted = true after a clean match")
	}
	if dec.Reason != defaultDenyMessage {
		t.Fatalf("reason = %q, want %q", dec.Reason, defaultDenyMessage)
	}
	if dec.SessionID != "s1" || dec.SessionTreeID != "tree-1" || dec.ParentSessionID != "parent-1" || dec.SubAgent != "reviewer" || dec.SubAgentID != "child-1" {
		t.Fatalf("decision lost session or sub-agent context: %+v", dec)
	}
	findings := findingLines(t, &buf)
	if len(findings) != 1 || findings[0]["rule_id"] != "test.enforce_block" || findings[0]["title"] != "explicitly enforceable" {
		t.Fatalf("finding lost operator-facing rule details: %+v", findings)
	}
	if refs, ok := findings[0]["evidence_refs"].([]any); !ok || len(refs) != 1 {
		t.Fatalf("finding lost operator-facing evidence: %+v", findings[0]["evidence_refs"])
	}
}

func TestProcessPowerShellPreviewDetectionDoesNotBlock(t *testing.T) {
	enforce := true
	eng, err := rule.NewEngine([]rule.Source{{Name: "test", Rules: []rule.Rule{{
		ID:       "test.preview",
		Title:    "preview",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  &enforce,
		Expr:     `shell_commands.exists(command, command.name == "remove-item")`,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		command string
		block   bool
	}{
		{"preview", `Remove-Item C:\tmp\x -Force -WhatIf`, false},
		{"explicit false", `Remove-Item C:\tmp\x -Force -WhatIf:$false`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var records, diagnostics bytes.Buffer
			decision := &EnforceDecision{}
			p := New(
				eng,
				output.New(&records, &diagnostics, "run-x"),
				Selection{Findings: true},
				finding.Options{},
				nil,
			).WithEnforce(decision)
			event := sampleEvent()
			event.ToolName = "PowerShell"
			event.Command = tt.command
			if err := p.Process(event, "src"); err != nil {
				t.Fatal(err)
			}
			if !decision.Matched || decision.Tainted || decision.Blocked != tt.block {
				t.Fatalf("decision = %+v, want matched clean block=%v", decision, tt.block)
			}
		})
	}
}

func TestProcessEnforceUsesRuleDenyMessage(t *testing.T) {
	enforce := true
	message := "Contact the workspace owner."
	eng, err := rule.NewEngine([]rule.Source{{Name: "test", Rules: []rule.Rule{{
		ID:          "test.custom_message",
		Title:       "custom message",
		Severity:    model.SeverityMedium,
		Version:     "1",
		Expr:        `event.event_type == "command.exec"`,
		Enforce:     &enforce,
		DenyMessage: message,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	dec := &EnforceDecision{}
	p := New(eng, output.New(&bytes.Buffer{}, &bytes.Buffer{}, "run-x"), Selection{}, finding.Options{}, nil).WithEnforce(dec)
	if err := p.Process(sampleEvent(), "src"); err != nil {
		t.Fatal(err)
	}
	if !dec.Blocked || dec.Reason != message {
		t.Fatalf("decision = %+v, want custom message %q", dec, message)
	}
}

func TestProcessEnforceErrorsStayScoped(t *testing.T) {
	eng := enforceEngine(t, true)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	dec := &EnforceDecision{}
	p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil).WithEnforce(dec)

	short := sampleEvent() // The sibling rule errors on this short command.
	long := sampleEvent()
	long.EventID = "event-long"
	long.Command = strings.Repeat("x", 64)
	if err := p.Process(short, "src"); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(long, "src"); err != nil {
		t.Fatal(err)
	}
	if dec.Tainted || !dec.Blocked {
		t.Fatalf("decision after error then clean match = %+v, want clean block", dec)
	}

	dec = &EnforceDecision{}
	p = New(eng, em, Selection{Findings: true}, finding.Options{}, nil).WithEnforce(dec)
	if err := p.Process(long, "src"); err != nil {
		t.Fatal(err)
	}
	if !dec.Blocked {
		t.Fatal("clean first event did not block")
	}
	short.EventID = "event-short-2"
	if err := p.Process(short, "src"); err != nil {
		t.Fatal(err)
	}
	if dec.Tainted || !dec.Blocked || dec.Reason == "" {
		t.Fatalf("decision after clean match then error = %+v, want retained clean block", dec)
	}
}

// TestProcessNilEngineWithEnforceFallsOpen pins the defensive boundary between
// live hooks and the shared pipeline: if a caller accidentally attaches an
// enforce accumulator while no rule engine is available, Process must behave as
// a fail-open no-op for findings/enforcement rather than panicking or blocking.
func TestProcessNilEngineWithEnforceFallsOpen(t *testing.T) {
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-x")
	dec := &EnforceDecision{}
	p := New(nil, em, Selection{}, finding.Options{}, nil).WithEnforce(dec)
	if err := p.Process(sampleEvent(), "src"); err != nil {
		t.Fatal(err)
	}
	if dec.Blocked {
		t.Fatal("Blocked = true, want false without a rule engine")
	}
	if got := em.Stats().FindingsEmitted; got != 0 {
		t.Fatalf("findings emitted = %d, want 0 without a rule engine", got)
	}
}

// TestProcessSelection checks that each Selection flag gates exactly the record
// kind it names: events emit event records, findings emit findings, and
// indicators fold into the accumulator without emitting inline.
func TestProcessSelection(t *testing.T) {
	eng := testEngine(t)
	ev := sampleEvent()

	t.Run("events only", func(t *testing.T) {
		var buf, diag bytes.Buffer
		em := output.New(&buf, &diag, "run-x")
		p := New(nil, em, Selection{Events: true}, finding.Options{}, nil)
		if err := p.Process(ev, "src"); err != nil {
			t.Fatal(err)
		}
		if got := em.Stats().EventsEmitted; got != 1 {
			t.Fatalf("events emitted = %d, want 1", got)
		}
		if got := em.Stats().FindingsEmitted; got != 0 {
			t.Fatalf("findings emitted = %d, want 0", got)
		}
	})

	t.Run("findings only", func(t *testing.T) {
		var buf, diag bytes.Buffer
		em := output.New(&buf, &diag, "run-x")
		p := New(eng, em, Selection{Findings: true}, finding.Options{}, nil)
		if err := p.Process(ev, "src"); err != nil {
			t.Fatal(err)
		}
		if got := em.Stats().EventsEmitted; got != 0 {
			t.Fatalf("events emitted = %d, want 0", got)
		}
		if got := em.Stats().FindingsEmitted; got != 1 {
			t.Fatalf("findings emitted = %d, want 1", got)
		}
	})

	t.Run("indicators fold without inline emit", func(t *testing.T) {
		var buf, diag bytes.Buffer
		em := output.New(&buf, &diag, "run-x")
		acc := output.NewIndicatorAccumulator()
		p := New(nil, em, Selection{Indicators: true}, finding.Options{}, acc)
		netEv := ev
		netEv.EventType = model.EventNetworkIndicator
		netEv.Command = ""
		netEv.URL = "https://evil.example/x"
		if err := p.Process(netEv, "src"); err != nil {
			t.Fatal(err)
		}
		if got := em.Stats().IndicatorsEmitted; got != 0 {
			t.Fatalf("indicators emitted inline = %d, want 0 (materialized by caller)", got)
		}
		if got := len(acc.Materialize()); got == 0 {
			t.Fatalf("accumulator folded 0 indicators, want >=1")
		}
	})
}

func TestProcessRejectsInvalidNormalizedEvent(t *testing.T) {
	bad := sampleEvent()
	duration := int64(1)
	bad.DurationMs = &duration // duration_ms is not valid on command.exec.

	var records, diagnostics bytes.Buffer
	em := output.New(&records, &diagnostics, "run-x")
	acc := output.NewIndicatorAccumulator()
	dec := &EnforceDecision{}
	p := New(testEngine(t), em, Selection{Events: true, Findings: true, Indicators: true}, finding.Options{}, acc).WithEnforce(dec)
	if err := p.Process(bad, "fixture"); err == nil {
		t.Fatal("invalid event was accepted")
	}
	if records.Len() != 0 || em.Stats().EventsEmitted != 0 || em.Stats().FindingsEmitted != 0 {
		t.Fatalf("invalid event produced output: %s", records.String())
	}
	if len(acc.Materialize()) != 0 {
		t.Fatal("invalid event reached indicator accumulation")
	}
	if dec.Blocked {
		t.Fatal("invalid event reached enforcement")
	}
}

func TestProcessNormalizesWindowsPathsBeforeRulesAndOutput(t *testing.T) {
	enabled := true
	eng, err := rule.NewEngine([]rule.Source{{Name: "path-test", Rules: []rule.Rule{{
		ID:       "test.windows_path",
		Title:    "normalized path matched",
		Severity: "high",
		Version:  "1",
		Expr:     `event.event_type == "file.read" && event.file_path.matches("(^|/)\\.ssh/authorized_keys$")`,
		Enabled:  &enabled,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	ev := sampleEvent()
	ev.EventType = model.EventFileRead
	ev.Command = ""
	ev.FilePath = `C:\Users\dev\.ssh\authorized_keys`
	ev.ProjectPath = `C:\Users\dev\repo`

	var records, diagnostics bytes.Buffer
	em := output.New(&records, &diagnostics, "run-x")
	p := New(eng, em, Selection{Events: true, Findings: true}, finding.Options{}, nil)
	if err := p.Process(ev, "windows-hook"); err != nil {
		t.Fatal(err)
	}
	lines := findingLines(t, &records)
	if len(lines) != 1 {
		t.Fatalf("findings = %d, want 1; records=%s diagnostics=%s", len(lines), records.String(), diagnostics.String())
	}
	if strings.Contains(records.String(), `C:\\Users`) || !strings.Contains(records.String(), `C:/Users/dev/.ssh/authorized_keys`) {
		t.Fatalf("event path was not normalized in output: %s", records.String())
	}
}

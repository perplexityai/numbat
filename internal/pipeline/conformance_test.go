package pipeline

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/sequence"
)

// canonical is the normalized semantic projection of a finding. It excludes
// finding identity, detection time, and evidence shape (FindingID, CaseID,
// DetectedAt, EvidenceRefs, run_id), which can vary with run context.
type canonical struct {
	Timestamp              string
	RuleID                 string
	RuleVersion            string
	Severity               string
	SourceAgent            string
	SourceType             string
	ProjectPathHash        string
	SessionID              string
	SessionTreeID          string
	ParentSessionID        string
	Model                  string
	ModelProvider          string
	SubAgent               string
	SubAgentID             string
	Title                  string
	ObservedEventType      string
	ObservedActor          string
	ObservedCommand        string
	ObservedFilePath       string
	ObservedURL            string
	ObservedMCPServer      string
	ObservedMCPTool        string
	ObservedContentPreview string
	Tags                   []string
	Redacted               bool
	Confidence             string
}

// project reduces an emitted finding record (the generic map findingLines
// decodes) to its canonical projection.
func project(rec map[string]any) canonical {
	c := canonical{
		Timestamp:              str(rec["timestamp"]),
		RuleID:                 str(rec["rule_id"]),
		RuleVersion:            str(rec["rule_version"]),
		Severity:               str(rec["severity"]),
		SourceAgent:            str(rec["source_agent"]),
		SourceType:             str(rec["source_type"]),
		ProjectPathHash:        str(rec["project_path_hash"]),
		SessionID:              str(rec["session_id"]),
		SessionTreeID:          str(rec["session_tree_id"]),
		ParentSessionID:        str(rec["parent_session_id"]),
		Model:                  str(rec["model"]),
		ModelProvider:          str(rec["model_provider"]),
		SubAgent:               str(rec["sub_agent"]),
		SubAgentID:             str(rec["sub_agent_id"]),
		Title:                  str(rec["title"]),
		ObservedEventType:      str(rec["observed_event_type"]),
		ObservedActor:          str(rec["observed_actor"]),
		ObservedCommand:        str(rec["observed_command"]),
		ObservedFilePath:       str(rec["observed_file_path"]),
		ObservedURL:            str(rec["observed_url"]),
		ObservedMCPServer:      str(rec["observed_mcp_server"]),
		ObservedMCPTool:        str(rec["observed_mcp_tool"]),
		ObservedContentPreview: str(rec["observed_content_preview"]),
		Tags:                   tags(rec["tags"]),
		Redacted:               boolOf(rec["redacted"]),
		Confidence:             str(rec["confidence"]),
	}
	return c
}

func tags(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		out = append(out, str(t))
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}

// projectAll maps every emitted finding record to its canonical projection.
func projectAll(t *testing.T, buf *bytes.Buffer) []canonical {
	t.Helper()
	recs := findingLines(t, buf)
	out := make([]canonical, len(recs))
	for i, r := range recs {
		out[i] = project(r)
	}
	return out
}

// fixedNow is the constant detection time used by the conformance fixtures.
var fixedNow = time.Unix(1_700_000_000, 0).UTC()

// runSingle drives the single-event match fixture through pipeline.Process and
// returns the canonical projection of the emitted findings.
func runSingle(t *testing.T) []canonical {
	t.Helper()
	eng := testEngine(t)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-conformance")
	p := New(eng, em, Selection{Findings: true}, finding.Options{Now: fixedNow}, nil)
	if err := p.Process(sampleEvent(), "fixture"); err != nil {
		t.Fatalf("process: %v", err)
	}
	return projectAll(t, &buf)
}

// runSequence drives the two-event chain fixture through a sequence-tracking
// pipeline and returns the canonical projection of the emitted chain finding.
func runSequence(t *testing.T) []canonical {
	t.Helper()
	eng := seqEngine(t, model.SeverityHigh)
	var buf, diag bytes.Buffer
	em := output.New(&buf, &diag, "run-conformance")
	p := New(eng, em, Selection{Findings: true}, finding.Options{Now: fixedNow}, nil).
		WithSequences(sequence.NewTracker(eng.SequenceRules(), sequence.DefaultConfig()))
	for _, ev := range seqEvents() {
		if err := p.Process(ev, "fixture"); err != nil {
			t.Fatalf("process: %v", err)
		}
	}
	return projectAll(t, &buf)
}

// TestCanonicalEquivalenceDeterministic pins the core invariant: the same event
// stream + same rule set + same finding options render to the same canonical
// findings every time, for both the single-event (FromMatch) and the sequence
// (FromSequence) render entry points the pipeline exercises.
func TestCanonicalEquivalenceDeterministic(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T) []canonical
	}{
		{"single_event", runSingle},
		{"sequence", runSequence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.run(t)
			if len(first) != 1 {
				t.Fatalf("expected exactly one canonical finding, got %d", len(first))
			}
			second := tc.run(t)
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("canonical projection not deterministic:\n first:  %+v\n second: %+v", first, second)
			}
		})
	}
}

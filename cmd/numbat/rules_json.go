package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
	"github.com/perplexityai/numbat/internal/version"
)

// rulesTestResultSchemaVersion identifies the machine-readable result stream
// contract emitted by `rules test --json`. It is intentionally separate from
// the wire record schema (model.SchemaVersion) because this envelope is a
// CLI-adjacent surface, not a record shape emitted by the pipeline. Any
// breaking change to the envelope requires a new major version and updated
// consumers.
const rulesTestResultSchemaVersion = "rules-test-result.v1"

// rulesTestEventResult is one line of the NDJSON stream: the direct-evaluator
// result for a single fixture line. Status distinguishes the result classes
// the contract must expose:
//
//   - "completed":          the event was evaluated and any matching rule is
//     reported in Findings. This is the only status that
//     legitimately reports zero findings as "no match".
//   - "malformed_input":    the fixture line could not be decoded, failed
//     model.Event validation, or the input stream itself
//     failed to scan; Error.Kind is "decode", "validate",
//     or "scan". Fixture processing stops at this event.
//   - "evaluation_failure": at least one compiled rule's CEL program errored
//     at runtime, or the sequence tracker returned an
//     error; EvaluatorErrors names every failing rule
//     (a per-rule CEL failure and a sequence-tracker
//     failure may both appear for the same event).
//     Error.Kind is "sequence" when the tracker failed,
//     otherwise "evaluation". Fixture processing stops.
type rulesTestEventResult struct {
	Type            string                     `json:"type"`
	SchemaVersion   string                     `json:"schema_version"`
	FixtureLine     int                        `json:"fixture_line"`
	EventID         string                     `json:"event_id,omitempty"`
	Status          string                     `json:"status"`
	Findings        []rulesTestFinding         `json:"findings,omitempty"`
	EvaluatorErrors []rulesTestEvaluatorError  `json:"evaluator_errors,omitempty"`
	Coverage        *rulesTestCoverage         `json:"coverage,omitempty"`
	Error           *rulesTestEventErrorDetail `json:"error,omitempty"`
}

// rulesTestFinding is one matched rule for the event. RuleVersion is copied
// from the compiled rule so downstream systems can reason about drift.
// EnforcementEligible is the same flag that would gate the live enforce
// path (already accounting for shell-enforcement-safety); Via reports whether
// the finding came from a single-event evaluation or a completed sequence
// chain so a consumer can attribute chain findings to the terminating event.
type rulesTestFinding struct {
	RuleID              string `json:"rule_id"`
	RuleVersion         string `json:"rule_version"`
	Severity            string `json:"severity,omitempty"`
	EnforcementEligible bool   `json:"enforcement_eligible"`
	Via                 string `json:"via"`
}

// rulesTestEvaluatorError names one rule whose CEL program failed at runtime.
// Emitted alongside any matches that other rules produced for the same event;
// per-rule failure never suppresses another rule's match.
type rulesTestEvaluatorError struct {
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message"`
}

// rulesTestCoverage carries the shared shell-analysis health signal for the
// event. shell_parse is one of "ok" (no shell analysis run or the parse was
// clean), "degraded" (analysis produced errors but at least one command was
// still usable), and "unusable" (parse produced no usable commands and rules
// that depend on shell_commands were skipped). sequence_tracker_active is
// true when the compiled catalog contains at least one sequence rule (i.e.
// a window tracker exists for this run); it does not imply this specific
// event was folded into a window (the tracker only observes events that
// carry a session_id).
type rulesTestCoverage struct {
	ShellParse            string `json:"shell_parse"`
	SequenceTrackerActive bool   `json:"sequence_tracker_active"`
}

// rulesTestEventErrorDetail describes a fixture-stopping failure for one
// event. Kind is one of: "decode" (invalid JSON), "validate"
// (schema/contract violation from model.Event.Validate), "scan" (input
// stream failed to scan, e.g. line too long or IO error; Message names the
// next unread fixture line), "evaluation" (per-rule CEL runtime error,
// aggregated), or "sequence" (window-tracker failure).
type rulesTestEventErrorDetail struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// rulesTestSummary is the terminal object in the stream. Status is
// "completed" when every fixture line was evaluated (including a clean
// no-match run) and "partial" when processing stopped at a malformed or
// failing event. AssertionOutcome captures the --require-match / --expect /
// --expect-none result independently of Status: a fully evaluated fixture
// whose assertions failed is Status="completed", AssertionOutcome="failed".
type rulesTestSummary struct {
	Type             string                    `json:"type"`
	SchemaVersion    string                    `json:"schema_version"`
	Status           string                    `json:"status"`
	EventsEvaluated  int                       `json:"events_evaluated"`
	Matches          int                       `json:"matches"`
	RulesLoaded      int                       `json:"rules_loaded"`
	EnforceEligible  int                       `json:"enforce_eligible_rules"`
	AssertionOutcome string                    `json:"assertion_outcome"`
	AssertionMissing []string                  `json:"assertion_missing,omitempty"`
	StoppedAt        *rulesTestSummaryStopping `json:"stopped_at,omitempty"`
	NumbatVersion    string                    `json:"numbat_version"`
	RecordSchema     string                    `json:"record_schema"`
}

// rulesTestSummaryStopping identifies the fixture line and reason a partial
// run stopped. Reason mirrors the last event_result's status ("malformed_input"
// or "evaluation_failure") so a consumer can dispatch on the summary alone.
type rulesTestSummaryStopping struct {
	FixtureLine int    `json:"fixture_line"`
	Reason      string `json:"reason"`
}

// rulesTestJSONDeliveryExitCode is returned when a stdout write fails at any
// point in the JSON result stream. It is deliberately distinct from the
// partial-run exit (1) and the completed-success exit (0) so a downstream
// consumer that only sees the process exit can distinguish "the evaluator
// ran but the machine-readable result could not be delivered" from "the
// evaluator observed a failure and reported it in a well-formed stream".
const rulesTestJSONDeliveryExitCode = 2

// runRulesTestJSON is the --json branch of `numbat rules test`. It shares
// no state with the legacy path, but reuses the compiled Engine and the
// same sequence.Tracker construction as evalFixture so its match set is
// byte-equivalent to the legacy stream. The JSON encoder is bound to
// stdout; every event_result and the terminal summary are one line each.
// Every write goes through the emit closure so a stdout failure never
// masquerades as a clean run.
func runRulesTestJSON(eng *rule.Engine, r io.Reader, stdout, stderr io.Writer, requireMatch, expectNone bool, expect multiFlag) int {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)

	// deliveryFailed records that at least one enc.Encode returned an error.
	// Once set, no further JSON is written to stdout (a downstream consumer
	// that treats a missing or invalid terminal stream as failure will react
	// correctly), and the function returns rulesTestJSONDeliveryExitCode.
	// This exists because evaluating successfully is not the same as
	// delivering the result: silently swallowing a stdout write failure would
	// let a Guardian-side JSON parser see zero events and infer a clean
	// no-match, which is the exact confusion this contract was added to
	// prevent.
	deliveryFailed := false
	emit := func(v interface{}) bool {
		if deliveryFailed {
			return false
		}
		if err := enc.Encode(v); err != nil {
			deliveryFailed = true
			// Best-effort diagnostic; a broken stderr is deliberately ignored
			// because the nonzero exit code already signals delivery failure to
			// the caller, and a stderr write error here would only mask the
			// original stdout failure.
			_, _ = fmt.Fprintln(stderr, "write rules-test-result:", err.Error())
			return false
		}
		return true
	}

	enforceEligible := eng.CountEnforceEligibleRules()

	var tracker *sequence.Tracker
	seqRules := eng.SequenceRules()
	if len(seqRules) > 0 {
		tracker = sequence.NewTracker(seqRules, sequence.DefaultConfig())
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	matched := 0
	matchedRules := map[string]int{}
	eventsEvaluated := 0
	line := 0
	var stopped *rulesTestSummaryStopping
	streamStatus := "completed"

	// summary is emitted at the end regardless of the outcome; capture stops in
	// stopped so a downstream consumer sees the exact fixture line that failed.
loop:
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			emit(rulesTestEventResult{
				Type:          "event_result",
				SchemaVersion: rulesTestResultSchemaVersion,
				FixtureLine:   line,
				Status:        "malformed_input",
				Error: &rulesTestEventErrorDetail{
					Kind:    "decode",
					Message: fmt.Sprintf("fixture line %d: %s", line, err.Error()),
				},
			})
			stopped = &rulesTestSummaryStopping{FixtureLine: line, Reason: "malformed_input"}
			streamStatus = "partial"
			break loop
		}
		ev = ev.NormalizePaths()
		if err := ev.Validate(); err != nil {
			emit(rulesTestEventResult{
				Type:          "event_result",
				SchemaVersion: rulesTestResultSchemaVersion,
				FixtureLine:   line,
				EventID:       ev.EventID,
				Status:        "malformed_input",
				Error: &rulesTestEventErrorDetail{
					Kind:    "validate",
					Message: fmt.Sprintf("fixture line %d: %s", line, err.Error()),
				},
			})
			stopped = &rulesTestSummaryStopping{FixtureLine: line, Reason: "malformed_input"}
			streamStatus = "partial"
			break loop
		}

		singleMatches, evalErrs, diag := eng.EvalDetailed(ev)
		coverage := &rulesTestCoverage{
			ShellParse:            classifyShellParse(diag),
			SequenceTrackerActive: tracker != nil,
		}

		findings := make([]rulesTestFinding, 0, len(singleMatches))
		for _, m := range singleMatches {
			matched++
			matchedRules[m.Rule.ID]++
			findings = append(findings, rulesTestFinding{
				RuleID:              m.Rule.ID,
				RuleVersion:         m.Rule.Version,
				Severity:            m.Rule.Severity,
				EnforcementEligible: m.EnforcementMatch,
				Via:                 "engine",
			})
		}

		// Convert per-rule single-event evaluator errors into the wire form up
		// front so the sequence-error branch can preserve them alongside a
		// tracker failure. Per-rule CEL errors and a sequence-tracker error can
		// legitimately co-occur for one event; neither may suppress the other.
		evaluatorErrors := make([]rulesTestEvaluatorError, 0, len(evalErrs)+1)
		for _, e := range evalErrs {
			evaluatorErrors = append(evaluatorErrors, rulesTestEvaluatorError{
				RuleID:  e.RuleID,
				Message: e.Message,
			})
		}

		sequenceErrorMessage := ""
		if tracker != nil {
			observation, err := tracker.Observe(ev)
			if err != nil {
				// A sequence-tracker error is a fixture-stopping evaluator failure:
				// the window state cannot be trusted for the remainder of the run.
				// Preserve any per-rule CEL errors above; the two failures are
				// independent and both belong in evaluator_errors.
				sequenceErrorMessage = err.Error()
				evaluatorErrors = append(evaluatorErrors, rulesTestEvaluatorError{
					Message: err.Error(),
				})
			} else {
				enforceIndex := map[string]bool{}
				for _, r := range observation.EnforcementRules {
					enforceIndex[r.ID] = true
				}
				for _, c := range observation.Findings {
					matched++
					matchedRules[c.Rule.ID]++
					findings = append(findings, rulesTestFinding{
						RuleID:              c.Rule.ID,
						RuleVersion:         c.Rule.Version,
						Severity:            c.Rule.Severity,
						EnforcementEligible: enforceIndex[c.Rule.ID],
						Via:                 "sequence",
					})
				}
			}
		}

		status := "completed"
		if len(evalErrs) > 0 || sequenceErrorMessage != "" {
			// Any evaluator failure stops the fixture. Matches from other rules on
			// this same event still surface in Findings; failures are never
			// silently suppressed.
			status = "evaluation_failure"
		}

		result := rulesTestEventResult{
			Type:            "event_result",
			SchemaVersion:   rulesTestResultSchemaVersion,
			FixtureLine:     line,
			EventID:         ev.EventID,
			Status:          status,
			Findings:        findings,
			EvaluatorErrors: evaluatorErrors,
			Coverage:        coverage,
		}
		if status == "evaluation_failure" {
			// error.kind is "sequence" when the tracker itself failed (so a
			// consumer can distinguish a window-state failure from a CEL runtime
			// error), otherwise "evaluation" for one or more per-rule CEL errors.
			switch {
			case sequenceErrorMessage != "":
				result.Error = &rulesTestEventErrorDetail{
					Kind:    "sequence",
					Message: fmt.Sprintf("fixture line %d: %s", line, sequenceErrorMessage),
				}
			default:
				result.Error = &rulesTestEventErrorDetail{
					Kind:    "evaluation",
					Message: fmt.Sprintf("fixture line %d: %d rule(s) failed evaluation", line, len(evalErrs)),
				}
			}
		}
		emit(result)

		// Every fixture line that reached direct evaluation is counted, even one
		// whose evaluation ended in failure. events_evaluated therefore denotes
		// "events that reached direct evaluation", not "events with matches";
		// matches is the total findings across all event_results and may exceed
		// events_evaluated when several rules match one event.
		eventsEvaluated++
		if status == "evaluation_failure" {
			stopped = &rulesTestSummaryStopping{FixtureLine: line, Reason: "evaluation_failure"}
			streamStatus = "partial"
			break loop
		}
	}
	if err := sc.Err(); err != nil {
		// A scanner failure (over-long line, IO error) must still terminate the
		// stream with a well-formed summary; a downstream consumer relying on
		// the terminal object to distinguish partial from truncated pipe would
		// otherwise hit bare EOF. Report the scan failure at the next fixture
		// line so its position is unambiguous, then fall through to the summary
		// emission below.
		emit(rulesTestEventResult{
			Type:          "event_result",
			SchemaVersion: rulesTestResultSchemaVersion,
			FixtureLine:   line + 1,
			Status:        "malformed_input",
			Error: &rulesTestEventErrorDetail{
				Kind:    "scan",
				Message: fmt.Sprintf("scan fixture: %s", err.Error()),
			},
		})
		stopped = &rulesTestSummaryStopping{FixtureLine: line + 1, Reason: "malformed_input"}
		streamStatus = "partial"
		fmt.Fprintln(stderr, "scan fixture:", err.Error())
	}

	// AssertionOutcome is only meaningful for a completed run; a partial run
	// intentionally reports "unchecked" so a consumer never conflates a
	// fixture-processing failure with an assertion failure.
	assertionOutcome := "unchecked"
	var assertionMissing []string
	if streamStatus == "completed" {
		assertionOutcome = "passed"
		if requireMatch && matched == 0 {
			assertionOutcome = "failed"
		}
		if expectNone && matched > 0 {
			assertionOutcome = "failed"
		}
		if missing := missingExpectedRules(expect, matchedRules); len(missing) > 0 {
			assertionOutcome = "failed"
			assertionMissing = missing
		}
		if len(expect) == 0 && !requireMatch && !expectNone {
			assertionOutcome = "unchecked"
		}
	}

	summary := rulesTestSummary{
		Type:             "summary",
		SchemaVersion:    rulesTestResultSchemaVersion,
		Status:           streamStatus,
		EventsEvaluated:  eventsEvaluated,
		Matches:          matched,
		RulesLoaded:      eng.Len(),
		EnforceEligible:  enforceEligible,
		AssertionOutcome: assertionOutcome,
		AssertionMissing: assertionMissing,
		StoppedAt:        stopped,
		NumbatVersion:    version.String(),
		RecordSchema:     model.SchemaVersion,
	}
	emit(summary)

	// A delivery failure at any point in the stream (event_result OR summary)
	// dominates the exit code: the caller must not observe "evaluation ran
	// cleanly, exit 0" when part or all of the machine-readable stream never
	// reached the descriptor. The legacy tab-separated path signals the same
	// class of failure with exit 1 and a stderr message; the JSON path uses a
	// distinct exit (2) so a consumer that also parses exit codes can tell
	// "partial run reported correctly" from "result stream truncated".
	if deliveryFailed {
		return rulesTestJSONDeliveryExitCode
	}
	if streamStatus == "partial" {
		return 1
	}
	if assertionOutcome == "failed" {
		return 1
	}
	return 0
}

// classifyShellParse maps rule.EvalDiagnostics to the coverage.shell_parse
// enum defined in rules-test-result.v1. It preserves the invariant that a
// consumer can distinguish a bounded/unusable shell parse from a clean
// no-match without reading log lines.
func classifyShellParse(diag rule.EvalDiagnostics) string {
	if diag.ShellParseError == nil {
		return "ok"
	}
	if diag.ShellUsable {
		return "degraded"
	}
	return "unusable"
}

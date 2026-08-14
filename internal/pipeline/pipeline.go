// Package pipeline holds the per-event core of a numbat run: take one
// normalized model.Event, evaluate the rule engine against it, and emit the
// selected records (events, findings, indicators) through the shared
// output.Emitter. Every sensor — the on-disk scanner, the live hook handler,
// and the OTel receiver — feeds events through this one path, so a
// finding is produced identically no matter how the event was observed.
package pipeline

import (
	"fmt"
	"strings"

	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
)

// Selection records which record kinds Process should emit for each event. It
// mirrors the scan --emit flag: findings is the default, events and indicators
// are opt-in, and all three may be enabled together.
type Selection struct {
	Events     bool
	Findings   bool
	Indicators bool
}

// Pipeline turns one event into the selected output records. It holds the
// per-run dependencies (engine, emitter, finding options) so Process stays a
// small, reusable step. A nil engine simply disables rule evaluation; event-only
// and indicator-only streams do not need rules, and an accidentally attached
// enforce decision cannot turn a missing engine into a deny path.
//
// Indicators are folded over the whole run, so Process feeds each event to the
// accumulator but never materializes it; the caller chooses when to snapshot it.
type Pipeline struct {
	engine     *rule.Engine
	emit       *output.Emitter
	sel        Selection
	fopts      finding.Options
	indicators *output.IndicatorAccumulator
	enforce    *EnforceDecision
	seq        SequenceObserver
}

// SequenceObserver is the window that evaluates sequence rules per event —
// sequence.Tracker in-memory for scan and collect, sequence.Store persisted
// for the process-per-event hook. The pipeline only needs the one method.
type SequenceObserver interface {
	Observe(model.Event) (sequence.Observation, error)
}

// EnforceDecision accumulates matches for an enforce-capable pre-action hook.
// It is the only channel through which the detection pipeline can authorize a
// deny, and is never used by scan or collect. Blocked is set only by a clean
// run, so an error path cannot authorize enforcement.
type EnforceDecision struct {
	// ObserveOnly is true for a monitor-mode or already-uncertain pre-action
	// hook. The zero value preserves the original enforcement accumulator
	// contract: a clean eligible match may block.
	ObserveOnly bool
	// Blocked is true when an enforce-eligible match has been proven and no
	// output or processing failure has tainted the decision.
	Blocked bool
	// Tainted is true once this hook payload encounters an output or processing
	// failure that makes a deny unsafe. A later clean event cannot restore it.
	Tainted bool
	// Reason is the generic denial message or the first eligible rule's explicit
	// override.
	Reason string

	// The remaining fields are identifier-only context for the enforcement
	// decision record. They never retain observed command or file content.
	Matched         bool
	ActionEventIDs  []string
	FindingIDs      []string
	RuleIDs         []string
	DenyRuleID      string
	DenyRuleVersion string
	CaseID          string
	SourceAgent     string
	SourceType      string
	SessionID       string
	Model           string
	ModelProvider   string
	SubAgent        string
	ToolName        string
	ToolCallID      string
}

// WithEnforce attaches the live hook's enforcement accumulator. Monitor mode
// uses an observe-only accumulator so it can report no_override without ever
// authorizing a deny. A nil accumulator keeps the pipeline detection-only.
func (p *Pipeline) WithEnforce(d *EnforceDecision) *Pipeline {
	p.enforce = d
	return p
}

// WithSequences attaches the window that evaluates the engine's sequence
// rules. Scan and collect set it when findings are selected; the hook also sets
// it when enforcement needs sequence state. The hook uses the persisted store
// (or omits it when the store is unavailable, its fail-open path), while other
// sensors use an in-memory tracker. Leaving it unset keeps correlation off.
//
// In live enforce mode, an eligible chain may deny only its final-step action;
// earlier observed steps are never retroactively blocked.
func (p *Pipeline) WithSequences(t SequenceObserver) *Pipeline {
	p.seq = t
	return p
}

// New constructs a Pipeline. indicators may be nil when Selection.Indicators is
// false; when indicators are selected the caller owns the accumulator and its
// cumulative snapshots.
func New(engine *rule.Engine, emit *output.Emitter, sel Selection, fopts finding.Options, indicators *output.IndicatorAccumulator) *Pipeline {
	return &Pipeline{engine: engine, emit: emit, sel: sel, fopts: fopts, indicators: indicators}
}

// Process runs one event through the selected steps: emit the event, evaluate
// rules and emit any findings, and fold the event into the indicator
// accumulator. source is a short label for the event's origin (an artifact path
// for scan, an agent name for hooks) used only in diagnostics so a reader can
// locate the failing input; pass "" when there is no meaningful source.
//
// Per-record emit failures and rule-evaluation errors become diagnostics and do
// not abort the surrounding run. An event that violates the normalized contract
// is rejected before emission or evaluation and returned to the sensor.
func (p *Pipeline) Process(ev model.Event, source string) error {
	ev = ev.NormalizePaths()
	if err := ev.Validate(); err != nil {
		return fmt.Errorf("invalid %q event %s: %w", source, ev.EventID, err)
	}
	if p.sel.Events {
		if err := p.emit.EmitEvent(ev); err != nil {
			p.emit.Diag("error", fmt.Sprintf("emit event %s: %v", ev.EventID, err))
		}
	}
	if (p.sel.Findings || p.enforce != nil) && p.engine != nil {
		matches, evalErr := p.engine.Eval(ev)
		// Rule evaluation scopes uncertainty to the predicate that failed: a clean
		// enforcement match remains usable when an unrelated rule reports an
		// error. Output failures still taint the decision because a deny must not
		// outrun its operator record.
		clean := true
		// firstEligible holds the first enforce-eligible match seen this run. The
		// enforce decision is applied only AFTER the loop, and only if clean stayed
		// true throughout — so an EmitFinding failure on ANY match (not just the
		// eligible one) suppresses the block.
		var firstEligible *rule.Rule
		for i := range matches {
			m := matches[i]
			findingID := ""
			if p.sel.Findings {
				f := finding.FromMatch(m, p.fopts)
				if !p.emitFinding(f) {
					clean = false
				} else {
					findingID = f.FindingID
				}
			}
			if p.enforce != nil {
				p.enforce.recordMatch(ev, m.Rule, findingID)
			}
			if firstEligible == nil && m.EnforcementMatch {
				r := m.Rule
				firstEligible = &r
			}
		}
		// Feed the event through the sequence window. Detection matches remain
		// subject to max_matches; the independent enforcement channel is uncapped
		// so a finding quota can never become a policy bypass. Sequence evaluation
		// likewise scopes uncertainty to the affected step; finding-delivery
		// errors still taint the decision.
		var seqErr error
		if p.seq != nil && (p.sel.Findings || p.enforce != nil) {
			var observation sequence.Observation
			observation, seqErr = p.seq.Observe(ev)
			if p.sel.Findings {
				for _, c := range observation.Findings {
					f := finding.FromSequence(c, p.fopts)
					if !p.emitFinding(f) {
						clean = false
					} else if p.enforce != nil {
						p.enforce.recordMatch(ev, c.Rule, f.FindingID)
					}
				}
			}
			if p.enforce != nil {
				for _, r := range observation.EnforcementRules {
					p.enforce.recordMatch(ev, r, "")
				}
			}
			if firstEligible == nil && len(observation.EnforcementRules) > 0 {
				r := observation.EnforcementRules[0]
				firstEligible = &r
			}
		}
		if message := uniqueErrorMessage(evalErr, seqErr); message != "" {
			p.emit.Diag("warn", fmt.Sprintf("rule evaluation %q event %s: %s", source, ev.EventID, message))
		}
		// Authorize an enforceable match only on a clean run. Monitor mode uses the
		// same accumulator with ObserveOnly set, so it records matches without ever
		// setting Blocked.
		if p.enforce != nil {
			if !clean {
				p.enforce.Tainted = true
				p.enforce.Blocked = false
				p.enforce.Reason = ""
				p.enforce.DenyRuleID = ""
				p.enforce.DenyRuleVersion = ""
			} else if !p.enforce.ObserveOnly && !p.enforce.Tainted && !p.enforce.Blocked && firstEligible != nil {
				p.enforce.Blocked = true
				p.enforce.Reason = denyMessage(*firstEligible)
				p.enforce.DenyRuleID = firstEligible.ID
				p.enforce.DenyRuleVersion = firstEligible.Version
			}
		}
	}
	if p.sel.Indicators {
		if p.indicators.Add(ev) {
			p.emit.Diag("warn", "indicator analysis reached a safety limit; some candidates may be omitted")
		}
	}
	return nil
}

func uniqueErrorMessage(errs ...error) string {
	seen := make(map[string]struct{})
	var messages []string
	var add func(error)
	add = func(err error) {
		if err == nil {
			return
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				add(child)
			}
			return
		}
		message := err.Error()
		if _, ok := seen[message]; ok {
			return
		}
		seen[message] = struct{}{}
		messages = append(messages, message)
	}
	for _, err := range errs {
		add(err)
	}
	return strings.Join(messages, "\n")
}

func (d *EnforceDecision) recordMatch(ev model.Event, r rule.Rule, findingID string) {
	d.Matched = true
	d.ActionEventIDs = appendUnique(d.ActionEventIDs, ev.EventID)
	d.RuleIDs = appendUnique(d.RuleIDs, r.ID)
	if findingID != "" {
		d.FindingIDs = appendUnique(d.FindingIDs, findingID)
	}
	if d.SourceAgent != "" {
		return
	}
	d.CaseID = ev.CaseID
	d.SourceAgent = ev.SourceAgent
	d.SourceType = ev.SourceType
	d.SessionID = ev.SessionID
	d.Model = ev.Model
	d.ModelProvider = ev.ModelProvider
	d.SubAgent = ev.SubAgent
	d.ToolName = ev.ToolName
	d.ToolCallID = ev.ToolCallID
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// emitFinding emits one rendered finding, reporting whether the emit succeeded.
// An emit failure is the caller's to fold into clean.
func (p *Pipeline) emitFinding(f model.Finding) bool {
	if err := p.emit.EmitFinding(f); err != nil {
		p.emit.Diag("error", fmt.Sprintf("emit finding %s: %v", f.FindingID, err))
		return false
	}
	return true
}

const defaultDenyMessage = "Action denied. Do not retry or attempt an equivalent action."

func denyMessage(r rule.Rule) string {
	if r.DenyMessage != "" {
		return r.DenyMessage
	}
	return defaultDenyMessage
}

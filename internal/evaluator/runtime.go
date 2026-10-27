package evaluator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
)

// Evaluation is one source action, possibly expanded into several normalized
// events. A rule is evaluated once using its first selected event.
type Evaluation struct {
	Events   []model.Event
	Evidence func(model.Event, string) decision.Evidence
	Confirm  func(context.Context, decision.Request) (uint64, error)
	Control  *pipeline.EnforceDecision
}

// Evaluate contributes evidence and findings, never a native control response.
// The host controller retains the final output and admission gates.
func (c *Config) Evaluate(ctx context.Context, in Evaluation, em *output.Emitter) {
	c.prepare(in).run(ctx, c, em, nil)
}

type plannedRule struct {
	configured ConfiguredRule
	invocation Invocation
	eventIndex int
	result     evaluationResult
}

type evaluationPlan struct {
	in           Evaluation
	invocationID string
	rules        []plannedRule
}

func (c *Config) prepare(in Evaluation) *evaluationPlan {
	plan := &evaluationPlan{in: in, invocationID: rand.Text()}
	if len(in.Events) == 0 || in.Evidence == nil {
		return plan
	}
	deterministicDeny := in.Control != nil && in.Control.Blocked && in.Control.DenyAssessmentID == ""
	for _, configured := range c.Rules {
		b, p := configured.Binding, configured.Compiled
		job := plannedRule{
			configured: configured,
			invocation: Invocation{
				Policy: p, Binding: b, Profile: c.Provider.Profile,
				Event: in.Events[0], Confirm: in.Confirm, DeterministicDeny: deterministicDeny,
			},
			result: evaluationResult{assessment: decision.Failure("skipped", "not_selected")},
		}
		for i, candidate := range in.Events {
			selected, err := p.Select(candidate)
			if err != nil {
				job.result.assessment = decision.Failure("skipped", "selector_error")
				break
			}
			if selected {
				job.eventIndex = i
				job.invocation.Event, job.invocation.selected = candidate, true
				job.invocation.Evidence = in.Evidence(candidate, b.View)
				break
			}
		}
		plan.rules = append(plan.rules, job)
	}
	// Evidence has been frozen for every applicable rule; queued work must not
	// retain a callback that could observe future activity or retain raw payloads.
	plan.in.Evidence = nil
	return plan
}

const concurrentDecisions = 2

func (p *evaluationPlan) run(parent context.Context, c *Config, em *output.Emitter, outputMu sync.Locker) {
	p.runWithFactory(parent, c, em, outputMu, c.Factory())
}

func (p *evaluationPlan) runWithFactory(parent context.Context, c *Config, em *output.Emitter, outputMu sync.Locker, factory Factory) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.BudgetMS)*time.Millisecond)
	defer cancel()
	work, cancelWork := context.WithCancelCause(ctx)
	defer cancelWork(nil)
	pending := make([]int, 0, len(p.rules))
	for i := range p.rules {
		if p.rules[i].invocation.selected {
			pending = append(pending, i)
		} else {
			p.record(ctx, c, em, i, outputMu)
		}
	}
	type completed struct {
		index  int
		result evaluationResult
	}
	done := make(chan completed, concurrentDecisions)
	next, active := 0, 0
	denied := false
	for next < len(pending) || active > 0 {
		for next < len(pending) && active < concurrentDecisions && ctx.Err() == nil && !denied {
			i := pending[next]
			next++
			active++
			go func() { done <- completed{i, evaluate(work, p.rules[i].invocation, factory)} }()
		}
		if active == 0 {
			break
		}
		finished := <-done
		active--
		p.rules[finished.index].result = finished.result
		p.record(ctx, c, em, finished.index, outputMu)
		if p.in.Control != nil && p.in.Control.Blocked && p.in.Control.DenyAssessmentID != "" {
			denied = true
			cancelWork(errPriorSemanticDeny)
		}
	}
	for _, i := range pending[next:] {
		status, reason := "timeout", "deadline"
		if denied {
			status, reason = "skipped", "prior_semantic_deny"
		}
		p.rules[i].result = evaluationResult{assessment: decision.Failure(status, reason)}
		p.record(ctx, c, em, i, outputMu)
	}
}

func (p *evaluationPlan) skip(c *Config, em *output.Emitter, reason string, outputMu sync.Locker) {
	for i := range p.rules {
		if p.rules[i].invocation.selected {
			p.rules[i].result = evaluationResult{assessment: decision.Failure("skipped", reason)}
		}
		p.record(context.Background(), c, em, i, outputMu)
	}
}

func (p *evaluationPlan) record(ctx context.Context, c *Config, em *output.Emitter, i int, outputMu sync.Locker) {
	if outputMu != nil {
		outputMu.Lock()
		defer outputMu.Unlock()
	}
	job := &p.rules[i]
	configured, ev := job.configured, job.invocation.Event
	b := configured.Binding
	a := job.result.finish(ctx, job.invocation)
	a.PolicyID, a.PolicyVersion, a.View = configured.Rule.ID, configured.Rule.Version, b.View
	a.RuleDigest = configured.Compiled.Digest()
	a.MatchThreshold, a.DenyThreshold = b.MatchThreshold, b.DenyThreshold
	if b.Mode == decision.Enforce && p.in.Control != nil && !p.in.Control.ObserveOnly {
		switch {
		case a.Status == "completed" && !a.InputEligible:
			em.Diag("warn", "decision rule "+configured.Rule.ID+": evidence ineligible for blocking; inspect assessment gaps")
		case a.Status != "completed" && a.Reason != "not_selected" &&
			a.Reason != "deterministic_deny" && a.Reason != "prior_semantic_deny":
			em.Diag("warn", "decision rule "+configured.Rule.ID+": check unavailable ("+a.Reason+"); no model deny")
		}
	}
	if a.DenyCandidate && (p.in.Control == nil || p.in.Control.ObserveOnly || p.in.Control.Tainted) {
		a.DenyCandidate, a.Reason = false, "native_enforcement_ineligible"
	}
	sum := sha256.Sum256([]byte(p.invocationID + "\x00" + ev.EventID + "\x00" + a.RuleDigest + "\x00" + b.View + "\x00" + a.RequestID))
	id := "asm-" + hex.EncodeToString(sum[:12])
	eventIDs := make([]string, len(p.in.Events))
	for i, event := range p.in.Events {
		eventIDs[i] = event.EventID
	}
	record := output.DecisionAssessment{
		Assessment: a, AssessmentID: id, SchemaVersion: model.SchemaVersion,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano), CaseID: ev.CaseID,
		SourceAgent: ev.SourceAgent, SourceType: ev.SourceType,
		SessionID: ev.SessionID, SessionTreeID: ev.SessionTreeID, SubAgentID: ev.SubAgentID,
		ToolCallID: ev.ToolCallID, ActionEventIDs: eventIDs,
		Provider: c.Provider.Protocol, ProviderModel: c.Provider.Model,
		ConfigDigest: c.Digest(), BindingMode: b.Mode,
	}
	if err := em.EmitAssessment(record); err != nil || !a.Matched {
		return
	}
	r := configured.Rule
	r.Tags = append(slices.Clone(r.Tags), "decision_model", "decision_view:"+b.View)
	f := finding.FromMatch(rule.Match{Rule: r, Event: ev}, finding.Options{AssessmentID: id})
	f.CitedEventIDs = slices.Clone(eventIDs)
	f.DecisionGaps = slices.Clone(a.Gaps)
	if err := em.EmitFinding(f); err != nil {
		return
	}
	if p.in.Control != nil {
		deny := a.DenyCandidate
		var confirm func(context.Context) bool
		if deny {
			// Retain only the identity needed for a final state read, not the
			// request's evidence. The hook supplies its remaining delivery budget.
			request := decision.Request{Subject: job.result.request.Subject, Revision: job.result.request.Revision}
			confirmState := job.invocation.Confirm
			confirm = func(ctx context.Context) bool {
				if ctx.Err() != nil {
					return false
				}
				if b.View == decision.Action {
					return true
				}
				if confirmState == nil {
					return false
				}
				revision, err := confirmState(ctx, request)
				return err == nil && ctx.Err() == nil && revision == request.Revision
			}
			// Do not choose a stale winner and cancel its siblings merely
			// because it was eligible before blocking record writes.
			checkCtx, cancel := context.WithDeadline(ctx, job.result.request.Deadline)
			deny = confirm(checkCtx)
			cancel()
			if !deny {
				em.Diag("warn", "decision rule "+r.ID+": eligibility changed during record delivery; no model deny")
			}
		}
		p.in.Control.RecordDecisionMatch(ev, r, f.FindingID, id, deny, eventIDs)
		if p.in.Control.DenyAssessmentID == id {
			p.in.Control.ConfirmDeny = confirm
		}
	}
}

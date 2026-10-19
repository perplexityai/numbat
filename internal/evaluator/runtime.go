package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
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
	if len(in.Events) == 0 || in.Evidence == nil {
		return
	}
	deterministicDeny := in.Control != nil && in.Control.Blocked && in.Control.DenyAssessmentID == ""
	for _, configured := range c.Rules {
		b, p := configured.Binding, configured.Compiled
		ev := in.Events[0]
		for _, candidate := range in.Events {
			if selected, err := p.Select(candidate); selected || err != nil {
				ev = candidate
				break
			}
		}
		e := in.Evidence(ev, b.View)
		var a decision.Assessment
		if in.Control != nil && in.Control.Blocked && in.Control.DenyAssessmentID != "" {
			a = decision.Failure("skipped", "prior_semantic_deny")
		} else {
			a = Run(ctx, Invocation{
				Policy: p, Binding: b, Profile: c.Provider.Profile,
				Event: ev, Evidence: e, Confirm: in.Confirm,
				DeterministicDeny: deterministicDeny,
			}, c.Factory())
		}
		a.PolicyID, a.PolicyVersion, a.View = configured.Rule.ID, configured.Rule.Version, b.View
		a.RuleDigest = p.Digest()
		a.MatchThreshold, a.DenyThreshold = b.MatchThreshold, b.DenyThreshold
		if a.DenyCandidate && (in.Control == nil || in.Control.ObserveOnly || in.Control.Tainted) {
			a.DenyCandidate, a.Reason = false, "native_enforcement_ineligible"
		}
		sum := sha256.Sum256([]byte(ev.EventID + "\x00" + a.PolicyID + "\x00" + b.View + "\x00" + a.RequestID))
		id := "asm-" + hex.EncodeToString(sum[:12])
		eventIDs := make([]string, len(in.Events))
		for i, event := range in.Events {
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
			continue
		}
		r := configured.Rule
		r.Tags = append(slices.Clone(r.Tags), "decision_model", "decision_view:"+b.View)
		f := finding.FromMatch(rule.Match{Rule: r, Event: ev}, finding.Options{})
		f.CitedEventIDs = slices.Clone(eventIDs)
		f.AssessmentID, f.DecisionGaps = id, slices.Clone(a.Gaps)
		if err := em.EmitFinding(f); err != nil {
			continue
		}
		if in.Control != nil {
			in.Control.RecordDecisionMatch(ev, r, f.FindingID, id, a.DenyCandidate, eventIDs)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/evaluator"
	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/state"
)

// The existing decoder retains its contract for ordinary rules. Optional
// semantic decisions additionally reject duplicate keys before projection.
func decodeDecisionPayload(stdin io.Reader, enabled bool) (map[string]any, bool, error) {
	var raw bytes.Buffer
	if enabled {
		stdin = io.TeeReader(stdin, &raw)
	}
	payload, err := decodeHookPayload(stdin)
	return payload, err == nil && (!enabled || decision.ValidJSON(raw.Bytes())), err
}

func validateDecisionHook(c *evaluator.Config, agent string, sel emitSelection, sinks outputSinks, httpTimeout time.Duration) error {
	if c == nil || !c.Enabled {
		return nil
	}
	if agent != hook.AgentClaude || !sel.findings || sinks.stdout {
		return errors.New("decision evaluation requires Claude hooks, findings, and file or HTTP output")
	}
	sinkBudget := time.Duration(0)
	if sinks.http {
		sinkBudget = httpTimeout
	}
	if time.Duration(c.BudgetMS)*time.Millisecond+time.Second+sinkBudget > 9*time.Second {
		return fmt.Errorf("decision budget %dms + local reserve 1000ms + HTTP sink timeout %dms exceeds the 9000ms hook budget", c.BudgetMS, sinkBudget.Milliseconds())
	}
	return nil
}

// runHookDecisions never returns a global processing error. Configuration,
// state, and provider failures affect this optional participant only. Failed
// record writes still reach the existing emitter's global clean-output gate.
func runHookDecisions(started time.Time, agent string, lc hook.Lifecycle, payload map[string]any,
	events []model.Event, opts hookOptions, em *output.Emitter, eng *rule.Engine,
	dec *pipeline.EnforceDecision, payloadClean bool,
) {
	if opts.decisionConfig == "" {
		return
	}
	c, err := evaluator.LoadConfig(opts.decisionConfig, opts.decisionUserConfig)
	if err != nil {
		em.Diag("warn", "decision evaluation unavailable: invalid or unreadable configuration")
		return
	}
	if !c.Enabled {
		return
	}
	sinks, err := parseOutputSinks(opts.modes, outputModeStdout)
	if err != nil || validateDecisionHook(c, agent, opts.sel, sinks, opts.httpTO) != nil {
		em.Diag("warn", "decision evaluation unavailable: unsupported hook or output budget")
		return
	}
	o, supported := hook.DecisionObservation(lc, agent, events, payload, c.Content)
	if !supported {
		return
	}
	o.Subject.Installation = c.InstallationID
	o.Subject.Generation = "action-" + runID()
	if !payloadClean {
		o.Phase, o.Complete = "gap", false
	}
	ctx, cancel := context.WithDeadline(context.Background(), started.Add(time.Duration(c.BudgetMS)*time.Millisecond))
	defer cancel()
	var snapshot decision.Evidence
	var stateErr error
	sessionEnabled := false
	for _, b := range c.Bindings {
		sessionEnabled = sessionEnabled || (b.Enabled && b.SendContent && b.View == decision.Session)
	}
	if sessionEnabled {
		var db *state.DB
		db, stateErr = openDecisionState(ctx, opts.stateDB)
		if stateErr == nil {
			if o.Subject.SubAgentID != "" {
				// Separate child histories must not promote a parent whose
				// evidence omits delegated work. Persist this gap first.
				parent := decision.Observation{Subject: o.Subject, Phase: "gap"}
				parent.Subject.SubAgentID = ""
				_, stateErr = db.ObserveDecision(c.Digest(), parent, c.State, time.Now())
			}
			if stateErr == nil {
				snapshot, stateErr = db.ObserveDecision(c.Digest(), o, c.State, time.Now())
			}
			stateErr = errors.Join(stateErr, db.Close())
		}
		if stateErr != nil {
			em.Diag("warn", "decision context unavailable; contextual enforcement skipped")
		}
	}
	if o.Phase != "pre" || len(events) == 0 {
		return
	}
	if opts.decisionReceipt != nil && sessionEnabled && stateErr == nil {
		*opts.decisionReceipt = decisionDenyReceipt{
			path: opts.stateDB, namespace: c.Digest(), limits: c.State,
			expected: decision.Evidence{
				Subject: snapshot.Subject, Revision: snapshot.Revision, Current: snapshot.Current,
			},
			deadline: started.Add(9 * time.Second),
		}
	}
	ev := events[len(events)-1]
	operator, _ := json.Marshal(c.OperatorContext)
	deterministicDeny := dec != nil && dec.Blocked
	for _, configured := range c.Bindings {
		b := configured.Binding
		if !b.Enabled || configured.Compiled == nil {
			continue
		}
		p := configured.Compiled.Policy()
		e := decision.Evidence{
			Subject: o.Subject, Current: o.Action, OperatorContext: operator, CurrentComplete: o.Complete,
		}
		if b.View == decision.Session {
			if stateErr == nil {
				e = snapshot
				e.OperatorContext = operator
			} else {
				e.Gaps = []string{"state_unavailable"}
			}
		}
		var a decision.Assessment
		switch {
		case eng != nil && slices.Contains(eng.RuleIDs(), p.ID):
			a = decision.Failure("skipped", "deterministic_policy_id_collision")
		case dec != nil && dec.Blocked && dec.DenyPolicyID != "":
			// Do not extend a confirmed deny's control window with more provider I/O.
			a = decision.Failure("skipped", "prior_semantic_deny")
		default:
			provider := c.Providers[configured.Provider]
			a = evaluator.Run(ctx, evaluator.Invocation{
				Policy: configured.Compiled, Binding: b, Profile: provider.Profile,
				Event: ev, Evidence: e, DeterministicDeny: deterministicDeny,
				Confirm: func(ctx context.Context, request decision.Request) (uint64, error) {
					db, err := openDecisionState(ctx, opts.stateDB)
					if err != nil {
						return 0, err
					}
					revision, err := db.ConfirmDecision(c.Digest(), request, time.Now(), time.Duration(c.State.IdleTTLMS)*time.Millisecond)
					return revision, errors.Join(err, db.Close())
				},
			}, c.Factory(configured.Provider))
		}
		a.PolicyID, a.PolicyVersion, a.View = p.ID, p.Version, b.View
		a.MatchThreshold, a.DenyThreshold = b.MatchThreshold, b.DenyThreshold
		if a.DenyCandidate && (!c.NoArgumentRewriters || o.Subject.SubAgentID != "") {
			a.DenyCandidate = false
			a.Reason = "host_argument_finality_unconfirmed"
		}
		if a.DenyCandidate && (!opts.enforce || dec == nil || dec.ObserveOnly || dec.Tainted || !payloadClean) {
			a.DenyCandidate = false
			a.Reason = "native_enforcement_ineligible"
		}
		sum := sha256.Sum256([]byte(ev.EventID + "\x00" + p.ID + "\x00" + b.View + "\x00" + a.RequestID))
		assessmentID := "asm-" + hex.EncodeToString(sum[:12])
		record := output.DecisionAssessment{
			Assessment: a, AssessmentID: assessmentID, SchemaVersion: model.SchemaVersion,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano), CaseID: ev.CaseID,
			SourceAgent: ev.SourceAgent, SourceType: model.SourceHook,
			SessionID: ev.SessionID, SessionTreeID: ev.SessionTreeID, SubAgentID: ev.SubAgentID,
			ToolCallID: ev.ToolCallID, ActionEventIDs: []string{ev.EventID},
			Provider: configured.Provider, ProviderModel: c.Providers[configured.Provider].Model,
			ConfigDigest: c.Digest(), BindingMode: b.Mode, AllowUserOwned: opts.decisionUserConfig,
		}
		if err := em.EmitAssessment(record); err != nil {
			continue
		}
		if !a.Matched || !a.InputEligible {
			continue
		}
		r := rule.Rule{ID: p.ID, Version: p.Version, Title: p.Title, Severity: p.Severity, Tags: []string{"decision_model", "decision_view:" + b.View}}
		f := finding.FromMatch(rule.Match{Rule: r, Event: ev}, findingOptions())
		sum = sha256.Sum256([]byte(f.FindingID + "\x00" + b.View))
		f.FindingID = "fnd-" + hex.EncodeToString(sum[:12])
		if err := em.EmitFinding(f); err != nil || dec == nil {
			continue
		}
		recordDecisionMatch(dec, ev, r, f.FindingID, assessmentID, a.DenyCandidate)
	}
}

// A successful control write is a deny request, not proof of host blocking.
// Record it only after the global output gate and the complete control write.
// A failed/stale state update leaves the proposal unresolved; it must not
// retract the independent deny or make a later prefix appear complete.
type decisionDenyReceipt struct {
	path, namespace string
	expected        decision.Evidence
	limits          decision.ContextLimits
	deadline        time.Time
}

func (r decisionDenyReceipt) record() {
	if r.namespace == "" {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), r.deadline)
	defer cancel()
	db, err := openDecisionState(ctx, r.path)
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	_ = db.RecordDecisionDeny(r.namespace, r.expected, r.limits, time.Now())
}

func recordDecisionMatch(d *pipeline.EnforceDecision, ev model.Event, r rule.Rule, findingID, assessmentID string, deny bool) {
	if !d.Matched {
		d.CaseID, d.SourceAgent, d.SourceType = ev.CaseID, ev.SourceAgent, ev.SourceType
		d.SessionID, d.SessionTreeID, d.ParentSessionID = ev.SessionID, ev.SessionTreeID, ev.ParentSessionID
		d.Model, d.ModelProvider, d.SubAgent, d.SubAgentID = ev.Model, ev.ModelProvider, ev.SubAgent, ev.SubAgentID
		d.ToolName, d.ToolCallID = ev.ToolName, ev.ToolCallID
	}
	d.Matched = true
	if !slices.Contains(d.ActionEventIDs, ev.EventID) {
		d.ActionEventIDs = append(d.ActionEventIDs, ev.EventID)
	}
	d.FindingIDs = append(d.FindingIDs, findingID)
	d.AssessmentIDs = append(d.AssessmentIDs, assessmentID)
	if deny && !d.Blocked && !d.Tainted && !d.ObserveOnly {
		d.Blocked = true
		d.Reason = "Action denied. Do not retry or attempt an equivalent action."
		d.DenyPolicyID, d.DenyPolicyVersion, d.DenyAssessmentID = r.ID, r.Version, assessmentID
	}
}

func openDecisionState(ctx context.Context, path string) (*state.DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".numbat", "state.db")
	}
	timeout := 250 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	return state.OpenEvidence(path, timeout)
}

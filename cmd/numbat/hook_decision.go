package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/evaluator"
	"github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/state"
)

func decodeDecisionPayload(stdin io.Reader, enabled bool) (map[string]any, bool, error) {
	var raw bytes.Buffer
	if enabled {
		stdin = io.TeeReader(stdin, &raw)
	}
	payload, err := decodeHookPayload(stdin)
	return payload, err == nil && (!enabled || decision.ValidJSON(raw.Bytes())), err
}

func validateDecisionHook(c *evaluator.Config, sel emitSelection, sinks outputSinks, httpTimeout time.Duration) error {
	if c == nil {
		return nil
	}
	if !sel.findings {
		return errors.New("decision evaluation requires findings output")
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

// Configuration and inference failures affect only the optional evaluator.
// Record failures still reach the existing global clean-output gate.
func runHookDecisions(started time.Time, rawEvent, agent string, lc hook.Lifecycle, payload map[string]any,
	events []model.Event, opts hookOptions, em *output.Emitter, eng *rule.Engine,
	control *pipeline.EnforceDecision, payloadClean bool,
) {
	if opts.decisionConfig == "" {
		return
	}
	c, err := evaluator.LoadConfig(opts.decisionConfig)
	if err != nil || c.ConfigureRules(eng.DecisionRules()) != nil {
		em.Diag("warn", "decision evaluation unavailable: invalid configuration")
		return
	}
	sinks, err := parseOutputSinks(opts.modes, outputModeStdout)
	if err != nil || validateDecisionHook(c, opts.sel, sinks, opts.httpTO) != nil {
		em.Diag("warn", "decision evaluation unavailable: unsupported output budget")
		return
	}
	o, supported := hook.DecisionObservation(rawEvent, lc, agent, events, payload, c.Content)
	if !supported {
		return
	}
	o.Subject.Installation, o.Subject.Generation = c.InstallationID, "action-"+runID()
	if !payloadClean {
		o.Phase, o.Complete = "gap", false
	}
	ctx, cancel := context.WithDeadline(context.Background(), started.Add(time.Duration(c.BudgetMS)*time.Millisecond))
	defer cancel()
	var snapshot decision.Evidence
	var stateErr error
	sessionEnabled := false
	for _, r := range c.Rules {
		sessionEnabled = sessionEnabled || r.View == decision.Session
	}
	if sessionEnabled {
		var db *state.DB
		db, stateErr = openDecisionState(ctx, opts.stateDB)
		if stateErr == nil {
			if o.Parent != nil {
				parent := decision.Observation{Subject: *o.Parent, Phase: "gap"}
				parent.Subject.Installation = c.InstallationID
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
	if o.Phase == "start" || o.Phase == "end" || o.Phase == "gap" {
		return
	}
	if o.Phase == "pre" && opts.decisionReceipt != nil && sessionEnabled && stateErr == nil {
		*opts.decisionReceipt = decisionDenyReceipt{
			path: opts.stateDB, namespace: c.Digest(), limits: c.State,
			expected: decision.Evidence{Subject: snapshot.Subject, Revision: snapshot.Revision, Current: snapshot.Current},
			deadline: started.Add(9 * time.Second),
		}
	}
	operator, _ := json.Marshal(c.OperatorContext)
	c.Evaluate(ctx, evaluator.Evaluation{
		Events: events, Control: control,
		Evidence: func(ev model.Event, view string) decision.Evidence {
			e := decision.Evidence{
				Subject: o.Subject, Current: o.Current(), CurrentComplete: o.Complete,
				OperatorContext: operator,
			}
			if view == decision.Session {
				if stateErr == nil {
					e = snapshot
					e.Current = o.Current()
					e.OperatorContext = operator
				} else {
					e.Gaps = []string{"state_unavailable"}
				}
			}
			e.Subject.EventID = ev.EventID
			return e
		},
		Confirm: func(ctx context.Context, request decision.Request) (uint64, error) {
			db, err := openDecisionState(ctx, opts.stateDB)
			if err != nil {
				return 0, err
			}
			revision, err := db.ConfirmDecision(c.Digest(), request, time.Now(), time.Duration(c.State.IdleTTLMS)*time.Millisecond)
			return revision, errors.Join(err, db.Close())
		},
	}, em)
}

// A receipt is only a completed deny request, never proof of host blocking.
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

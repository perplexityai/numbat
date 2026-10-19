// Package evaluator is the optional monitoring-side provider boundary.
package evaluator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
)

var (
	ErrResponse = errors.New("invalid decision response")
	ErrInput    = errors.New("invalid or oversized decision input")
)

// Provider implementations must respect cancellation and perform no tool or
// remediation side effects. The native path does not load arbitrary plugins.
// The compiled policy is immutable; adapters verify its request binding rather
// than constructing another CEL engine or evaluating the selector again.
type Provider interface {
	Evaluate(context.Context, decision.Request, *decision.Compiled, int) (decision.Reply, error)
}

type Factory func(Profile) (Provider, error)

type Invocation struct {
	Policy            *decision.Compiled
	Binding           decision.Binding
	Profile           Profile
	Event             model.Event
	Evidence          decision.Evidence
	DeterministicDeny bool
	// Confirm reads state without holding a DB handle across provider I/O.
	// Session mode is never enforce-eligible without a successful confirmation.
	Confirm func(context.Context, decision.Request) (uint64, error)
}

// Run returns only an assessment. The caller retains global enforcement,
// native-host eligibility and the existing clean-output gate.
func Run(parent context.Context, in Invocation, factory Factory) (assessment decision.Assessment) {
	fail := decision.Failure
	defer func() {
		if recover() != nil {
			assessment = fail("unavailable", "evaluator_panic")
		}
	}()
	b := in.Binding
	if !b.Enabled {
		return decision.Failure("skipped", "disabled")
	}
	if !b.SendContent {
		return decision.Failure("skipped", "egress_not_authorized")
	}
	if in.DeterministicDeny {
		return decision.Failure("skipped", "deterministic_deny")
	}
	if b.Validate(in.Policy) != nil || in.Profile.Validate() != nil || factory == nil {
		return decision.Failure("skipped", "invalid_configuration")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(b.BudgetMS)*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return decision.Failure("timeout", "deadline")
	}
	selected, err := in.Policy.Select(in.Event)
	if err != nil {
		return decision.Failure("skipped", "selector_error")
	}
	if !selected {
		return decision.Failure("skipped", "not_selected")
	}
	s := in.Evidence.Subject
	if s.EventID != in.Event.EventID || s.CallID != in.Event.ToolCallID ||
		s.Agent != in.Event.SourceAgent || s.Session != in.Event.SessionID ||
		s.SessionTree != in.Event.SessionTreeID || s.SubAgentID != in.Event.SubAgentID {
		return decision.Failure("skipped", "subject_mismatch")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return decision.Failure("unavailable", "invocation_identity")
	}
	request, err := decision.Prepare(in.Policy, b, in.Evidence, hex.EncodeToString(nonce),
		in.Profile.Digest(), in.Profile.Model, deadline)
	if err != nil {
		return decision.Failure("skipped", "invalid_or_oversized_input")
	}
	fail = func(status, reason string) decision.Assessment {
		a := decision.Failure(status, reason)
		a.RequestID, a.RequestDigest = request.ID, request.Digest
		a.PolicyID, a.PolicyVersion = in.Policy.Policy().ID, in.Policy.Policy().Version
		a.View = b.View
		a.MatchThreshold, a.DenyThreshold = b.MatchThreshold, b.DenyThreshold
		a.Gaps = slices.Clone(request.Gaps)
		a.InputEligible = request.Eligible && b.View == decision.Action
		if b.View == decision.Session {
			a.Gaps = append(a.Gaps, "freshness_unchecked")
		}
		return a
	}
	provider, err := factory(in.Profile)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return fail("timeout", "deadline")
	}
	if err != nil || provider == nil {
		return fail("unavailable", "provider_initialization")
	}
	reply, err := provider.Evaluate(ctx, request, in.Policy, b.MaxRequestBytes)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return fail("timeout", "deadline")
	}
	if err != nil {
		if errors.Is(err, ErrInput) {
			return fail("skipped", "invalid_or_oversized_input")
		}
		if errors.Is(err, ErrResponse) {
			return fail("invalid_response", "provider_contract")
		}
		return fail("unavailable", "provider_error")
	}
	revision := request.Revision
	confirmed := b.View != decision.Session
	if b.View == decision.Session && in.Confirm != nil {
		revision, err = in.Confirm(ctx, request)
		confirmed = err == nil
		if !confirmed {
			// A failed read does not prove a different revision.
			revision = request.Revision
		}
	}
	if ctx.Err() != nil {
		return fail("timeout", "deadline")
	}
	a := decision.Reduce(in.Policy, b, request, reply, revision, time.Now())
	if b.View == decision.Session && !confirmed {
		a.InputEligible, a.DenyCandidate = false, false
		if !slices.Contains(a.Gaps, "state_unavailable") {
			a.Gaps = append(a.Gaps, "state_unavailable")
		}
		if a.Status == "completed" {
			a.Reason = "state_unavailable"
		}
	}
	return a
}

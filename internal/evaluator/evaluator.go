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
	ErrResponse  = errors.New("invalid decision response")
	ErrInput     = errors.New("invalid or oversized decision input")
	ErrRateLimit = errors.New("decision provider rate limited")

	errPriorSemanticDeny = errors.New("prior semantic deny")
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
	Confirm  func(context.Context, decision.Request) (uint64, error)
	selected bool
}

// Run returns only an assessment. The caller retains global enforcement,
// native-host eligibility and the existing clean-output gate.
func Run(parent context.Context, in Invocation, factory Factory) (assessment decision.Assessment) {
	return evaluate(parent, in, factory).finish(parent, in)
}

// Provider work may overlap; freshness and authority are checked when the
// caller is ready to record the result, not when an earlier response arrives.
type evaluationResult struct {
	request    decision.Request
	reply      decision.Reply
	assessment decision.Assessment
	ready      bool
}

func (r evaluationResult) failure(in Invocation, status, reason string) decision.Assessment {
	a := decision.Failure(status, reason)
	if r.request.ID == "" {
		return a
	}
	a.RequestID, a.RequestDigest = r.request.ID, r.request.Digest
	a.PolicyID, a.PolicyVersion = in.Policy.Policy().ID, in.Policy.Policy().Version
	a.View = in.Binding.View
	a.MatchThreshold, a.DenyThreshold = in.Binding.MatchThreshold, in.Binding.DenyThreshold
	a.Gaps = slices.Clone(r.request.Gaps)
	a.InputEligible = r.request.Eligible && in.Binding.View == decision.Action
	if in.Binding.View == decision.Session {
		a.Gaps = append(a.Gaps, "freshness_unchecked")
	}
	return a
}

func evaluate(parent context.Context, in Invocation, factory Factory) (result evaluationResult) {
	fail := func(status, reason string) evaluationResult {
		result.assessment = result.failure(in, status, reason)
		return result
	}
	defer func() {
		if recover() != nil {
			result = fail("unavailable", "evaluator_panic")
		}
	}()
	b := in.Binding
	if !b.Enabled {
		return fail("skipped", "disabled")
	}
	if !b.SendContent {
		return fail("skipped", "egress_not_authorized")
	}
	if in.DeterministicDeny {
		return fail("skipped", "deterministic_deny")
	}
	if b.Validate(in.Policy) != nil || in.Profile.Validate() != nil || factory == nil {
		return fail("skipped", "invalid_configuration")
	}
	if !in.selected {
		selected, err := in.Policy.Select(in.Event)
		if err != nil {
			return fail("skipped", "selector_error")
		}
		if !selected {
			return fail("skipped", "not_selected")
		}
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(b.BudgetMS)*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	cancelled := func() evaluationResult {
		if errors.Is(context.Cause(ctx), errPriorSemanticDeny) && time.Now().Before(deadline) {
			return fail("skipped", "prior_semantic_deny")
		}
		return fail("timeout", "deadline")
	}
	if err := ctx.Err(); err != nil {
		return cancelled()
	}
	s := in.Evidence.Subject
	if s.EventID != in.Event.EventID || s.CallID != in.Event.ToolCallID ||
		s.Agent != in.Event.SourceAgent || s.Session != in.Event.SessionID ||
		s.SessionTree != in.Event.SessionTreeID || s.SubAgentID != in.Event.SubAgentID {
		return fail("skipped", "subject_mismatch")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fail("unavailable", "invocation_identity")
	}
	request, err := decision.Prepare(in.Policy, b, in.Evidence, hex.EncodeToString(nonce),
		in.Profile.Digest(), in.Profile.responseModel(), deadline)
	if err != nil {
		return fail("skipped", "invalid_or_oversized_input")
	}
	result.request = request
	provider, err := factory(in.Profile)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return cancelled()
	}
	if err != nil || provider == nil {
		return fail("unavailable", "provider_initialization")
	}
	reply, err := provider.Evaluate(ctx, request, in.Policy, b.MaxRequestBytes)
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return cancelled()
	}
	if err != nil {
		if errors.Is(err, ErrInput) {
			return fail("skipped", "invalid_or_oversized_input")
		}
		if errors.Is(err, ErrRateLimit) {
			return fail("unavailable", "rate_limited")
		}
		if errors.Is(err, ErrResponse) {
			return fail("invalid_response", "provider_contract")
		}
		return fail("unavailable", "provider_error")
	}
	result.reply, result.ready = reply, true
	return result
}

func (r evaluationResult) finish(parent context.Context, in Invocation) (assessment decision.Assessment) {
	if !r.ready {
		return r.assessment
	}
	defer func() {
		if recover() != nil {
			assessment = r.failure(in, "unavailable", "evaluator_panic")
		}
	}()
	ctx, cancel := context.WithDeadline(parent, r.request.Deadline)
	defer cancel()
	if ctx.Err() != nil {
		return r.failure(in, "timeout", "deadline")
	}
	revision := r.request.Revision
	confirmed := in.Binding.View != decision.Session
	if in.Binding.View == decision.Session && in.Confirm != nil {
		var err error
		revision, err = in.Confirm(ctx, r.request)
		confirmed = err == nil
		if !confirmed {
			// A failed read does not prove a different revision.
			revision = r.request.Revision
		}
	}
	if ctx.Err() != nil {
		return r.failure(in, "timeout", "deadline")
	}
	a := decision.Reduce(in.Policy, in.Binding, r.request, r.reply, revision, time.Now())
	if a.Status == "completed" {
		a.ReturnedModel = r.reply.Model
	}
	if in.Binding.View == decision.Session && !confirmed {
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

package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
)

func TestConcurrentRuntimeFastDenyCancelsSlowAndQueued(t *testing.T) {
	started := make(chan string, 4)
	slow, fast := make(chan struct{}), make(chan struct{})
	releaseSlow := sync.OnceFunc(func() { close(slow) })
	releaseFast := sync.OnceFunc(func() { close(fast) })
	var active, peak atomic.Int32
	c, hits := runtimeConfig(t, func(raw []byte) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		var body struct {
			State struct {
				Current struct {
					Action struct {
						FilePath string `json:"file_path"`
					} `json:"action"`
				} `json:"current_event"`
			} `json:"state"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
			return
		}
		path := body.State.Current.Action.FilePath
		started <- path
		if path == "/fast" {
			<-fast
		} else {
			<-slow
		}
	})
	c.BudgetMS, c.TimeoutMS = 1500, 1500
	paths := []string{"/slow", "/fast", "/queued-a", "/queued-b"}
	if err := c.ConfigureRules(concurrencyRules(decision.Action, paths...)); err != nil {
		t.Fatal(err)
	}
	in := concurrencyEvaluation(paths...)
	in.Control = &pipeline.EnforceDecision{}
	var out bytes.Buffer
	em := output.New(&out, io.Discard, "test")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		releaseSlow()
		releaseFast()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("runtime did not stop after cancellation")
		}
	})
	go func() {
		defer close(done)
		c.Evaluate(ctx, in, em)
	}()
	seen := make(map[string]bool)
	for range 2 {
		select {
		case path := <-started:
			seen[path] = true
		case <-time.After(time.Second):
			t.Fatal("independent second request was starved")
		}
	}
	if !seen["/slow"] || !seen["/fast"] {
		t.Fatalf("unexpected initial requests: %v", seen)
	}
	select {
	case path := <-started:
		t.Fatalf("request exceeded the two-request bound: %s", path)
	case <-time.After(25 * time.Millisecond):
	}
	releaseFast()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fast deny waited for the blocked first response")
	}
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || peak.Load() != 2 {
		t.Fatalf("requests=%d peak=%d", hits.Load(), peak.Load())
	}
	if !in.Control.Blocked || in.Control.DenyRuleID != "local.fast" || in.Control.DenyAssessmentID == "" {
		t.Fatalf("fast response did not authorize the deny: %+v", in.Control)
	}
	records := concurrencyAssessments(t, out.Bytes())
	if len(records) != len(paths) {
		t.Fatalf("got %d assessments for %d rules", len(records), len(paths))
	}
	for id, a := range records {
		if id == "local.fast" {
			if a.Status != "completed" || !a.Matched || !a.DenyCandidate || a.Reason != "semantic_match" {
				t.Fatalf("fast response lost authority: %+v", a)
			}
		} else if a.Status != "skipped" || a.Reason != "prior_semantic_deny" || a.Matched || a.DenyCandidate {
			t.Fatalf("cancelled or queued rule gained a verdict: %+v", a)
		}
	}
}

func TestRuntimeRetainsCompletedSiblingsAfterDeny(t *testing.T) {
	for _, tc := range []struct {
		name, status, reason string
		err                  error
		cancelParent         bool
		expireBudget         bool
		staleFirst           bool
	}{
		{name: "completed", status: "completed", reason: "semantic_match"},
		{name: "invalid_response", err: ErrResponse, status: "invalid_response", reason: "provider_contract"},
		{name: "rate_limited", err: ErrRateLimit, status: "unavailable", reason: "rate_limited"},
		{name: "provider_error", err: errors.New("synthetic failure"), status: "unavailable", reason: "provider_error"},
		{name: "parent_cancelled", cancelParent: true, status: "timeout", reason: "deadline"},
		{name: "budget_expired", expireBudget: true, status: "timeout", reason: "deadline"},
		{name: "session_changes_during_first_finding", staleFirst: true, status: "completed", reason: "semantic_match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := &Config{
					BudgetMS: 2000, TimeoutMS: 2000, MaxRequestBytes: 32768,
					Provider: ProviderConfig{Profile: Profile{
						Protocol: "decisions-v1", Endpoint: "https://provider.example/v1/decisions",
						Model: "fixture", MaxResponseBytes: 4096,
					}},
				}
				rules := concurrencyRules(decision.Action, "/first", "/second")
				if tc.staleFirst {
					rules[0].Decision.View, rules[0].Decision.MaxHistoryCalls = decision.Session, 4
				}
				if err := c.ConfigureRules(rules); err != nil {
					t.Fatal(err)
				}
				in := concurrencyEvaluation("/first", "/second")
				in.Control = &pipeline.EnforceDecision{}
				var revision, confirmations atomic.Uint64
				revision.Store(7)
				firstRejected := make(chan struct{})
				rejectFirst := sync.OnceFunc(func() { close(firstRejected) })
				if tc.staleFirst {
					in.Confirm = func(_ context.Context, r decision.Request) (uint64, error) {
						confirmations.Add(1)
						current := revision.Load()
						if current != r.Revision {
							rejectFirst()
						}
						return current, nil
					}
				}
				var out bytes.Buffer
				var writer io.Writer = &out
				if tc.staleFirst {
					writer = runtimeWriterFunc(func(raw []byte) (int, error) {
						n, err := out.Write(raw)
						if err == nil {
							var record struct {
								RecordType string `json:"record_type"`
								RuleID     string `json:"rule_id"`
							}
							if decodeErr := json.Unmarshal(raw, &record); decodeErr != nil {
								t.Error(decodeErr)
							}
							if record.RecordType == output.RecordFinding && record.RuleID == "local.first" {
								revision.Add(1)
							}
						}
						return n, err
					})
				}
				em := output.New(writer, io.Discard, "test")
				gate := &runtimeRecordGate{entered: make(chan struct{}), release: make(chan struct{})}
				release := sync.OnceFunc(func() { close(gate.release) })
				defer release()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				factory := func(Profile) (Provider, error) {
					return providerFunc(func(ctx context.Context, r decision.Request, p *decision.Compiled, _ int) (decision.Reply, error) {
						if p.Policy().ID == "local.second" {
							<-gate.entered
							if tc.staleFirst {
								select {
								case <-firstRejected:
								case <-ctx.Done():
									return decision.Reply{}, ctx.Err()
								}
							}
							if tc.err != nil {
								return decision.Reply{}, tc.err
							}
						}
						return decision.Reply{
							RequestDigest: r.Digest, Model: r.Model, Choice: "violation",
							Probabilities: map[string]float64{"violation": .999, "unknown": .001},
						}, nil
					}), nil
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					c.prepare(in).runWithFactory(ctx, c, em, gate, factory)
				}()
				<-gate.entered
				// The first record remains blocked until the sibling completes,
				// or waits for the stale first contribution to be rejected.
				synctest.Wait()
				if tc.cancelParent {
					cancel()
				}
				if tc.expireBudget {
					time.Sleep(time.Duration(c.BudgetMS) * time.Millisecond)
				}
				release()
				<-done
				if err := em.Close(); err != nil {
					t.Fatal(err)
				}
				records := concurrencyAssessments(t, out.Bytes())
				first, second := records["local.first"], records["local.second"]
				if len(records) != 2 || first.RequestID == "" || second.RequestID == "" ||
					second.Status != tc.status || second.Reason != tc.reason {
					t.Fatalf("first=%+v second=%+v", first, second)
				}
				if tc.cancelParent || tc.expireBudget {
					if first.Status != "timeout" || first.Reason != "deadline" ||
						first.Matched || second.Matched || first.DenyCandidate || second.DenyCandidate || in.Control.Blocked {
						t.Fatalf("expired authority survived: first=%+v second=%+v control=%+v", first, second, in.Control)
					}
				} else {
					winner, winnerID := first, "local.first"
					if tc.staleFirst {
						winner, winnerID = second, "local.second"
						if revision.Load() != 8 || confirmations.Load() != 2 || !first.DenyCandidate ||
							in.Control.ConfirmDeny == nil || !in.Control.ConfirmDeny(ctx) {
							t.Fatalf("post-write recheck did not preserve a healthy winner: revision=%d confirmations=%d first=%+v control=%+v",
								revision.Load(), confirmations.Load(), first, in.Control)
						}
					}
					if !first.Matched || !in.Control.Blocked || in.Control.DenyRuleID != winnerID ||
						in.Control.DenyAssessmentID != winner.AssessmentID {
						t.Fatalf("wrong deny winner: first=%+v second=%+v control=%+v", first, second, in.Control)
					}
					if matched := tc.status == "completed"; second.Matched != matched || second.DenyCandidate != matched {
						t.Fatalf("completed sibling lost its verdict: %+v", second)
					}
				}
			})
		})
	}
}

type runtimeWriterFunc func([]byte) (int, error)

func (f runtimeWriterFunc) Write(raw []byte) (int, error) { return f(raw) }

type runtimeRecordGate struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *runtimeRecordGate) Lock() {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
}

func (*runtimeRecordGate) Unlock() {}

func TestCompletedResponseCannotDenyAfterFinalizationDeadline(t *testing.T) {
	c, hits := runtimeConfig(t, nil)
	if err := c.ConfigureRules(concurrencyRules(decision.Session, "/pending")); err != nil {
		t.Fatal(err)
	}
	in := c.prepare(concurrencyEvaluation("/pending")).rules[0].invocation
	var confirmations atomic.Int32
	in.Confirm = func(_ context.Context, r decision.Request) (uint64, error) {
		confirmations.Add(1)
		return r.Revision, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := evaluate(ctx, in, c.Factory())
	if !result.ready || hits.Load() != 1 {
		t.Fatalf("response was not completed: %+v requests=%d", result.assessment, hits.Load())
	}
	if a := result.finish(ctx, in); !a.DenyCandidate {
		t.Fatalf("fresh response was not deny-eligible: %+v", a)
	}
	<-ctx.Done()
	a := result.finish(context.Background(), in)
	if a.Status != "timeout" || a.Reason != "deadline" || a.DenyCandidate || a.Matched ||
		a.RequestID != result.request.ID || confirmations.Load() != 1 {
		t.Fatalf("expired completed response retained authority: %+v confirmations=%d", a, confirmations.Load())
	}
}

func TestCompletedResponseConfirmsCurrentRevisionAtFinalization(t *testing.T) {
	c, hits := runtimeConfig(t, nil)
	if err := c.ConfigureRules(concurrencyRules(decision.Session, "/pending")); err != nil {
		t.Fatal(err)
	}
	in := c.prepare(concurrencyEvaluation("/pending")).rules[0].invocation
	var revision atomic.Uint64
	revision.Store(in.Evidence.Revision)
	in.Confirm = func(context.Context, decision.Request) (uint64, error) {
		return revision.Load(), nil
	}
	result := evaluate(context.Background(), in, c.Factory())
	if !result.ready || hits.Load() != 1 {
		t.Fatalf("response was not completed: %+v requests=%d", result.assessment, hits.Load())
	}
	if a := result.finish(context.Background(), in); !a.DenyCandidate {
		t.Fatalf("fresh response was not deny-eligible: %+v", a)
	}
	revision.Add(1)
	a := result.finish(context.Background(), in)
	if a.Status != "completed" || a.Reason != "stale_snapshot" || !a.Matched ||
		a.InputEligible || a.DenyCandidate || !slices.Contains(a.Gaps, "stale_snapshot") {
		t.Fatalf("finalization ignored changed session revision: %+v", a)
	}
}

func TestExpiredRuntimePreservesUnselectedReason(t *testing.T) {
	c, hits := runtimeConfig(t, nil)
	rules := concurrencyRules(decision.Action, "/unselected", "/selected")
	rules[0].Decision.Select = "false"
	if err := c.ConfigureRules(rules); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	plan := c.prepare(concurrencyEvaluation("/selected"))
	a := Run(ctx, plan.rules[0].invocation, c.Factory())
	if a.Status != "skipped" || a.Reason != "not_selected" {
		t.Fatalf("inactive selector was mislabeled by deadline: %+v", a)
	}
	var out bytes.Buffer
	em := output.New(&out, io.Discard, "test")
	plan.run(ctx, c, em, nil)
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	records := concurrencyAssessments(t, out.Bytes())
	if hits.Load() != 0 || len(records) != 2 {
		t.Fatalf("requests=%d assessments=%d", hits.Load(), len(records))
	}
	for id, reason := range map[string]string{"local.unselected": "not_selected", "local.selected": "deadline"} {
		a := records[id]
		if a.Reason != reason || a.Matched || a.DenyCandidate || a.RequestID != "" {
			t.Fatalf("wrong expired-runtime assessment: %+v", a)
		}
	}
}

func TestConcurrentRuntimeDeterministicDenyAvoidsProvider(t *testing.T) {
	c, hits := runtimeConfig(t, nil)
	paths := []string{"/one", "/two", "/three"}
	if err := c.ConfigureRules(concurrencyRules(decision.Action, paths...)); err != nil {
		t.Fatal(err)
	}
	in := concurrencyEvaluation(paths...)
	in.Control = &pipeline.EnforceDecision{Blocked: true, DenyRuleID: "local.deterministic"}
	var out bytes.Buffer
	em := output.New(&out, io.Discard, "test")
	c.Evaluate(context.Background(), in, em)
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	records := concurrencyAssessments(t, out.Bytes())
	if hits.Load() != 0 || len(records) != len(paths) {
		t.Fatalf("requests=%d assessments=%d", hits.Load(), len(records))
	}
	for _, a := range records {
		if a.Status != "skipped" || a.Reason != "deterministic_deny" || a.RequestID != "" || a.Matched || a.DenyCandidate {
			t.Fatalf("deterministic deny did not skip model work: %+v", a)
		}
	}
	if !in.Control.Blocked || in.Control.DenyRuleID != "local.deterministic" || in.Control.DenyAssessmentID != "" {
		t.Fatalf("model work changed deterministic authority: %+v", in.Control)
	}
}

func concurrencyRules(view string, paths ...string) []rule.Rule {
	rules := make([]rule.Rule, 0, len(paths))
	for _, path := range paths {
		r := runtimeRule(view)
		r.ID = "local." + path[1:]
		r.Decision.Select = fmt.Sprintf("event.file_path == %q", path)
		rules = append(rules, r)
	}
	return rules
}

func concurrencyEvaluation(paths ...string) Evaluation {
	var events []model.Event
	for _, path := range paths {
		ev := runtimeEvent(path[1:], "session", path)
		ev.SourceType, ev.ToolCallID = model.SourceHook, "pending-call"
		events = append(events, ev)
	}
	return Evaluation{
		Events: events,
		Evidence: func(ev model.Event, _ string) decision.Evidence {
			o := decision.Project(ev, "pre", "raw")
			o.Subject.Installation, o.Subject.Generation = "test", "epoch"
			return decision.Evidence{
				Subject: o.Subject, Revision: 7, Current: o.Current(),
				CurrentComplete: o.Complete, PrefixComplete: true, OperatorContext: json.RawMessage(`{}`),
			}
		},
	}
}

func concurrencyAssessments(t *testing.T, raw []byte) map[string]output.DecisionAssessment {
	t.Helper()
	records := make(map[string]output.DecisionAssessment)
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var record struct {
			RecordType string `json:"record_type"`
			output.DecisionAssessment
		}
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record.RecordType == output.RecordAssessment {
			if _, exists := records[record.PolicyID]; exists {
				t.Fatalf("duplicate assessment for %s", record.PolicyID)
			}
			records[record.PolicyID] = record.DecisionAssessment
		}
	}
	return records
}

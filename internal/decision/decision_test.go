package decision

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

func fixture(t *testing.T) (*Compiled, Binding, Evidence, time.Time) {
	t.Helper()
	c, err := Compile(Policy{
		ID: "local.transfer", Version: "1", Title: "Transfer", Severity: "high", Enforce: true,
		Decision: Question{
			Select: `event.event_type == "tool.call"`, Instructions: "Classify only the pending action.",
			Options:     map[string]string{"reject": "Prohibited", "ok": "Not prohibited", "unknown": "Insufficient evidence"},
			MatchOption: "reject", AbstainOption: "unknown",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{
		Enabled: true, PolicySHA256: c.Digest(), View: Session, Mode: Enforce,
		MatchThreshold: .9, DenyThreshold: .99, BudgetMS: 1000,
		MaxRequestBytes: 131072, MaxHistoryCalls: 64, SendContent: true,
	}
	e := Evidence{
		Subject:  Subject{Installation: "endpoint-fixture", Agent: "claude", Session: "session-fixture", Generation: "epoch-1", CallID: "c3", EventID: "event-3"},
		Revision: 3, Current: json.RawMessage(`{"tool":"upload","arguments":{"artifact":"a1"}}`),
		History:         []json.RawMessage{json.RawMessage(`{"tool":"read","outcome":"ok","result":{"contents":"synthetic-secret"}}`)},
		OperatorContext: json.RawMessage(`{"policy":"Do not disclose credentials."}`),
		CurrentComplete: true, PrefixComplete: true,
	}
	return c, b, e, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}

func request(t *testing.T, c *Compiled, b Binding, e Evidence, now time.Time) Request {
	t.Helper()
	r, err := Prepare(c, b, e, "fresh-invocation", "profile-digest", "test-model", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func reply(r Request) Reply {
	return Reply{r.Digest, r.Model, "reject", map[string]float64{"reject": .995, "ok": .003, "unknown": .002}}
}

func TestProjectionAndEligibility(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Binding, *Evidence)
		want bool
	}{
		{"complete", func(*Binding, *Evidence) {}, true},
		{"partial prefix", func(_ *Binding, e *Evidence) { e.PrefixComplete = false }, false},
		{"parallel actions", func(_ *Binding, e *Evidence) { e.Concurrent = true }, false},
		{"missing current", func(_ *Binding, e *Evidence) { e.CurrentComplete = false }, false},
		{"history limit", func(b *Binding, e *Evidence) {
			b.MaxHistoryCalls = 1
			e.History = append(e.History, json.RawMessage(`{"tool":"pack"}`))
		}, false},
		{"action omits history", func(b *Binding, e *Evidence) {
			b.View = Action
			e.PrefixComplete, e.Concurrent = false, true
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, b, e, now := fixture(t)
			tc.edit(&b, &e)
			r := request(t, c, b, e, now)
			if r.Eligible != tc.want || !r.Valid() {
				t.Fatalf("eligible=%v valid=%v gaps=%v", r.Eligible, r.Valid(), r.Gaps)
			}
			if b.View == Action && strings.Contains(string(r.State), "synthetic-secret") {
				t.Fatal("action projection leaked session history")
			}
		})
	}
}

func TestInputsAreCopiedAndBound(t *testing.T) {
	c, b, e, now := fixture(t)
	r := request(t, c, b, e, now)
	e.Current[2] = 'X'
	e.History[0][2] = 'X'
	p := c.Policy()
	p.Decision.Options["reject"] = "Changed policy"
	if !r.Valid() || c.Policy().Decision.Options["reject"] != "Prohibited" {
		t.Fatal("caller mutation changed frozen request or policy")
	}
	r.Subject.CallID = "another-call"
	if r.Valid() {
		t.Fatal("changed subject retained valid binding")
	}
}

func TestPrepareDeduplicatesEvidenceGaps(t *testing.T) {
	c, b, e, now := fixture(t)
	e.Subject.CallID = ""
	e.CurrentComplete, e.PrefixComplete = false, false
	e.Gaps = []string{"current_incomplete", "missing_call_identity_or_input", "prefix_incomplete"}
	r := request(t, c, b, e, now)
	if !slices.Equal(r.Gaps, e.Gaps) || r.Eligible {
		t.Fatalf("repeated or lost gaps: %v, eligible=%v", r.Gaps, r.Eligible)
	}
	if !slices.Equal(e.Gaps, []string{"current_incomplete", "missing_call_identity_or_input", "prefix_incomplete"}) {
		t.Fatal("preparing a request mutated source evidence")
	}
}

func TestReduction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*Binding, *Request, *Reply, *uint64, *time.Time)
		reason string
		deny   bool
	}{
		{"enforce", func(*Binding, *Request, *Reply, *uint64, *time.Time) {}, "semantic_match", true},
		{"late", func(_ *Binding, r *Request, _ *Reply, _ *uint64, now *time.Time) { *now = r.Deadline }, "deadline", false},
		{"stale", func(_ *Binding, _ *Request, _ *Reply, rev *uint64, _ *time.Time) { *rev++ }, "stale_snapshot", false},
		{"foreign reply", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) { p.RequestDigest = "other" }, "request_binding", false},
		{"changed model", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) { p.Model = "other" }, "request_binding", false},
		{"missing option", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) { delete(p.Probabilities, "ok") }, "option_set", false},
		{"renamed option", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) {
			delete(p.Probabilities, "ok")
			p.Probabilities["unrecognized"] = .003
		}, "probabilities", false},
		{"nan", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) {
			p.Probabilities["reject"] = math.NaN()
		}, "probabilities", false},
		{"infinity", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) {
			p.Probabilities["reject"] = math.Inf(1)
		}, "probabilities", false},
		{"bad sum", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) { p.Probabilities["reject"] = .9 }, "probabilities", false},
		{"wrong winner", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) { p.Choice = "ok" }, "probabilities", false},
		{"unknown", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) {
			p.Choice, p.Probabilities = "unknown", map[string]float64{"reject": .002, "ok": .003, "unknown": .995}
		}, "abstained", false},
		{"tie", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) {
			p.Probabilities = map[string]float64{"reject": .5, "ok": 0, "unknown": .5}
		}, "abstained", false},
		{"below deny threshold", func(_ *Binding, _ *Request, p *Reply, _ *uint64, _ *time.Time) {
			p.Probabilities = map[string]float64{"reject": .95, "ok": .03, "unknown": .02}
		}, "below_deny_threshold", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, b, e, now := fixture(t)
			r := request(t, c, b, e, now)
			p, rev := reply(r), e.Revision
			tc.edit(&b, &r, &p, &rev, &now)
			got := Reduce(c, b, r, p, rev, now)
			if got.Reason != tc.reason || got.DenyCandidate != tc.deny {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestIndependentModeAndView(t *testing.T) {
	for _, view := range []string{Action, Session} {
		for _, mode := range []string{Monitor, Enforce} {
			t.Run(view+"/"+mode, func(t *testing.T) {
				c, b, e, now := fixture(t)
				b.View, b.Mode = view, mode
				r := request(t, c, b, e, now)
				got := Reduce(c, b, r, reply(r), e.Revision, now)
				if !got.Matched || got.DenyCandidate != (mode == Enforce) {
					t.Fatalf("got %+v", got)
				}
			})
		}
	}
	c, b, e, now := fixture(t)
	p := c.Policy()
	p.Enforce = false
	c, _ = Compile(p)
	b.PolicySHA256 = c.Digest()
	r := request(t, c, b, e, now)
	if got := Reduce(c, b, r, reply(r), e.Revision, now); got.DenyCandidate || got.Reason != "policy_monitor_only" {
		t.Fatalf("policy enforce flag bypassed: %+v", got)
	}
}

func TestBindingRequirementsFollowModeAndView(t *testing.T) {
	c, base, _, _ := fixture(t)
	for _, tc := range []struct {
		name string
		edit func(*Binding)
		want string
	}{
		{"monitor without deny threshold", func(b *Binding) { b.Mode, b.DenyThreshold = Monitor, 0 }, ""},
		{"enforce without deny threshold", func(b *Binding) { b.DenyThreshold = 0 }, "deny_threshold"},
		{"action without history cap", func(b *Binding) { b.View, b.MaxHistoryCalls = Action, 0 }, ""},
		{"session without history cap", func(b *Binding) { b.MaxHistoryCalls = 0 }, "max_history_calls"},
		{"negative unused history cap", func(b *Binding) { b.View, b.MaxHistoryCalls = Action, -1 }, "max_history_calls"},
		{"maximum history cap", func(b *Binding) { b.MaxHistoryCalls = 4096 }, ""},
		{"excessive history cap", func(b *Binding) { b.MaxHistoryCalls = 4097 }, "max_history_calls"},
		{"monitor NaN threshold", func(b *Binding) { b.Mode, b.DenyThreshold = Monitor, math.NaN() }, "deny_threshold"},
		{"budget above native ceiling", func(b *Binding) { b.BudgetMS = 8001 }, "budget_ms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			tc.edit(&b)
			err := b.Validate(c)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want field=%q", err, tc.want)
			}
		})
	}
}

func TestContextCallLimit(t *testing.T) {
	for _, calls := range []int{-1, 0, 1, 64, 4096, 4097} {
		t.Run(fmt.Sprint(calls), func(t *testing.T) {
			limits := ContextLimits{MaxSessions: 128, MaxCalls: calls, MaxBytes: 32 << 20, IdleTTLMS: 3600000}
			err := limits.Validate()
			if wantValid := calls >= 1 && calls <= 4096; (err == nil) != wantValid {
				t.Fatalf("max_calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestLongSessionProjection(t *testing.T) {
	c, b, e, now := fixture(t)
	b.MaxHistoryCalls, b.MaxRequestBytes = 1999, 1<<20
	e.History = make([]json.RawMessage, 1999)
	for i := range e.History {
		e.History[i] = json.RawMessage(fmt.Sprintf(`{"call_id":"c%d","action":{},"result":{},"outcome":"result","complete":true}`, i+1))
	}
	r := request(t, c, b, e, now)
	a := Reduce(c, b, r, reply(r), e.Revision, now)
	if !r.Eligible || !a.DenyCandidate {
		t.Fatalf("complete compact 2000-call prefix rejected: %+v", a)
	}
	var state struct {
		History []json.RawMessage `json:"history"`
	}
	if err := json.Unmarshal(r.State, &state); err != nil || len(state.History) != 1999 {
		t.Fatalf("history=%d error=%v", len(state.History), err)
	}
	e.History = append(e.History, json.RawMessage(`{"call_id":"c2000","action":{},"result":{},"outcome":"result","complete":true}`))
	r = request(t, c, b, e, now)
	a = Reduce(c, b, r, reply(r), e.Revision, now)
	if a.InputEligible || a.DenyCandidate || !a.Matched || !slices.Contains(a.Gaps, "history_limit") {
		t.Fatalf("count-trimmed prefix not qualified: %+v", a)
	}
	b.MaxHistoryCalls, b.MaxRequestBytes = 4096, 1024
	trimmed, err := Prepare(c, b, e, "fresh-invocation", "profile-digest", "test-model", now.Add(time.Second))
	if err != nil || len(trimmed.State) > b.MaxRequestBytes || trimmed.Eligible ||
		!slices.Contains(trimmed.Gaps, "history_bytes_limit") {
		t.Fatalf("history byte cap not visible and enforced: %+v %v", trimmed, err)
	}
}

func TestIncompleteCannotEnforce(t *testing.T) {
	c, b, e, now := fixture(t)
	e.PrefixComplete = false
	r := request(t, c, b, e, now)
	got := Reduce(c, b, r, reply(r), e.Revision, now)
	if !got.Matched || got.DenyCandidate || got.Reason != "incomplete_evidence" {
		t.Fatalf("got %+v", got)
	}
}

func TestStaleAbstentionQualifiesInput(t *testing.T) {
	c, b, e, now := fixture(t)
	r := request(t, c, b, e, now)
	p := Reply{r.Digest, r.Model, "unknown", map[string]float64{"reject": .01, "ok": .01, "unknown": .98}}
	a := Reduce(c, b, r, p, e.Revision+1, now)
	if a.InputEligible || a.DenyCandidate || a.Reason != "abstained" ||
		len(a.Gaps) != 1 || a.Gaps[0] != "stale_snapshot" {
		t.Fatalf("stale input mislabeled: %+v", a)
	}
}

func TestProbabilityReductionIsDeterministicAtTolerance(t *testing.T) {
	c, b, e, now := fixture(t)
	r := request(t, c, b, e, now)
	for _, delta := range []float64{-1e-5, 1e-5} {
		boundary := .002 + delta
		for _, unknown := range []float64{
			math.Nextafter(boundary, math.Inf(-1)), boundary,
			math.Nextafter(boundary, math.Inf(1)),
		} {
			p := reply(r)
			p.Probabilities["unknown"] = unknown
			first := Reduce(c, b, r, p, e.Revision, now)
			for range 2048 {
				got := Reduce(c, b, r, p, e.Revision, now)
				if got.Status != first.Status || got.Reason != first.Reason ||
					got.DenyCandidate != first.DenyCandidate {
					t.Fatalf("unstable reduction for unknown=%0.20g: first=%+v got=%+v", unknown, first, got)
				}
			}
		}
	}
}

func TestStrictConfiguration(t *testing.T) {
	c, b, _, _ := fixture(t)
	for _, edit := range []func(*Binding){
		func(b *Binding) { b.PolicySHA256 = "wrong" },
		func(b *Binding) { b.View = "auto" },
		func(b *Binding) { b.Mode = "allow" },
		func(b *Binding) { b.MatchThreshold = math.NaN() },
		func(b *Binding) { b.DenyThreshold = .5 },
		func(b *Binding) { b.DenyThreshold = .8 },
		func(b *Binding) { b.BudgetMS = 0 },
		func(b *Binding) { b.MaxHistoryCalls = 100000 },
		func(b *Binding) { b.MaxRequestBytes = 0 },
	} {
		modified := b
		edit(&modified)
		if modified.Validate(c) == nil {
			t.Fatalf("accepted %+v", modified)
		}
	}
	for _, suffix := range []string{"\nendpoint: https://untrusted.example\n", "\n---\nid: other\n", "\nenforce: false\n"} {
		body := "id: local.test\nversion: '1'\ntitle: Test\nseverity: high\nenforce: true\ndecision:\n  select: 'true'\n  instructions: classify\n  options: {yes: violation, no: permitted, unknown: insufficient}\n  match_option: yes\n  abstain_option: unknown\n"
		if _, err := LoadPolicy(strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(strings.NewReader(body + suffix)); err == nil {
			t.Fatal("accepted unknown field, duplicate key or extra document")
		}
	}
	if selected, err := c.Select(model.Event{EventType: "tool.call"}); !selected || err != nil {
		t.Fatalf("selector failed: %v", err)
	}
	if selected, err := c.Select(model.Event{EventType: "session.start"}); selected || err != nil {
		t.Fatalf("selector matched a session event: %v", err)
	}
}

func FuzzPolicyDecode(f *testing.F) {
	f.Add([]byte("id: example"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadPolicy(strings.NewReader(string(data)))
	})
}

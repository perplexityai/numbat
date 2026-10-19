package evaluator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
)

type providerFunc func(context.Context, decision.Request, *decision.Compiled, int) (decision.Reply, error)

func (f providerFunc) Evaluate(ctx context.Context, r decision.Request, p *decision.Compiled, n int) (decision.Reply, error) {
	return f(ctx, r, p, n)
}

func invocation(t *testing.T) Invocation {
	t.Helper()
	c, err := decision.Compile(decision.Policy{
		ID: "local.transfer", Version: "1", Title: "Transfer", Severity: "high", Enforce: true,
		Decision: decision.Question{
			Select: `event.event_type == "tool.call"`, Instructions: "Classify the pending action.",
			Options:     map[string]string{"violation": "Prohibited", "permitted": "Not prohibited", "unknown": "Insufficient evidence"},
			MatchOption: "violation", AbstainOption: "unknown",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Invocation{
		Policy: c,
		Binding: decision.Binding{
			Enabled: true, PolicySHA256: c.Digest(), View: decision.Session, Mode: decision.Enforce,
			MatchThreshold: .9, DenyThreshold: .99, BudgetMS: 1000, MaxRequestBytes: 131072,
			MaxHistoryCalls: 64, SendContent: true,
		},
		Profile: Profile{"decisions-v1", "https://provider.example/v1/decisions", "fixture-model", 65536},
		Event:   model.Event{EventID: "e3", SourceAgent: "claude", SessionID: "s1", ToolCallID: "c3", EventType: "tool.call"},
		Evidence: decision.Evidence{
			Subject:  decision.Subject{Installation: "fixture", Agent: "claude", Session: "s1", Generation: "epoch", CallID: "c3", EventID: "e3"},
			Revision: 3, Current: json.RawMessage(`{"tool":"upload","arguments":{"artifact":"a1"}}`),
			History:         []json.RawMessage{json.RawMessage(`{"tool":"read","outcome":"ok"}`)},
			OperatorContext: json.RawMessage(`{"policy":"No credential disclosure"}`),
			CurrentComplete: true, PrefixComplete: true,
		},
		Confirm: func(_ context.Context, r decision.Request) (uint64, error) { return r.Revision, nil },
	}
}

func validProvider(_ context.Context, r decision.Request, _ *decision.Compiled, _ int) (decision.Reply, error) {
	return decision.Reply{
		RequestDigest: r.Digest, Model: r.Model, Choice: "violation",
		Probabilities: map[string]float64{"violation": .995, "permitted": .003, "unknown": .002},
	}, nil
}

func TestNoProviderOnInactivePaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Invocation)
	}{
		{"disabled", func(i *Invocation) { i.Binding.Enabled = false }},
		{"no egress consent", func(i *Invocation) { i.Binding.SendContent = false }},
		{"deterministic deny", func(i *Invocation) { i.DeterministicDeny = true }},
		{"not selected", func(i *Invocation) { i.Event.EventType = "session.start" }},
		{"bad binding", func(i *Invocation) { i.Binding.PolicySHA256 = "foreign" }},
		{"bad subject", func(i *Invocation) { i.Evidence.Subject.CallID = "another-call" }},
		{"oversized", func(i *Invocation) { i.Binding.MaxRequestBytes = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := invocation(t)
			tc.edit(&in)
			called := false
			got := Run(context.Background(), in, func(Profile) (Provider, error) {
				called = true
				return providerFunc(validProvider), nil
			})
			if called || got.DenyCandidate || got.Status != "skipped" {
				t.Fatalf("provider=%v got=%+v", called, got)
			}
		})
	}
}

func TestFailuresAreScoped(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Invocation)
		fn   providerFunc
		want string
	}{
		{"valid", func(*Invocation) {}, validProvider, "semantic_match"},
		{"monitor", func(i *Invocation) { i.Binding.Mode = decision.Monitor }, validProvider, "monitor_mode"},
		{"missing state", func(i *Invocation) { i.Confirm = nil }, validProvider, "state_unavailable"},
		{"stale", func(i *Invocation) {
			i.Confirm = func(context.Context, decision.Request) (uint64, error) { return 4, nil }
		}, validProvider, "stale_snapshot"},
		{"partial", func(i *Invocation) { i.Evidence.PrefixComplete = false }, validProvider, "incomplete_evidence"},
		{"error", func(*Invocation) {}, func(context.Context, decision.Request, *decision.Compiled, int) (decision.Reply, error) {
			return decision.Reply{}, errors.New("secret-bearing upstream error")
		}, "provider_error"},
		{"malformed", func(*Invocation) {}, func(context.Context, decision.Request, *decision.Compiled, int) (decision.Reply, error) {
			return decision.Reply{}, ErrResponse
		}, "provider_contract"},
		{"timeout", func(i *Invocation) { i.Binding.BudgetMS = 5 }, func(ctx context.Context, _ decision.Request, _ *decision.Compiled, _ int) (decision.Reply, error) {
			<-ctx.Done()
			return decision.Reply{}, ctx.Err()
		}, "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := invocation(t)
			tc.edit(&in)
			got := Run(context.Background(), in, func(Profile) (Provider, error) { return tc.fn, nil })
			if got.Reason != tc.want || got.DenyCandidate != (tc.want == "semantic_match") {
				t.Fatalf("got %+v", got)
			}
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), "secret-bearing") {
				t.Fatal("upstream error leaked")
			}
		})
	}
}

func TestFailedAssessmentRetainsKnownGaps(t *testing.T) {
	in := invocation(t)
	in.Evidence.Gaps = []string{"history_evicted"}
	got := Run(context.Background(), in, func(Profile) (Provider, error) {
		return nil, errors.New("provider unavailable")
	})
	if got.InputEligible || got.DenyCandidate || !slices.Contains(got.Gaps, "history_evicted") ||
		!slices.Contains(got.Gaps, "freshness_unchecked") || got.MatchThreshold != in.Binding.MatchThreshold {
		t.Fatalf("failure lost evidence qualification or thresholds: %+v", got)
	}
}

func TestRecoveredPanicsRetainPreparedEvidence(t *testing.T) {
	for _, stage := range []string{"factory", "provider", "confirm"} {
		t.Run(stage, func(t *testing.T) {
			in := invocation(t)
			in.Evidence.Gaps = []string{"history_evicted"}
			in.Confirm = func(_ context.Context, r decision.Request) (uint64, error) {
				if stage == "confirm" {
					panic("secret-bearing panic")
				}
				return r.Revision, nil
			}
			got := Run(context.Background(), in, func(Profile) (Provider, error) {
				if stage == "factory" {
					panic("secret-bearing panic")
				}
				return providerFunc(func(ctx context.Context, r decision.Request, p *decision.Compiled, n int) (decision.Reply, error) {
					if stage == "provider" {
						panic("secret-bearing panic")
					}
					return validProvider(ctx, r, p, n)
				}), nil
			})
			if got.Status != "unavailable" || got.Reason != "evaluator_panic" ||
				got.InputEligible || got.DenyCandidate || got.Matched ||
				!slices.Contains(got.Gaps, "history_evicted") ||
				!slices.Contains(got.Gaps, "freshness_unchecked") {
				t.Fatalf("panic lost evidence qualification or gained authority: %+v", got)
			}
			p := in.Policy.Policy()
			if got.RequestID == "" || got.RequestDigest == "" || got.View != in.Binding.View ||
				got.PolicyID != p.ID || got.PolicyVersion != p.Version ||
				got.MatchThreshold != in.Binding.MatchThreshold || got.DenyThreshold != in.Binding.DenyThreshold {
				t.Fatalf("panic lost prepared assessment metadata: %+v", got)
			}
			raw, err := json.Marshal(got)
			if err != nil || strings.Contains(string(raw), "secret-bearing") {
				t.Fatalf("panic detail leaked or assessment invalid: %s (%v)", raw, err)
			}
		})
	}
}

func TestFailedConfirmationCannotLabelInputEligible(t *testing.T) {
	for name, confirm := range map[string]func(context.Context, decision.Request) (uint64, error){
		"absent": nil,
		"failed zero": func(context.Context, decision.Request) (uint64, error) {
			return 0, errors.New("state unavailable")
		},
		"failed same revision": func(_ context.Context, r decision.Request) (uint64, error) {
			return r.Revision, errors.New("state unavailable")
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, malformed := range []bool{false, true} {
				in := invocation(t)
				in.Confirm = confirm
				got := Run(context.Background(), in, func(Profile) (Provider, error) {
					return providerFunc(func(ctx context.Context, r decision.Request, p *decision.Compiled, n int) (decision.Reply, error) {
						reply, err := validProvider(ctx, r, p, n)
						if malformed {
							reply.Probabilities["violation"] = .5
						}
						return reply, err
					}), nil
				})
				if got.InputEligible || got.DenyCandidate || !slices.Contains(got.Gaps, "state_unavailable") ||
					slices.Contains(got.Gaps, "stale_snapshot") {
					t.Fatalf("malformed=%t failed freshness mislabeled: %+v", malformed, got)
				}
				if malformed && got.Status != "invalid_response" {
					t.Fatalf("response error was hidden: %+v", got)
				}
			}
		})
	}
}

func TestActionInputEligibilityDoesNotDependOnProviderAvailability(t *testing.T) {
	in := invocation(t)
	in.Binding.View = decision.Action
	got := Run(context.Background(), in, func(Profile) (Provider, error) {
		return nil, errors.New("provider unavailable")
	})
	if !got.InputEligible || got.DenyCandidate || got.Status != "unavailable" {
		t.Fatalf("provider failure changed known action-input completeness: %+v", got)
	}
}

func TestExpiredParentAndFreshInvocation(t *testing.T) {
	in := invocation(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	factory := func(Profile) (Provider, error) { t.Fatal("factory called"); return nil, nil }
	if got := Run(ctx, in, factory); got.Status != "timeout" {
		t.Fatalf("got %+v", got)
	}
	var old decision.Reply
	first := Run(context.Background(), in, func(Profile) (Provider, error) {
		return providerFunc(func(ctx context.Context, r decision.Request, p *decision.Compiled, n int) (decision.Reply, error) {
			old, _ = validProvider(ctx, r, p, n)
			return old, nil
		}), nil
	})
	second := Run(context.Background(), in, func(Profile) (Provider, error) {
		return providerFunc(func(context.Context, decision.Request, *decision.Compiled, int) (decision.Reply, error) {
			return old, nil
		}), nil
	})
	if !first.DenyCandidate || second.DenyCandidate || second.Reason != "request_binding" {
		t.Fatalf("replayed response: %+v", second)
	}
}

func TestHTTPContract(t *testing.T) {
	good := `{"model":"fixture-model","answers":{"policy":{"type":"choice","choice":"violation","confidence":0.1,"probabilities":{"violation":0.995,"permitted":0.003,"unknown":0.002}}},"usage":{"input_tokens":123}}`
	metadata := strings.Replace(good, `{"model":`, `{"id":"provider-response","provider":"fixture-provider","model":`, 1)
	for _, tc := range []struct {
		name, body string
		code       int
		deny       bool
	}{
		{"valid ignores confidence", good, 200, true},
		{"valid ignores provider metadata", metadata, 200, true},
		{"truncation not reported", strings.Replace(good, `,"usage":{"input_tokens":123}`, "", 1), 200, true},
		{"null usage", strings.Replace(good, `{"input_tokens":123}`, `null`, 1), 200, true},
		{"no reported truncation", strings.Replace(good, `{"input_tokens":123}`, `{"input_tokens":123,"truncated":false,"truncated_questions":[]}`, 1), 200, true},
		{"null truncation metadata", strings.Replace(good, `{"input_tokens":123}`, `{"truncated":null,"truncated_questions":null}`, 1), 200, true},
		{"state truncated", strings.Replace(good, `{"input_tokens":123}`, `{"truncated":true}`, 1), 200, false},
		{"question truncated", strings.Replace(good, `{"input_tokens":123}`, `{"truncated_questions":["policy"]}`, 1), 200, false},
		{"conflicting truncation", strings.Replace(good, `{"input_tokens":123}`, `{"truncated":false,"truncated_questions":["policy"]}`, 1), 200, false},
		{"truncation alias cannot hide true", strings.Replace(good, `{"input_tokens":123}`, `{"truncated":true,"Truncated":false}`, 1), 200, false},
		{"truncation flag type", strings.Replace(good, `{"input_tokens":123}`, `{"truncated":"false"}`, 1), 200, false},
		{"truncation questions type", strings.Replace(good, `{"input_tokens":123}`, `{"truncated_questions":"policy"}`, 1), 200, false},
		{"truncation item type", strings.Replace(good, `{"input_tokens":123}`, `{"truncated_questions":[false]}`, 1), 200, false},
		{"usage type", strings.Replace(good, `{"input_tokens":123}`, `[]`, 1), 200, false},
		{"metadata does not authorize another model", strings.Replace(metadata, "fixture-model", "fixture-model-other", 1), 200, false},
		{"metadata id type", strings.Replace(metadata, `"id":"provider-response"`, `"id":42`, 1), 200, false},
		{"metadata provider type", strings.Replace(metadata, `"provider":"fixture-provider"`, `"provider":{}`, 1), 200, false},
		{"metadata duplicate", strings.Replace(metadata, `"id":"provider-response"`, `"id":"first","id":"provider-response"`, 1), 200, false},
		{"metadata id alias", strings.Replace(metadata, `"id":`, `"ID":`, 1), 200, false},
		{"metadata provider alias", strings.Replace(metadata, `"provider":`, `"Provider":`, 1), 200, false},
		{"metadata unknown field", strings.Replace(metadata, `"id":`, `"allow":true,"id":`, 1), 200, false},
		{"wrong model", strings.Replace(good, "fixture-model", "other", 1), 200, false},
		{"extra field", strings.Replace(good, `"model":`, `"allow":true,"model":`, 1), 200, false},
		{"duplicate", strings.Replace(good, `"violation":0.995`, `"violation":0.9,"violation":0.995`, 1), 200, false},
		{"case alias", strings.Replace(good, `"choice":"violation"`, `"choice":"permitted","Choice":"violation"`, 1), 200, false},
		{"escaped case alias", strings.Replace(good, `"choice":"violation"`, `"choice":"permitted","\u0043hoice":"violation"`, 1), 200, false},
		{"wrong question", strings.Replace(good, `"policy":`, `"other":`, 1), 200, false},
		{"null probability", strings.Replace(good, `"unknown":0.002`, `"unknown":null`, 1), 200, false},
		{"trailing object", good + `{}`, 200, false},
		{"oversized", strings.Repeat(" ", 66000) + good, 200, false},
		{"rate limit", "secret-bearing error", 429, false},
		{"redirect", "", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.Method != "POST" || req.Header.Get("Authorization") != "Bearer synthetic-token" {
					t.Error("bad request method or auth")
				}
				data, _ := io.ReadAll(req.Body)
				if !strings.Contains(string(data), `"criteria"`) || strings.Contains(string(data), "synthetic-token") {
					t.Error("bad request projection")
				}
				w.Header().Set("Location", "https://untrusted.example")
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			in := invocation(t)
			in.Profile.Endpoint = srv.URL
			client, err := NewHTTP(in.Profile, "synthetic-token")
			if err != nil {
				t.Fatal(err)
			}
			// Trust only this test certificate; retain redirect/no-proxy settings.
			tr := client.client.Transport.(*http.Transport)
			tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			if tr.Proxy != nil {
				t.Fatal("ambient proxy inherited")
			}
			got := Run(context.Background(), in, func(Profile) (Provider, error) { return client, nil })
			if got.DenyCandidate != tc.deny || calls.Load() != 1 {
				t.Fatalf("got %+v calls=%d", got, calls.Load())
			}
			if tc.code == http.StatusOK && !tc.deny && (got.Status != "invalid_response" || got.Reason != "provider_contract") {
				t.Fatalf("invalid reply was not rejected as a provider-contract failure: %+v", got)
			}
		})
	}
}

func TestProfileRejectsUnsafeEndpoints(t *testing.T) {
	in := invocation(t)
	for _, endpoint := range []string{
		"http://provider.example", "https://user:token@provider.example",
		"https://provider.example/?key=secret", "https://provider.example/#fragment",
		"file:///etc/passwd", "",
	} {
		p := in.Profile
		p.Endpoint = endpoint
		if _, err := NewHTTP(p, "synthetic"); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	for _, token := range []string{"", " x", "x\r\nInjected: header"} {
		if _, err := NewHTTP(in.Profile, token); err == nil {
			t.Fatal("accepted invalid credential")
		}
	}
}

func TestHTTPEnforcesRequestDeadlineWithoutParentDeadline(t *testing.T) {
	in := invocation(t)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	in.Profile.Endpoint = srv.URL
	client, err := NewHTTP(in.Profile, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	client.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	req, err := decision.Prepare(in.Policy, in.Binding, in.Evidence, "expired",
		in.Profile.Digest(), in.Profile.Model, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Evaluate(context.Background(), req, in.Policy, in.Binding.MaxRequestBytes); err == nil || calls.Load() != 0 {
		t.Fatal("expired request performed network I/O or returned success")
	}
}

func TestHTTPRejectsUnboundCompiledPolicyBeforeTransport(t *testing.T) {
	in := invocation(t)
	client, err := NewHTTP(in.Profile, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	client.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected transport")
	})
	request, err := decision.Prepare(in.Policy, in.Binding, in.Evidence, "bound",
		in.Profile.Digest(), in.Profile.Model, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	policy := in.Policy.Policy()
	policy.Decision.Instructions += " Different criteria."
	other, err := decision.Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []*decision.Compiled{nil, {}, other} {
		if _, err := client.Evaluate(context.Background(), request, policy, in.Binding.MaxRequestBytes); !errors.Is(err, ErrInput) {
			t.Fatalf("unbound policy accepted: %v", err)
		}
	}
	if called {
		t.Fatal("invalid policy reached transport")
	}
}

func TestLateStateConfirmationCannotDeny(t *testing.T) {
	in := invocation(t)
	in.Binding.BudgetMS = 5
	in.Confirm = func(ctx context.Context, r decision.Request) (uint64, error) {
		<-ctx.Done()
		return r.Revision, nil
	}
	got := Run(context.Background(), in, func(Profile) (Provider, error) { return providerFunc(validProvider), nil })
	if got.DenyCandidate || got.Status != "timeout" {
		t.Fatalf("got %+v", got)
	}
}

func TestExpiredInitializationDoesNotEvaluate(t *testing.T) {
	in := invocation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := Run(ctx, in, func(Profile) (Provider, error) {
		cancel()
		return providerFunc(func(context.Context, decision.Request, *decision.Compiled, int) (decision.Reply, error) {
			t.Fatal("evaluation started after initialization exhausted the budget")
			return decision.Reply{}, nil
		}), nil
	})
	if got.DenyCandidate || got.Status != "timeout" {
		t.Fatalf("got %+v", got)
	}
}

func TestHTTPBoundsFullRequestEnvelope(t *testing.T) {
	in := invocation(t)
	client, err := NewHTTP(in.Profile, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	// Establish the serialized envelope length without making a network call.
	var size int
	client.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		size = len(body)
		return nil, errors.New("synthetic transport stop")
	})
	request, err := decision.Prepare(in.Policy, in.Binding, in.Evidence, "bounded",
		in.Profile.Digest(), in.Profile.Model, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Evaluate(context.Background(), request, in.Policy, in.Binding.MaxRequestBytes)
	if size <= len(request.State) {
		t.Fatal("test did not include the policy envelope")
	}
	for _, tc := range []struct {
		limit int
		call  bool
	}{
		{size - 1, false},
		{size, true},
	} {
		called := false
		client.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("synthetic transport stop")
		})
		_, err := client.Evaluate(context.Background(), request, in.Policy, tc.limit)
		if called != tc.call || (!tc.call && !errors.Is(err, ErrInput)) {
			t.Fatalf("limit=%d called=%t err=%v", tc.limit, called, err)
		}
	}
	in.Binding.MaxRequestBytes = size - 1
	got := Run(context.Background(), in, func(Profile) (Provider, error) { return client, nil })
	if got.Status != "skipped" || got.Reason != "invalid_or_oversized_input" {
		t.Fatalf("local input failure mislabeled: %+v", got)
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCancellationDuringConfirmationCannotDeny(t *testing.T) {
	in := invocation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in.Confirm = func(_ context.Context, r decision.Request) (uint64, error) {
		cancel()
		return r.Revision, nil
	}
	got := Run(ctx, in, func(Profile) (Provider, error) { return providerFunc(validProvider), nil })
	if got.DenyCandidate || got.Status != "timeout" {
		t.Fatalf("got %+v", got)
	}
}

func TestParallelRequestsDoNotShareVerdicts(t *testing.T) {
	for n := range 12 {
		t.Run(time.Duration(n).String(), func(t *testing.T) {
			t.Parallel()
			in := invocation(t)
			got := Run(context.Background(), in, func(Profile) (Provider, error) { return providerFunc(validProvider), nil })
			if !got.DenyCandidate {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func FuzzUniqueJSON(f *testing.F) {
	f.Add([]byte(`{"x":1}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = decision.ValidJSON(data)
		if decision.ValidJSON(data) {
			_ = exactResponseFields(data)
		}
	})
}

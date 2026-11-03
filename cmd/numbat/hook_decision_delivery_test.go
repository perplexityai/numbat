//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/evaluator"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/state"
)

func decisionHTTPHook(t *testing.T, lab *decisionHookLab, url string, batch int, extra ...string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "session",
		"tool_use_id": "upload-1", "tool_name": "mcp__fixture__upload",
		"tool_input": map[string]any{"artifact": "synthetic"},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--agent", "claude", "--enforce", "--emit", "findings",
		"--no-builtin-rules", "--rules-dir", filepath.Join(lab.dir, "decisions"),
		"--output", "http", "--http-url", url,
		"--http-timeout", "2s", "--http-batch-size", fmt.Sprint(batch),
		"--state-db", filepath.Join(lab.dir, "state", "state.db"),
		"--decision-config", lab.config,
	}
	args = append(args, extra...)
	var control, diagnostics bytes.Buffer
	if code := runHookEvent("pre-tool", args, bytes.NewReader(raw), &control, &diagnostics); code != 0 {
		t.Fatalf("hook code=%d diagnostics=%s", code, &diagnostics)
	}
	return control.String()
}

func TestNativeDecisionHTTPDeliverySharesHookDeadline(t *testing.T) {
	lab := newDecisionHookLab(t)
	lab.cfg.BudgetMS, lab.cfg.TimeoutMS = 1000, 1000
	lab.rules[0].Decision.View, lab.rules[0].Decision.MaxHistoryCalls = decision.Action, 0
	prototype := lab.rules[0]
	lab.rules = nil
	for i := range 8 {
		r := prototype
		r.ID = fmt.Sprintf("local.policy%d", i)
		lab.rules = append(lab.rules, r)
	}
	lab.save(t)
	if err := validateDecisionHook(&lab.cfg, emitSelection{findings: true}, outputSinks{http: true}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		posts.Add(1)
		select {
		case <-time.After(1025 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer receiver.Close()
	start := time.Now()
	control := decisionHTTPHook(t, lab, receiver.URL, 1)
	elapsed := time.Since(start)
	if elapsed > decisionHookBudget+500*time.Millisecond || posts.Load() < 2 || lab.hits.Load() == 0 ||
		strings.Contains(control, `"permissionDecision":"deny"`) {
		t.Fatalf("elapsed=%s posts=%d provider_calls=%d control=%s", elapsed, posts.Load(), lab.hits.Load(), control)
	}
}

func TestNativeDecisionReconfirmsAfterOutput(t *testing.T) {
	for _, tc := range []struct {
		stage         string
		view          string
		deterministic bool
		wantDeny      bool
	}{
		{"unchanged", decision.Session, false, true},
		{"provider", decision.Session, false, false},
		{"assessment", decision.Session, false, false},
		{"enforcement", decision.Session, false, false},
		{"final_flush", decision.Session, false, false},
		{"final_flush", decision.Action, false, true},
		{"final_flush", decision.Session, true, true},
	} {
		t.Run(fmt.Sprintf("%s/%s/local=%t", tc.stage, tc.view, tc.deterministic), func(t *testing.T) {
			lab := newDecisionHookLab(t)
			lab.rules[0].Decision.View = tc.view
			if tc.view == decision.Action {
				lab.rules[0].Decision.MaxHistoryCalls = 0
			}
			if tc.deterministic {
				lab.rules = append(lab.rules, rule.Rule{
					ID: "local.block", Version: "1", Title: "Synthetic local deny", Severity: "high",
					Expr: `event.tool_name == "mcp__fixture__upload"`, Enforce: decisionBool(true),
				})
			}
			lab.save(t)
			lab.invoke(t, "session-start", map[string]any{
				"hook_event_name": "SessionStart", "source": "startup",
			}, "--no-builtin-rules")
			c, err := evaluator.LoadConfig(lab.config)
			if err != nil {
				t.Fatal(err)
			}
			var changed atomic.Bool
			var once sync.Once
			invalidate := func() {
				once.Do(func() {
					db, err := state.OpenEvidence(filepath.Join(lab.dir, "state", "state.db"), time.Second)
					if err != nil {
						t.Error(err)
						return
					}
					snapshot, observeErr := db.ObserveDecision(c.Digest(), decision.Observation{
						Subject: decision.Subject{
							Installation: c.InstallationID, Agent: model.AgentClaudeCode, Session: "session",
						},
						Phase: "gap",
					}, c.State, time.Now())
					closeErr := db.Close()
					if observeErr != nil || closeErr != nil || snapshot.PrefixComplete {
						t.Errorf("gap mutation: observe=%v close=%v complete=%t", observeErr, closeErr, snapshot.PrefixComplete)
						return
					}
					changed.Store(true)
				})
			}
			if tc.stage == "provider" {
				lab.check = func(_ *http.Request, _ []byte) { invalidate() }
			}
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				switch tc.stage {
				case "assessment":
					if bytes.Contains(raw, []byte(`"record_type":"assessment"`)) {
						invalidate()
					}
				case "enforcement", "final_flush":
					if bytes.Contains(raw, []byte(`"record_type":"enforcement"`)) {
						invalidate()
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer receiver.Close()
			batch := 1
			if tc.stage == "final_flush" {
				batch = 500
			}
			control := decisionHTTPHook(t, lab, receiver.URL, batch)
			wantCalls := int32(1)
			if tc.deterministic {
				wantCalls = 0
			}
			if changed.Load() != (tc.stage != "unchanged") || lab.hits.Load() != wantCalls ||
				strings.Contains(control, `"permissionDecision":"deny"`) != tc.wantDeny {
				t.Fatalf("mutation=%t provider_calls=%d control=%s", changed.Load(), lab.hits.Load(), control)
			}
		})
	}
}

func TestNativeDecisionAuditLossRetainsCleanOutputGate(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			lab := newDecisionHookLab(t)
			lab.rules[0].Decision.View, lab.rules[0].Decision.MaxHistoryCalls = decision.Action, 0
			lab.rules = append(lab.rules, rule.Rule{
				ID: "local.block", Version: "1", Title: "Synthetic local deny", Severity: "high",
				Expr: "true", Enforce: decisionBool(true),
			})
			lab.save(t)
			var findingAccepted, assessmentRejected atomic.Bool
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if bytes.Contains(raw, []byte(`"record_type":"assessment"`)) {
					assessmentRejected.Store(true)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if bytes.Contains(raw, []byte(`"rule_id":"local.block"`)) {
					findingAccepted.Store(true)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer receiver.Close()
			var extra []string
			if !enabled {
				extra = []string{"--decision-config", ""}
			}
			control := decisionHTTPHook(t, lab, receiver.URL, 1, extra...)
			denied := strings.Contains(control, `"permissionDecision":"deny"`)
			if !findingAccepted.Load() || assessmentRejected.Load() != enabled || denied == enabled || lab.hits.Load() != 0 {
				t.Fatalf("enabled=%t finding_accepted=%t assessment_rejected=%t deny=%t provider_calls=%d",
					enabled, findingAccepted.Load(), assessmentRejected.Load(), denied, lab.hits.Load())
			}
		})
	}
}

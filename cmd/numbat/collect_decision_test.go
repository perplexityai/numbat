//go:build unix

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/rule"
)

type collectorDecisionWriter struct {
	bytes.Buffer
	failType string
	failed   chan struct{}
	matched  chan struct{}
}

func (w *collectorDecisionWriter) Write(p []byte) (int, error) {
	if w.failType != "" && bytes.Contains(p, []byte(`"record_type":"`+w.failType+`"`)) {
		w.failType = ""
		close(w.failed)
		return 0, io.ErrClosedPipe
	}
	n, err := w.Buffer.Write(p)
	if bytes.Contains(p, []byte(`"record_type":"finding"`)) && bytes.Contains(p, []byte(`"rule_id":"local.transfer"`)) {
		w.matched <- struct{}{}
	}
	return n, err
}

func newCollectorDecisionLab(t *testing.T) *decisionHookLab {
	t.Helper()
	lab := newDecisionHookLab(t)
	lab.rules[0].Decision.Select = "true"
	lab.rules[0].Decision.View = decision.Action
	lab.rules[0].Decision.MaxHistoryCalls = 0
	lab.rules = append(lab.rules, rule.Rule{
		ID: "local.deterministic", Version: "1", Title: "Synthetic", Severity: "high",
		Expr: `event.tool_name == "Read"`,
	})
	lab.save(t)
	return lab
}

func newDecisionCollector(t *testing.T, lab *decisionHookLab, records io.Writer) *collector {
	t.Helper()
	em := output.New(records, io.Discard, "test")
	c, err := newCollector(collectorConfig{
		emit: em, runID: "test", decisionConfig: lab.config,
		ruleDirs: multiFlag{filepath.Join(lab.dir, "decisions")}, noBuiltin: true,
		sel: emitSelection{events: true, findings: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.close()
		if err := em.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func decisionCollectRequest(ctx context.Context, c *collector, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, otlpLogsPath, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", contentTypeProtobuf)
	res := httptest.NewRecorder()
	c.handleLogs(res, req)
	return res
}

func waitCollectorDecision(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("collector decision did not complete")
	}
}

func TestClosedCollectorRejectsFurtherAdmission(t *testing.T) {
	lab := newCollectorDecisionLab(t)
	var records bytes.Buffer
	c := newDecisionCollector(t, lab, &records)
	c.close()
	body := buildOTLPLogs("claude-code", []map[string]string{
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read"},
	})
	res := decisionCollectRequest(context.Background(), c, body)
	if res.Code != http.StatusServiceUnavailable || c.processed() != 0 || lab.hits.Load() != 0 || records.Len() != 0 {
		t.Fatalf("closed collector accepted work: status=%d processed=%d requests=%d records=%d",
			res.Code, c.processed(), lab.hits.Load(), records.Len())
	}
}

func TestCollectorImmediateAssessmentFailureDoesNotRejectExport(t *testing.T) {
	lab := newCollectorDecisionLab(t)
	lab.rules[0].Decision.Select = "false"
	lab.save(t)
	records := &collectorDecisionWriter{failType: "assessment", failed: make(chan struct{}), matched: make(chan struct{}, 1)}
	c := newDecisionCollector(t, lab, records)
	body := buildOTLPLogs("claude-code", []map[string]string{
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read"},
	})
	res := decisionCollectRequest(context.Background(), c, body)
	c.close()
	if res.Code != http.StatusOK || c.processed() != 1 || lab.hits.Load() != 0 ||
		c.emit.Stats().RecordErrors != 1 || c.advisoryErrors != 1 {
		t.Fatalf("optional skip output rejected telemetry: status=%d processed=%d requests=%d errors=%d optional=%d",
			res.Code, c.processed(), lab.hits.Load(), c.emit.Stats().RecordErrors, c.advisoryErrors)
	}
}

func TestCollectorHTTPAckDoesNotCancelAcceptedInference(t *testing.T) {
	lab := newCollectorDecisionLab(t)
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	lab.check = func(r *http.Request, _ []byte) {
		started <- r.Context()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}
	records := &collectorDecisionWriter{matched: make(chan struct{}, 1)}
	c := newDecisionCollector(t, lab, records)
	server := httptest.NewServer(http.HandlerFunc(c.handleLogs))
	defer server.Close()
	body := buildOTLPLogs("claude-code", []map[string]string{
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+otlpLogsPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentTypeProtobuf)
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("actual HTTP acknowledgment waited for inference: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("HTTP status=%d", res.StatusCode)
	}
	var provider context.Context
	select {
	case provider = <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("accepted work was not dispatched")
	}
	select {
	case <-provider.Done():
		t.Fatal("finishing the actual HTTP handler cancelled accepted inference")
	default:
	}
	close(release)
	waitCollectorDecision(t, records.matched)
	c.close()
	if c.processed() != 1 || lab.hits.Load() != 1 {
		t.Fatalf("processed=%d model requests=%d", c.processed(), lab.hits.Load())
	}
}

func TestCollectorAcknowledgesBeforeDecisionCompletes(t *testing.T) {
	for _, mode := range []string{"cancelled", "expired", "after_ack", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			lab := newCollectorDecisionLab(t)
			started := make(chan context.Context, 2)
			release := make(chan struct{})
			lab.check = func(r *http.Request, _ []byte) {
				started <- r.Context()
				select {
				case <-release:
				case <-r.Context().Done():
				case <-time.After(3 * time.Second):
					t.Error("provider was neither released nor cancelled")
				}
			}
			records := &collectorDecisionWriter{matched: make(chan struct{}, 2)}
			c := newDecisionCollector(t, lab, records)
			ctx, cancel := context.WithCancel(context.Background())
			switch mode {
			case "cancelled":
				cancel()
			case "expired":
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			defer cancel()
			body := buildOTLPLogs("claude-code", []map[string]string{
				{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/first"},
				{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/second"},
			})
			ack := make(chan *httptest.ResponseRecorder, 1)
			go func() { ack <- decisionCollectRequest(ctx, c, body) }()
			select {
			case res := <-ack:
				if res.Code != http.StatusOK || c.processed() != 2 {
					t.Fatalf("HTTP=%d processed=%d", res.Code, c.processed())
				}
			case <-time.After(time.Second):
				t.Fatal("OTLP acknowledgment waited for the blocked provider")
			}
			stats := c.emit.Stats()
			if stats.EventsEmitted != 2 || stats.FindingsEmitted != 2 {
				t.Fatalf("local telemetry did not finish before inference: %+v", stats)
			}
			var providerContext context.Context
			select {
			case providerContext = <-started:
			case <-time.After(time.Second):
				t.Fatal("accepted telemetry did not start optional model work")
			}
			cancel()
			select {
			case <-providerContext.Done():
				t.Fatal("HTTP request cancellation stopped collector-owned model work")
			case <-time.After(50 * time.Millisecond):
			}
			if mode == "shutdown" {
				c.close()
				select {
				case <-providerContext.Done():
				case <-time.After(time.Second):
					t.Fatal("collector shutdown did not cancel the provider")
				}
			} else {
				close(release)
				waitCollectorDecision(t, records.matched)
				waitCollectorDecision(t, records.matched)
				c.close()
			}
			wantCalls := int32(2)
			wantFindings := 4
			if mode == "shutdown" {
				wantCalls, wantFindings = 1, 2
			}
			if lab.hits.Load() != wantCalls || c.processed() != 2 ||
				c.emit.Stats().FindingsEmitted != wantFindings ||
				bytes.Count(records.Bytes(), []byte(`"record_type":"event"`)) != 2 ||
				bytes.Count(records.Bytes(), []byte(`"record_type":"assessment"`)) != 2 ||
				bytes.Count(records.Bytes(), []byte(`"rule_id":"local.deterministic"`)) != 2 ||
				bytes.Contains(records.Bytes(), []byte(`"deny_candidate":true`)) {
				t.Fatalf("background work lost local records or gained enforcement: calls=%d stats=%+v records=%s",
					lab.hits.Load(), c.emit.Stats(), records.Bytes())
			}
		})
	}
}

func TestCollectorDecisionSinkFailureDoesNotPoisonNextExport(t *testing.T) {
	for _, recordType := range []string{"assessment", "event"} {
		t.Run(recordType, func(t *testing.T) {
			lab := newCollectorDecisionLab(t)
			records := &collectorDecisionWriter{
				failType: recordType, failed: make(chan struct{}), matched: make(chan struct{}, 2),
			}
			c := newDecisionCollector(t, lab, records)
			body := buildOTLPLogs("claude-code", []map[string]string{{
				"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/first",
			}})
			res := decisionCollectRequest(context.Background(), c, body)
			wantStatus := http.StatusOK
			if recordType == "event" {
				wantStatus = http.StatusServiceUnavailable
			}
			if res.Code != wantStatus {
				t.Fatalf("first export status=%d, want %d", res.Code, wantStatus)
			}
			waitCollectorDecision(t, records.failed)
			body = buildOTLPLogs("claude-code", []map[string]string{{
				"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/second",
			}})
			if res := decisionCollectRequest(context.Background(), c, body); res.Code != http.StatusOK {
				t.Fatalf("prior %s failure poisoned the next export: HTTP=%d", recordType, res.Code)
			}
			c.close()
			stats := c.emit.Stats()
			if stats.RecordErrors != 1 || c.processed() != 2 ||
				bytes.Count(records.Bytes(), []byte(`"rule_id":"local.deterministic"`)) != 2 {
				t.Fatalf("sink failure lost local findings or changed export accounting: stats=%+v processed=%d records=%s",
					stats, c.processed(), records.Bytes())
			}
		})
	}
}

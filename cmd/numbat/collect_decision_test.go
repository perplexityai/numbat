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
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/rule"
)

func TestCollectorCancellationStopsOnlyModelWork(t *testing.T) {
	for _, mode := range []string{"before", "during", "expired", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			lab := newDecisionHookLab(t)
			lab.rules[0].Decision.Select = "true"
			lab.rules[0].Decision.View = decision.Action
			lab.rules[0].Decision.MaxHistoryCalls = 0
			lab.rules = append(lab.rules, rule.Rule{
				ID: "local.deterministic", Version: "1", Title: "Synthetic", Severity: "high",
				Expr: `event.tool_name == "Read"`,
			})
			lab.save(t)
			ctx, cancel := context.WithCancel(context.Background())
			switch mode {
			case "expired", "deadline":
				cancel()
				remaining := -time.Second
				if mode == "deadline" {
					remaining = 500 * time.Millisecond
				}
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(remaining))
			}
			defer cancel()
			if mode == "during" || mode == "deadline" {
				lab.check = func(r *http.Request, _ []byte) {
					if mode == "during" {
						cancel()
					}
					select {
					case <-r.Context().Done():
					case <-time.After(3 * time.Second):
						t.Error("provider request did not receive cancellation")
					}
				}
			} else {
				cancel()
			}
			var records bytes.Buffer
			em := output.New(&records, io.Discard, "test")
			c, err := newCollector(collectorConfig{
				emit: em, runID: "test", decisionConfig: lab.config,
				ruleDirs: multiFlag{filepath.Join(lab.dir, "decisions")}, noBuiltin: true,
				sel: emitSelection{events: true, findings: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			body := buildOTLPLogs("claude-code", []map[string]string{
				{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/first"},
				{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/second"},
				{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read", "file.path": "/synthetic/third"},
			})
			req := httptest.NewRequest(http.MethodPost, otlpLogsPath, bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", contentTypeProtobuf)
			res := httptest.NewRecorder()
			c.handleLogs(res, req)
			if err := em.Close(); err != nil {
				t.Fatal(err)
			}
			wantCalls := int32(0)
			if mode == "during" || mode == "deadline" {
				wantCalls = 1
			}
			if lab.hits.Load() != wantCalls || c.processed() != 3 || res.Code != http.StatusOK ||
				bytes.Count(records.Bytes(), []byte(`"record_type":"finding"`)) != 3 ||
				bytes.Count(records.Bytes(), []byte(`"status":"timeout"`)) != 3 {
				t.Fatalf("cancellation lost local work or continued inference: calls=%d processed=%d HTTP=%d records=%s",
					lab.hits.Load(), c.processed(), res.Code, records.Bytes())
			}
		})
	}
}

func TestCollectorSharesModelDeadlineAcrossExport(t *testing.T) {
	c, err := newCollector(collectorConfig{
		emit: output.New(io.Discard, io.Discard, "test"), sel: emitSelection{findings: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.emit.Close()
	calls := 0
	var firstDeadline time.Time
	start := time.Now()
	c.pipe.WithDecisionObserver(func(ctx context.Context, _ model.Event) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(start.Add(collectDecisionBudget+time.Second)) {
			t.Fatal("collector did not cap model work")
		}
		if calls > 0 && !deadline.Equal(firstDeadline) {
			t.Fatal("collector renewed the model deadline for a later record")
		}
		firstDeadline = deadline
		calls++
	})
	body := buildOTLPLogs("claude-code", []map[string]string{
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read"},
		{"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Read"},
	})
	req := httptest.NewRequest(http.MethodPost, otlpLogsPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentTypeProtobuf)
	c.handleLogs(httptest.NewRecorder(), req)
	if calls != 2 || c.processed() != 2 {
		t.Fatalf("deadline probe did not process the batch: calls=%d processed=%d", calls, c.processed())
	}
}

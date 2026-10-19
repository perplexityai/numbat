package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
)

func runtimeConfig(t *testing.T, inspect func([]byte)) (*Config, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("missing token")
		}
		if inspect != nil {
			inspect(body)
		}
		_, _ = io.WriteString(w, `{"model":"fixture","answers":{"policy":{"type":"choice","choice":"violation","probabilities":{"violation":0.999,"unknown":0.001}}}}`)
	}))
	t.Cleanup(server.Close)
	dir := runtimePrivateDir(t)
	token, ca, config := filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "config.json")
	c := Config{
		Version: "1", InstallationID: "test", BudgetMS: 2000, TimeoutMS: 2000, MaxRequestBytes: 32768, Content: "raw",
		Provider: ProviderConfig{Profile: Profile{Protocol: "decisions-v1", Endpoint: server.URL, Model: "fixture", MaxResponseBytes: 4096}, TokenFile: token, CAFile: ca},
		State:    StateConfig{MaxSessions: 4, MaxCalls: 8, MaxBytes: 32768, IdleTTLMS: 60000},
	}
	raw, _ := json.Marshal(c)
	for path, data := range map[string][]byte{
		token: []byte("synthetic-token"), config: raw,
		ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	return loaded, &hits
}

func runtimeRule(view string) rule.Rule {
	enforce := true
	return rule.Rule{
		ID: "local.test", Version: "1", Title: "Synthetic", Severity: "high", Enforce: &enforce,
		Decision: &rule.DecisionSpec{
			Select: "true", Instructions: "Classify the action.", View: view,
			Options:     map[string]string{"violation": "Prohibited.", "unknown": "Insufficient evidence."},
			MatchOption: "violation", AbstainOption: "unknown", MatchThreshold: .9, DenyThreshold: .99,
		},
	}
}

func runtimeEvent(id, session, path string) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion, EventID: id, SourceAgent: model.AgentClaudeCode,
		SourceType: model.SourceArtifact, SessionID: session, ToolCallID: id, EventType: model.EventFileRead,
		FilePath: path, Confidence: "high", Evidence: model.Evidence{ArtifactType: "synthetic", LocalPath: "a.jsonl"},
	}
}

func TestRuntimePreservesWholeActionAndPartialFindings(t *testing.T) {
	for _, complete := range []bool{true, false} {
		c, hits := runtimeConfig(t, func(raw []byte) {
			if !bytes.Contains(raw, []byte("/first")) || !bytes.Contains(raw, []byte("/second")) {
				t.Error("batch evidence lost")
			}
		})
		r := runtimeRule(decision.Action)
		r.Decision.Select = `event.file_path == "/first"`
		if err := c.ConfigureRules([]rule.Rule{r}); err != nil {
			t.Fatal(err)
		}
		events := []model.Event{runtimeEvent("first", "session", "/first"), runtimeEvent("second", "session", "/second")}
		for i := range events {
			events[i].SourceType = model.SourceHook
			events[i].ToolCallID = "one-call"
		}
		o := decision.ProjectBatch(events, "pre", "raw")
		var out bytes.Buffer
		em := output.New(&out, io.Discard, "test")
		control := &pipeline.EnforceDecision{}
		c.Evaluate(context.Background(), Evaluation{Events: events, Control: control, Evidence: func(ev model.Event, _ string) decision.Evidence {
			s := o.Subject
			s.Installation = "test"
			s.Generation = "epoch"
			s.EventID = ev.EventID
			return decision.Evidence{Subject: s, Current: o.Current(), CurrentComplete: complete, OperatorContext: json.RawMessage(`{}`)}
		}}, em)
		if err := em.Close(); err != nil {
			t.Fatal(err)
		}
		if hits.Load() != 1 || control.Blocked != complete || !control.Matched {
			t.Fatalf("wrong batch result: hits=%d control=%+v", hits.Load(), control)
		}
		var found bool
		for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
			var record struct {
				RecordType string `json:"record_type"`
				model.Finding
			}
			if err := json.Unmarshal(line, &record); err != nil {
				t.Fatal(err)
			}
			if record.RecordType == "finding" {
				found = true
				if record.AssessmentID == "" || !slices.Equal(record.CitedEventIDs, []string{"first", "second"}) ||
					(!complete && !slices.Contains(record.DecisionGaps, "current_incomplete")) {
					t.Fatalf("unqualified finding: %+v", record)
				}
			}
		}
		if !found {
			t.Fatal("advisory match disappeared")
		}
	}
}

func TestMonitorPartitionsAndNeverAuthorizesDeny(t *testing.T) {
	var bodies [][]byte
	c, hits := runtimeConfig(t, func(raw []byte) { bodies = append(bodies, slices.Clone(raw)) })
	if err := c.ConfigureRules([]rule.Rule{runtimeRule(decision.Session)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	em := output.New(&out, io.Discard, "test")
	observe := c.Monitor(em)
	a := runtimeEvent("one", "s", "/artifact-A")
	observe(a)
	b := runtimeEvent("two", "s", "/artifact-B")
	b.Evidence.LocalPath = "b.jsonl"
	observe(b)
	a.EventID, a.ToolCallID, a.FilePath = "three", "three", "/current-A"
	observe(a)
	if hits.Load() != 3 || bytes.Contains(bodies[1], []byte("/artifact-A")) || !bytes.Contains(bodies[2], []byte("/artifact-A")) {
		t.Fatalf("artifact partitions mixed or lost: %q", bodies)
	}
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(`"deny_candidate":true`)) || !bytes.Contains(out.Bytes(), []byte("history_coverage_unverified")) {
		t.Fatalf("passive history gained authority: %s", out.Bytes())
	}
}

func TestEveryNormalizedAgentCanBeClassified(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", "v"+model.SchemaVersion, "event-record.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	agents := schema.Properties["source_agent"].Enum
	if len(agents) < 2 {
		t.Fatal("missing source vocabulary")
	}
	for _, agent := range agents {
		t.Run(agent, func(t *testing.T) {
			in := invocation(t)
			in.Binding.View = decision.Action
			in.Event.SourceAgent, in.Evidence.Subject.Agent = agent, agent
			in.Event.SessionID, in.Event.ToolCallID = "", ""
			in.Evidence.Subject.Session, in.Evidence.Subject.CallID = "", ""
			got := Run(context.Background(), in, func(Profile) (Provider, error) { return providerFunc(validProvider), nil })
			if !got.Matched || !got.DenyCandidate {
				t.Fatalf("arbitrary agent or identity restriction: %+v", got)
			}
		})
	}
}

func TestExactResponseAliasMappingAndRouting(t *testing.T) {
	for _, returned := range []string{"resolved-model", "requested-alias", "unrelated"} {
		t.Run(returned, func(t *testing.T) {
			in := invocation(t)
			in.Profile.ExpectedModel = "resolved-model"
			in.Profile.Model = "requested-alias"
			in.Profile.Routing = &Routing{DataCollection: "deny"}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if !bytes.Contains(raw, []byte(`"model":"requested-alias"`)) || !bytes.Contains(raw, []byte(`"allow_fallbacks":false`)) || !bytes.Contains(raw, []byte(`"data_collection":"deny"`)) {
					t.Errorf("wrong routed request: %s", raw)
				}
				body := `{"model":"` + returned + `","answers":{"policy":{"type":"choice","choice":"violation","probabilities":{"violation":0.999,"permitted":0.0005,"unknown":0.0005}}}}`
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			in.Profile.Endpoint = server.URL
			got := Run(context.Background(), in, func(p Profile) (Provider, error) {
				h, err := NewHTTP(p, "synthetic-token")
				if err != nil {
					return nil, err
				}
				h.client = server.Client()
				h.client.Timeout = time.Second
				return h, nil
			})
			if (got.Status == "completed") != (returned == "resolved-model") || (returned != "resolved-model" && got.DenyCandidate) {
				t.Fatalf("alias validation: %+v", got)
			}
			if returned == "resolved-model" && !strings.EqualFold(got.ReturnedModel, returned) {
				t.Fatal("actual response identity lost")
			}
		})
	}
}

func TestCollectorWithoutOriginDoesNotMergeExporters(t *testing.T) {
	var bodies [][]byte
	c, _ := runtimeConfig(t, func(raw []byte) { bodies = append(bodies, slices.Clone(raw)) })
	if err := c.ConfigureRules([]rule.Rule{runtimeRule(decision.Session)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	em := output.New(&out, io.Discard, "test")
	observe := c.Monitor(em)
	for _, path := range []string{"/exporter-A", "/exporter-B"} {
		ev := runtimeEvent(path, "same-session", path)
		ev.SourceType = model.SourceOTel
		ev.Evidence = model.Evidence{ArtifactType: "otel"}
		observe(ev)
	}
	if len(bodies) != 2 || bytes.Contains(bodies[1], []byte("/exporter-A")) {
		t.Fatalf("unknown exporters combined: %q", bodies)
	}
	if !bytes.Contains(out.Bytes(), []byte("history_origin_unknown")) {
		t.Fatal("unknown origin not reported")
	}
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWholeProviderEnvelopeFitsAfterHistoryTrim(t *testing.T) {
	c, _ := runtimeConfig(t, func(raw []byte) {
		if len(raw) > 1200 || !bytes.Contains(raw, []byte("current-marker")) {
			t.Errorf("incorrect request bound: %d bytes", len(raw))
		}
	})
	c.MaxRequestBytes = 1200
	if err := c.ConfigureRules([]rule.Rule{runtimeRule(decision.Session)}); err != nil {
		t.Fatal(err)
	}
	in := invocation(t)
	in.Evidence.Current = json.RawMessage(`{"command":"current-marker"}`)
	for range 50 {
		in.Evidence.History = append(in.Evidence.History, json.RawMessage(`{"result":"`+strings.Repeat("x", 200)+`"}`))
	}
	var out bytes.Buffer
	em := output.New(&out, io.Discard, "test")
	ev := runtimeEvent("e", "s", "current-marker")
	in.Evidence.Subject.Agent = ev.SourceAgent
	in.Evidence.Subject.Session = ev.SessionID
	in.Evidence.Subject.CallID = ev.ToolCallID
	in.Evidence.Subject.EventID = ev.EventID
	c.Evaluate(context.Background(), Evaluation{Events: []model.Event{ev}, Evidence: func(model.Event, string) decision.Evidence { return in.Evidence }}, em)
	if !bytes.Contains(out.Bytes(), []byte("history_bytes_limit")) || bytes.Contains(out.Bytes(), []byte(`"deny_candidate":true`)) {
		t.Fatalf("trim hidden or gained authority: %s", out.Bytes())
	}
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
}

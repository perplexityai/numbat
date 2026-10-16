package output

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

func TestRecordLimit(t *testing.T) {
	original := []byte(`{"schema_version":"0.5.0","record_type":"event","event_id":"e","tool_input":"{\"query\":\"keep\"}","tool_input_bytes":16,"tool_result":"` +
		strings.Repeat("x", 1000) + `","tool_result_bytes":2000,"tool_result_truncated":true,"extra":{"wide":9007199254740993},"content_preview":"keep"}` + "\n")
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(original, &fields); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, len(original), len(original) + 1} {
		got, err := limitRecord(fields, original, limit)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("limit %d changed fitting output: %v", limit, err)
		}
	}
	got, err := limitRecord(fields, original, len(original)-1)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(original, &before)
	_ = json.Unmarshal(got, &after)
	if string(after["content_omitted"]) != `["tool_result"]` {
		t.Fatalf("omitted = %s", after["content_omitted"])
	}
	delete(before, "tool_result")
	delete(after, "content_omitted")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("metadata or smaller body changed")
	}
}

func TestRecordLimitRepeatedReduction(t *testing.T) {
	input := []byte(`{"schema_version":"0.5.0","record_type":"event","tool_input":"` +
		strings.Repeat(`\"`, 500) + `","tool_result":"` + strings.Repeat("界", 600) +
		`","tool_input_bytes":500,"tool_result_bytes":1800}` + "\n")
	for _, limit := range []int{1500, 250} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(input, &fields); err != nil {
			t.Fatal(err)
		}
		got, err := limitRecord(fields, input, limit)
		if err != nil || len(got) > limit {
			t.Fatalf("limit=%d len=%d err=%v", limit, len(got), err)
		}
		input = got
	}
	var got model.Event
	_ = json.Unmarshal(input, &got)
	if !reflect.DeepEqual(got.ContentOmitted, []string{"tool_result", "tool_input"}) ||
		got.ToolInputBytes != 500 || got.ToolResultBytes != 1800 ||
		got.ToolInputTruncated || got.ToolResultTruncated {
		t.Fatalf("omission metadata changed: %+v", got)
	}
}

func TestRecordLimitRejectsIrreducibleMetadata(t *testing.T) {
	var first, second bytes.Buffer
	em := NewWithSink(NewMultiSink(nopCloseSink{&first}, nopCloseSink{&second}), io.Discard, "run",
		WithRawContent(), WithMaxRecordBytes(1024))
	ev := model.Event{SchemaVersion: model.SchemaVersion, EventType: model.EventCommandExec, Command: strings.Repeat("x", 2048)}
	ev.SetToolInput(strings.Repeat("y", 4096))
	if err := em.EmitEvent(ev); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("irreducible event error = %v", err)
	}
	if first.Len() != 0 || second.Len() != 0 || em.Stats().RecordErrors != 1 {
		t.Fatal("irreducible event reached a sink or lost failure accounting")
	}
}

func TestRecordLimitBeforeFanout(t *testing.T) {
	for _, mode := range []string{"preview", "full", "raw", "messages"} {
		for _, compressed := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/plain", true: "/gzip"}[compressed], func(t *testing.T) {
				const limit = 1600
				received := make(chan []byte, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					mac := hmac.New(sha256.New, []byte("synthetic-key"))
					mac.Write([]byte(r.Header.Get(DefaultTimestampHeader) + "."))
					mac.Write(body)
					if r.Header.Get(DefaultHMACHeader) != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
						t.Error("signature not over delivered bytes")
					}
					if compressed {
						z, err := gzip.NewReader(bytes.NewReader(body))
						if err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return
						}
						body, err = io.ReadAll(z)
						if err != nil {
							t.Error(err)
						}
						_ = z.Close()
					}
					received <- body
				}))
				defer server.Close()
				httpSink, err := NewHTTPSink(HTTPConfig{
					URL: server.URL, BatchSize: 1, Gzip: compressed, HTTPClient: server.Client(),
					Auth: HTTPAuth{Mode: AuthHMAC, HMACKey: []byte("synthetic-key"), HMACHeader: DefaultHMACHeader, TimestampHeader: DefaultTimestampHeader},
				})
				if err != nil {
					t.Fatal(err)
				}
				var local bytes.Buffer
				opts := []EmitterOption{WithMaxRecordBytes(limit)}
				switch mode {
				case "full":
					opts = append(opts, WithFullContent())
				case "raw":
					opts = append(opts, WithRawContent())
				case "messages":
					opts = append(opts, WithRawContent(), WithMessageContentOnly())
				}
				em := NewWithSink(NewMultiSink(httpSink, nopCloseSink{&local}), io.Discard, "run", opts...)
				ev := model.Event{SchemaVersion: model.SchemaVersion, EventID: "e", EventType: model.EventToolResult}
				ev.SetToolInput(`{"query":"keep"}`)
				ev.SetToolResult(`"` + strings.Repeat("x", 4096) + `"`)
				original := ev.ToolResultForAnalysis()
				if err := em.EmitEvent(ev); err != nil {
					t.Fatal(err)
				}
				if err := em.Close(); err != nil {
					t.Fatal(err)
				}
				wire := <-received
				if !bytes.Equal(wire, local.Bytes()) || len(wire) > limit {
					t.Fatal("record was not bounded identically before fanout")
				}
				var got model.Event
				_ = json.Unmarshal(wire, &got)
				if mode == "full" || mode == "raw" {
					if !reflect.DeepEqual(got.ContentOmitted, []string{"tool_result"}) || got.ToolInput != ev.ToolInputForAnalysis() {
						t.Fatal("failed to retain small input and mark omitted result")
					}
				} else if len(got.ContentOmitted) != 0 {
					t.Fatal("marked a body omitted by content selection")
				}
				if ev.ToolResultForAnalysis() != original || len(ev.ContentOmitted) != 0 {
					t.Fatal("changed local analysis")
				}
			})
		}
	}
}

func TestRecordLimitMessageReplay(t *testing.T) {
	ev := model.Event{
		SchemaVersion: model.SchemaVersion, EventID: "e", EventType: model.EventPromptUser,
		SourceAgent: model.AgentClaudeCode, SourceType: model.SourceHook, Confidence: model.ConfidenceHigh,
		Evidence: model.Evidence{ArtifactType: "test"},
	}
	ev.SetContent(strings.Repeat("x", 5000), true)
	var records bytes.Buffer
	if err := New(&records, io.Discard, "run", WithRawContent(), WithMaxRecordBytes(1600)).EmitEvent(ev); err != nil {
		t.Fatal(err)
	}
	var replay model.Event
	_ = json.Unmarshal(records.Bytes(), &replay)
	for _, got := range []model.Event{replay, redact.Event(replay), redact.EventWithContent(replay), redact.EventWithRawContent(replay), redact.EventWithMessageContent(replay, true)} {
		if got.Content != "" || got.ContentBytes != ev.ContentBytesForAnalysis() ||
			got.ContentTruncated != ev.ContentTruncatedForAnalysis() ||
			!reflect.DeepEqual(got.ContentOmitted, []string{"content"}) {
			t.Fatal("lost message omission metadata")
		}
		if err := got.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecordLimitFailureAccounting(t *testing.T) {
	for _, limit := range []int{-1, 1} {
		var records, diagnostics bytes.Buffer
		em := New(&records, &diagnostics, "run", WithMaxRecordBytes(limit))
		for _, emit := range []func() error{
			func() error { return em.EmitEvent(model.Event{EventID: "e"}) },
			func() error { return em.EmitFinding(testFinding("f")) },
			func() error { return em.EmitEnforcement(testEnforcement()) },
			func() error { return em.EmitIndicator(Indicator{Type: IndicatorDomain, Value: "example.com"}) },
			func() error { return em.EmitSummary(ScanSummary{}) },
		} {
			if err := emit(); err == nil {
				t.Fatal("oversized or invalidly configured emission succeeded")
			}
		}
		if records.Len() != 0 || em.Stats().RecordErrors != 5 || em.Stats().EventsEmitted != 0 {
			t.Fatalf("bad failed-emission accounting: %+v", em.Stats())
		}
		em.Diag(DiagnosticError, "record emission failed")
		if diagnostics.Len() == 0 {
			t.Fatal("separate diagnostic channel was size-limited")
		}
		em = NewWithSinkAndDiagnostics(nopCloseSink{&records}, "run", WithMaxRecordBytes(limit))
		em.Diag(DiagnosticError, "record emission failed")
		if records.Len() != 0 || em.Stats().RecordErrors != 1 {
			t.Fatal("in-stream diagnostic bypassed the limit")
		}
	}
}

func FuzzRecordLimit(f *testing.F) {
	f.Add("hello", "world", 600)
	f.Add(strings.Repeat(`"`, 400), strings.Repeat("界", 600), 500)
	f.Fuzz(func(t *testing.T, input, result string, limit int) {
		if len(input)+len(result) > 1<<16 || limit < 0 {
			t.Skip()
		}
		ev := model.Event{SchemaVersion: model.SchemaVersion, EventID: "e", EventType: model.EventToolResult}
		ev.SetToolInput(input)
		ev.SetToolResult(result)
		var records bytes.Buffer
		em := New(&records, io.Discard, "run", WithRawContent(), WithMaxRecordBytes(limit))
		em.endpoint = Endpoint{}
		err := em.EmitEvent(ev)
		if err != nil {
			if records.Len() != 0 || em.Stats().RecordErrors != 1 {
				t.Fatal("failed emission reached sink")
			}
			return
		}
		if (limit > 0 && records.Len() > limit) || !json.Valid(records.Bytes()) {
			t.Fatal("invalid or oversized output")
		}
		var got model.Event
		_ = json.Unmarshal(records.Bytes(), &got)
		if got.ToolInputBytes != ev.ToolInputBytesForAnalysis() || got.ToolResultBytes != ev.ToolResultBytesForAnalysis() ||
			got.ToolInputTruncated || got.ToolResultTruncated {
			t.Fatal("changed capture metadata")
		}
	})
}

func BenchmarkEmitRecordLimit(b *testing.B) {
	ev := model.Event{SchemaVersion: model.SchemaVersion, EventType: model.EventToolResult}
	ev.SetToolResult(`"` + strings.Repeat("x", 1<<20) + `"`)
	for _, tc := range []struct {
		name  string
		limit int
	}{{"disabled", 0}, {"fitting", 2 << 20}, {"omitted", 2048}} {
		b.Run(tc.name, func(b *testing.B) {
			em := New(io.Discard, io.Discard, "run", WithRawContent(), WithMaxRecordBytes(tc.limit))
			b.ReportAllocs()
			for b.Loop() {
				if err := em.EmitEvent(ev); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

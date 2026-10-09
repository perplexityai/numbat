package output

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestLargeToolContentSurvivesHTTP(t *testing.T) {
	// Two retained bodies exceed the former 16 MiB sink buffer. Markup must
	// not expand sixfold through HTML escaping in an NDJSON-only transport.
	body := strings.Repeat("<", 9<<20) + "TAIL"
	ev := model.Event{SchemaVersion: model.SchemaVersion, EventID: "e", EventType: model.EventToolResult}
	ev.SetToolInput(body)
	ev.SetToolResult(body)
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run", WithRawContent())
	if err := em.EmitEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if len(b) >= 20<<20 {
			t.Fatal("avoidable HTML escaping inflated record")
		}
		var decoded model.Event
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ToolInput != ev.ToolInputForAnalysis() || decoded.ToolResult != ev.ToolResultForAnalysis() {
			t.Fatal("HTTP delivery lost content")
		}
	default:
		t.Fatal("no record delivered")
	}
}

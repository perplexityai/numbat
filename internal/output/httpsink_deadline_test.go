package output

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPSinkDeadlineDoesNotRenewAcrossFlushesAndClose(t *testing.T) {
	deadline := time.Now().Add(100 * time.Millisecond)
	calls := 0
	client := &http.Client{
		Timeout: time.Second,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if got, ok := r.Context().Deadline(); !ok || !got.Equal(deadline) {
				t.Errorf("request %d deadline=%v, want original %v", calls, got, deadline)
				return nil, context.DeadlineExceeded
			}
			if calls == 1 {
				return &http.Response{
					StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader("")),
				}, nil
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}),
	}
	sink, err := NewHTTPSink(HTTPConfig{
		URL: "https://example.invalid/ingest", BatchSize: 1, Deadline: deadline, HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := sink.Write([]byte("{}\n")); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := sink.Close(); err == nil {
		t.Fatal("expired delivery was reported as successful")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("Close renewed an expired delivery budget")
	}
	if stats := sink.Stats(); calls != 3 || stats.BatchesSucceeded != 1 ||
		stats.BatchesFailed != 2 || stats.RecordsSent != 1 || !stats.PendingFailure {
		t.Fatalf("calls=%d stats=%+v", calls, stats)
	}
}

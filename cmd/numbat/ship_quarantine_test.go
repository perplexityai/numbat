package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/perplexityai/numbat/internal/spool"
)

func TestSpoolUnrepresentableRecordDoesNotBlock(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	records := [][]byte{
		[]byte("{\"event_id\":\"before\"}\n"),
		[]byte("{\"event_id\":\"unsupported\"}\n"),
		[]byte("{\"event_id\":\"after\"}\n"),
	}
	for _, record := range records {
		if err := store.Put(record); err != nil {
			t.Fatal(err)
		}
	}
	var delivered bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if bytes.Contains(body, []byte("unsupported")) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		delivered.Write(body)
	}))
	defer server.Close()
	if err := drainSpoolAvailable(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(delivered.Bytes(), append(bytes.Clone(records[0]), records[2]...)) {
		t.Fatalf("delivered %q, want both surrounding records", delivered.Bytes())
	}
	summary, err := store.ExportOriginals(filepath.Join(t.TempDir(), "export"))
	if err != nil || summary.QuarantinedCount != 1 || summary.AckedThrough != nil ||
		summary.SettledThrough == nil || *summary.SettledThrough != 3 ||
		summary.Quarantined[0].Reason != "unrepresentable" {
		t.Fatalf("quarantine is not distinct from delivery: %+v, %v", summary, err)
	}
}

func TestSpoolQuarantineDoesNotHideDeliveryFailures(t *testing.T) {
	for _, code := range []int{400, 401, 403, 429, 500, 503, 0} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
			original := oversizedTestEvent(t)
			if err := store.Put(original); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					return
				}
				if code == 0 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				w.WriteHeader(code)
			}))
			defer server.Close()
			_, err := shipSpoolBatch(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard)
			if err == nil {
				t.Fatal("delivery failure was hidden")
			}
			pending, err := store.Peek(maxShipBatchBytes)
			if err != nil || len(pending.Records) != 1 || !bytes.Equal(pending.Records[0], original) {
				t.Fatalf("original changed after failure: %v", err)
			}
			status, err := store.Status()
			if err != nil || status.QuarantinedRecords != 0 || status.RetainedRecords != 0 {
				t.Fatalf("non-record-specific failure quarantined: %+v, %v", status, err)
			}
		})
	}
}

func TestSpoolCancellationDoesNotQuarantine(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	if err := store.Put(oversizedTestEvent(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()
	if _, err := shipSpoolBatch(ctx, store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard); err == nil {
		t.Fatal("cancellation was ignored")
	}
	status, err := store.Status()
	if err != nil || status.PendingRecords != 1 || status.QuarantinedRecords != 0 {
		t.Fatalf("canceled record disposition: %+v, %v", status, err)
	}
}

func TestSpoolRetentionFullQuarantinesBeforeBoundedSend(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	original := oversizedTestEvent(t)
	for i := 0; i < 256; i++ {
		if err := store.Put(original); err != nil {
			t.Fatal(err)
		}
		batch, err := store.Peek(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.AckRepresented(batch); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Put(original); err != nil {
		t.Fatal(err)
	}
	after := []byte("{\"event_id\":\"after\"}\n")
	if err := store.Put(after); err != nil {
		t.Fatal(err)
	}
	var boundedCalls, delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"transport"`)) {
			boundedCalls.Add(1)
		}
		if !bytes.Equal(body, after) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		delivered.Add(1)
	}))
	defer server.Close()
	if err := drainSpoolAvailable(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard); err != nil {
		t.Fatal(err)
	}
	status, err := store.Status()
	if err != nil || status.QuarantinedRecords != 1 || status.RetainedRecords != 256 ||
		status.PendingRecords != 0 || delivered.Load() != 1 || boundedCalls.Load() != 0 {
		t.Fatalf("retention-full disposition: %+v, %v, bounded=%d delivered=%d", status, err, boundedCalls.Load(), delivered.Load())
	}
	summary, err := store.ExportOriginals(filepath.Join(t.TempDir(), "export"))
	if err != nil || summary.Quarantined[0].Reason != "retention_full" {
		t.Fatalf("export: %+v, %v", summary, err)
	}
}

func TestSpoolStatusIsReadOnlyAndIndependentOfHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.spool")
	var stdout, stderr bytes.Buffer
	args := []string{"--spool-file", path, "--spool-status"}
	if code := runShip(args, &stdout, &stderr); code != 1 {
		t.Fatalf("missing spool status=%d", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("status created a spool: %v", err)
	}
	store := spool.New(path)
	if err := store.Put([]byte("{\"id\":1}\n")); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, quarantine := range []bool{false, true} {
		if quarantine {
			if err := store.Quarantine(batch, spool.QuarantineUnrepresentable); err != nil {
				t.Fatal(err)
			}
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		code := runShip(args, &stdout, &stderr)
		if code != map[bool]int{false: 0, true: 1}[quarantine] || stderr.Len() != 0 {
			t.Fatalf("status code=%d stderr=%s", code, &stderr)
		}
		var status spool.Status
		if err := json.Unmarshal(stdout.Bytes(), &status); err != nil || status.NeedsAttention != quarantine {
			t.Fatalf("status=%s err=%v", &stdout, err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("status modified source: %v", err)
		}
	}
	for _, extra := range [][]string{{"--http-url", "http://127.0.0.1:1"}, {"--export-originals", "unused"}, {"--poll", "1s"}} {
		stdout.Reset()
		if code := runShip(append(append([]string{}, args...), extra...), &stdout, io.Discard); code != 2 || stdout.Len() != 0 {
			t.Fatalf("accepted status delivery flags: %v", extra)
		}
	}
}

func TestSpoolQuarantineDiagnosticDoesNotContainRecord(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	const privateMarker = "PRIVATE_SYNTHETIC_CONTENT"
	if err := store.Put([]byte("{\"id\":\"" + privateMarker + "\"}\n")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()
	var stderr bytes.Buffer
	if err := drainSpoolAvailable(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), privateMarker) || !strings.Contains(stderr.String(), "not delivered") {
		t.Fatalf("unsafe or misleading quarantine diagnostic: %s", &stderr)
	}
}

func TestSpoolLocallyUnrepresentableRecordDoesNotReachHTTP(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	original := []byte("{\"unsupported\":\"" + strings.Repeat("x", maxShipRecordBytes) + "\"}\n")
	if err := store.Put(original); err != nil {
		t.Fatal(err)
	}
	after := []byte("{\"event_id\":\"after\"}\n")
	if err := store.Put(after); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, after) {
			t.Errorf("unexpected HTTP body, bytes=%d error=%v", len(body), err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		calls.Add(1)
	}))
	defer server.Close()
	if err := drainSpoolAvailable(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard); err != nil {
		t.Fatal(err)
	}
	status, err := store.Status()
	if err != nil || status.QuarantinedRecords != 1 || status.QuarantinedBytes != uint64(len(original)) ||
		status.PendingRecords != 0 || calls.Load() != 1 {
		t.Fatalf("local bound disposition: %+v, %v, HTTP calls=%d", status, err, calls.Load())
	}
}

func TestSpoolFullQuarantineKeepsNextRejectedRecordPending(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	record := []byte("{\"id\":\"rejected\"}\n")
	for i := 0; i < 256; i++ {
		if err := store.Put(record); err != nil {
			t.Fatal(err)
		}
		batch, err := store.Peek(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Quarantine(batch, spool.QuarantineHTTP413); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range [][]byte{record, []byte("{\"id\":\"after\"}\n")} {
		if err := store.Put(value); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()
	if err := drainSpoolAvailable(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard); err == nil {
		t.Fatal("exhausted quarantine reported delivery progress")
	}
	status, err := store.Status()
	if err != nil || status.QuarantinedRecords != 256 || status.PendingRecords != 2 {
		t.Fatalf("full quarantine lost pending records: %+v, %v", status, err)
	}
}

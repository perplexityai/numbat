package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/output"
)

const testShipDestination = "test-destination"

type flakySink struct {
	srv      *httptest.Server
	healthy  atomic.Bool
	attempts atomic.Int64
	mu       sync.Mutex
	accepted map[string]int
}

func newFlakySink() *flakySink {
	f := &flakySink{accepted: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.attempts.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !f.healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.mu.Lock()
		for _, id := range eventIDs(body) {
			f.accepted[id]++
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return f
}

func (f *flakySink) uniqueDelivered() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.accepted)
}

func eventIDs(ndjson []byte) []string {
	var out []string
	for _, line := range bytes.Split(ndjson, []byte{'\n'}) {
		var rec struct {
			EventID string `json:"event_id"`
		}
		if json.Unmarshal(line, &rec) == nil && rec.EventID != "" {
			out = append(out, rec.EventID)
		}
	}
	return out
}

func writeSpool(t *testing.T, path, prefix string, n int) int64 {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	defer f.Close()
	for i := 1; i <= n; i++ {
		line := fmt.Sprintf(`{"record_type":"event","event_id":"%s-%d"}`+"\n", prefix, i)
		if _, err := f.WriteString(line); err != nil {
			t.Fatalf("write input: %v", err)
		}
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat input: %v", err)
	}
	return info.Size()
}

func appendRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("append input: %v", err)
	}
}

func newSinkFactory(url string) shipSinkFactory {
	return func() (output.Sink, error) {
		return buildSink(sinkConfig{
			modes:         []string{outputModeHTTP},
			defaultMode:   outputModeHTTP,
			httpURL:       url,
			httpBatch:     maxShipBatchBytes + 1,
			httpMaxBuffer: shipHTTPBufferBytes,
			httpTimeout:   5 * time.Second,
			httpAuth:      output.AuthNone,
		}, io.Discard)
	}
}

func newTestShipCursor() shipCursor {
	return shipCursor{checkpoint: newShipCheckpoint(testShipDestination, "", 0, nil)}
}

func TestShipZeroLossAcrossOutage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := inputPath + ".ship-state"
	size := writeSpool(t, inputPath, "g1", 1000)

	sink := newFlakySink()
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor := newTestShipCursor()

	sink.healthy.Store(false)
	cursor, err := drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err == nil {
		t.Fatal("drain during outage returned no error")
	}
	if cursor.checkpoint.Offset != 0 || sink.uniqueDelivered() != 0 {
		t.Fatalf("outage advanced offset=%d or delivered=%d", cursor.checkpoint.Offset, sink.uniqueDelivered())
	}
	if got := sink.attempts.Load(); got != 1 {
		t.Fatalf("HTTP attempts during one failed pass = %d, want 1", got)
	}

	sink.healthy.Store(true)
	cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err != nil {
		t.Fatalf("drain after recovery: %v", err)
	}
	if cursor.checkpoint.Offset != size || sink.uniqueDelivered() != 1000 {
		t.Fatalf("recovery offset=%d/%d delivered=%d/1000", cursor.checkpoint.Offset, size, sink.uniqueDelivered())
	}

	before := sink.attempts.Load()
	cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err != nil || cursor.checkpoint.Offset != size || sink.attempts.Load() != before {
		t.Fatalf("caught-up drain changed state: offset=%d attempts=%d err=%v", cursor.checkpoint.Offset, sink.attempts.Load(), err)
	}
	restored, err := readShipCursor(statePath, testShipDestination)
	if err != nil || restored.checkpoint.Offset != size {
		t.Fatalf("restored offset=%d, want %d; err=%v", restored.checkpoint.Offset, size, err)
	}
}

func TestShipDetectsRotation(t *testing.T) {
	tests := []struct {
		name   string
		rotate func(t *testing.T, path string)
	}{
		{
			name: "truncate shorter",
			rotate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
				writeSpool(t, path, "new", 3)
			},
		},
		{
			name: "truncate and regrow larger",
			rotate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
				writeSpool(t, path, "new", 30)
			},
		},
		{
			name: "replace with larger file",
			rotate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Rename(path, path+".1"); err != nil {
					t.Fatal(err)
				}
				writeSpool(t, path, "new", 30)
			},
		},
		{
			name: "copytruncate with retained file",
			rotate: func(t *testing.T, path string) {
				t.Helper()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path+".1", data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
				writeSpool(t, path, "new", 30)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "records.ndjson")
			statePath := filepath.Join(dir, "records.ship-state")
			writeSpool(t, inputPath, "old", 10)

			sink := newFlakySink()
			sink.healthy.Store(true)
			defer sink.srv.Close()
			factory := newSinkFactory(sink.srv.URL)
			cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
			if err != nil {
				t.Fatalf("initial drain: %v", err)
			}

			tt.rotate(t, inputPath)
			newInfo, err := os.Stat(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
				if err != nil {
					t.Fatalf("drain after rotation pass %d: %v", i+1, err)
				}
			}
			if cursor.checkpoint.Offset != newInfo.Size() {
				t.Fatalf("offset after rotation=%d, want %d", cursor.checkpoint.Offset, newInfo.Size())
			}
			want := 13
			if strings.Contains(tt.name, "larger") || strings.Contains(tt.name, "copytruncate") {
				want = 40
			}
			if got := sink.uniqueDelivered(); got != want {
				t.Fatalf("unique delivered=%d, want %d", got, want)
			}
		})
	}
}

func TestShipDrainsRetainedRotationAfterOutage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	writeSpool(t, inputPath, "old", 100)

	sink := newFlakySink()
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor := newTestShipCursor()
	sink.healthy.Store(false)
	cursor, err := drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err == nil || cursor.checkpoint.Offset != 0 || cursor.checkpoint.FileID == "" {
		t.Fatalf("outage state offset=%d file_id=%q err=%v", cursor.checkpoint.Offset, cursor.checkpoint.FileID, err)
	}
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	newSize := writeSpool(t, inputPath, "new", 10)

	sink.healthy.Store(true)
	for i := 0; i < 2; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("recovery pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 110 {
		t.Fatalf("delivered=%d, want all 110 records across rotation", got)
	}
	if cursor.checkpoint.Offset != newSize {
		t.Fatalf("active offset=%d, want %d", cursor.checkpoint.Offset, newSize)
	}
}

func TestShipDrainsMultipleRetainedRotationsAfterOutage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := inputPath + ".ship-state"
	writeSpool(t, inputPath, "oldest", 100)

	sink := newFlakySink()
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor := newTestShipCursor()
	sink.healthy.Store(false)
	cursor, err := drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err == nil {
		t.Fatal("drain during outage returned no error")
	}

	if err := os.Rename(inputPath, inputPath+".2"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "middle", 10)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	activeSize := writeSpool(t, inputPath, "active", 5)

	sink.healthy.Store(true)
	for i := 0; i < 2; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("recovery pass %d: %v", i+1, err)
		}
	}
	cursor, err = readShipCursor(statePath, testShipDestination)
	if err != nil {
		t.Fatalf("restart state: %v", err)
	}
	for i := 2; i < 4; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("recovery pass %d after restart: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 115 {
		t.Fatalf("delivered=%d, want all 115 records across two rotations", got)
	}
	if cursor.checkpoint.Offset != activeSize || len(cursor.checkpoint.DrainedFileIDs) != 0 {
		t.Fatalf("active checkpoint offset=%d/%d drained=%v", cursor.checkpoint.Offset, activeSize, cursor.checkpoint.DrainedFileIDs)
	}
}

func TestShipDrainsRetainedCopytruncateAfterOutage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	writeSpool(t, inputPath, "old", 100)

	sink := newFlakySink()
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor := newTestShipCursor()
	sink.healthy.Store(false)
	cursor, err := drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err == nil || cursor.checkpoint.GuardBytes == 0 {
		t.Fatalf("outage did not persist pending fingerprint: guard=%d err=%v", cursor.checkpoint.GuardBytes, err)
	}
	old, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath+".1", old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(inputPath, 0); err != nil {
		t.Fatal(err)
	}
	newSize := writeSpool(t, inputPath, "new", 10)

	sink.healthy.Store(true)
	for i := 0; i < 2; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("recovery pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 110 {
		t.Fatalf("delivered=%d, want all 110 records across copytruncate", got)
	}
	if cursor.checkpoint.Offset != newSize {
		t.Fatalf("active offset=%d, want %d", cursor.checkpoint.Offset, newSize)
	}
}

func TestShipPrefersRotatedFileIdentityOverCopiedPrefix(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	writeSpool(t, inputPath, "old", 10)

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath+".0", prefix, 0o600); err != nil {
		t.Fatal(err)
	}
	// Make the copied prefix unambiguously older. Equal mtimes intentionally
	// favor replay because skipping an ambiguous segment could lose records.
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(inputPath+".0", oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "old-tail", 1)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "new", 1)

	for i := 0; i < 2; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("rotation pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 12 {
		t.Fatalf("delivered=%d, want copied prefix ignored and both tail records delivered", got)
	}
}

func TestShipOversizedBatchLineStillShips(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	const batchCap = 64
	big := fmt.Sprintf(`{"record_type":"event","event_id":"big","pad":"%s"}`, strings.Repeat("x", 200)) + "\n"
	small := `{"record_type":"event","event_id":"small"}` + "\n"
	appendRaw(t, inputPath, []byte(big+small))

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), batchCap, newSinkFactory(sink.srv.URL), io.Discard)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if cursor.checkpoint.Offset != int64(len(big+small)) || sink.uniqueDelivered() != 2 {
		t.Fatalf("offset=%d/%d delivered=%d/2", cursor.checkpoint.Offset, len(big+small), sink.uniqueDelivered())
	}
}

func TestShipBoundsOversizedRecord(t *testing.T) {
	line, err := readShipLine(bufio.NewReader(strings.NewReader("12345\n")), 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readShipLine error=%v, want size-limit error", err)
	}
	if len(line.bytes) != 0 || string(line.tail) != "12345\n" || line.consumed != 6 || !line.complete {
		t.Fatalf("oversized line=%+v", line)
	}

	partial, err := readShipLine(bufio.NewReader(strings.NewReader("12345")), 4)
	if !errors.Is(err, errShipRecordTooLarge) || partial.complete {
		t.Fatalf("partial oversized line=%+v err=%v", partial, err)
	}
}

func TestShipLeavesPartialTrailingLine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	complete := `{"record_type":"event","event_id":"c1"}` + "\n"
	partial := `{"record_type":"event","event_id":"c2"`
	appendRaw(t, inputPath, []byte(complete+partial))

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
	if err != nil || cursor.checkpoint.Offset != int64(len(complete)) || sink.uniqueDelivered() != 1 {
		t.Fatalf("partial drain offset=%d delivered=%d err=%v", cursor.checkpoint.Offset, sink.uniqueDelivered(), err)
	}

	appendRaw(t, inputPath, []byte("}\n"))
	cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	want := int64(len(complete) + len(partial) + len("}\n"))
	if err != nil || cursor.checkpoint.Offset != want || sink.uniqueDelivered() != 2 {
		t.Fatalf("completed drain offset=%d/%d delivered=%d err=%v", cursor.checkpoint.Offset, want, sink.uniqueDelivered(), err)
	}
}

func TestShipCheckpointFailsSafe(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]*string{
		"missing":  nil,
		"empty":    stringPtr(""),
		"garbage":  stringPtr("not-json"),
		"old":      stringPtr("42\n"),
		"negative": stringPtr(`{"version":1,"offset":-1,"destination_sha256":"test-destination"}`),
	}
	for name, content := range bad {
		path := filepath.Join(dir, name)
		if content != nil {
			if err := os.WriteFile(path, []byte(*content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cursor, err := readShipCursor(path, testShipDestination)
		if err != nil || cursor.checkpoint.Offset != 0 {
			t.Errorf("%s: offset=%d err=%v, want safe replay", name, cursor.checkpoint.Offset, err)
		}
		if name == "missing" && cursor.resetReason != "" {
			t.Errorf("%s: unexpected reset warning %q", name, cursor.resetReason)
		}
		if name != "missing" && cursor.resetReason == "" {
			t.Errorf("%s: missing reset warning", name)
		}
	}

	goodPath := filepath.Join(dir, "good")
	cp := newShipCheckpoint(testShipDestination, "file-1", 4, []byte("x\n"))
	if err := writeShipCheckpoint(goodPath, cp); err != nil {
		t.Fatal(err)
	}
	good, err := readShipCursor(goodPath, testShipDestination)
	if err != nil || good.checkpoint.Offset != 4 {
		t.Fatalf("good state offset=%d err=%v", good.checkpoint.Offset, err)
	}
	if good.resetReason != "" {
		t.Fatalf("good state reset warning = %q", good.resetReason)
	}
	changed, err := readShipCursor(goodPath, "new-destination")
	if err != nil || changed.checkpoint.Offset != 0 {
		t.Fatalf("changed destination offset=%d err=%v, want replay", changed.checkpoint.Offset, err)
	}
	if changed.resetReason == "" {
		t.Fatal("changed destination should explain replay")
	}
}

func stringPtr(s string) *string { return &s }

func TestShipRetriesStateWriteBeforeMoreDelivery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	size := writeSpool(t, inputPath, "state", 1)
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	f, err := openShipInput(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	fileID, err := shipFileIdentity(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	cursor := shipCursor{checkpoint: newPendingShipCheckpoint(testShipDestination, fileID, pending)}
	cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err == nil || !cursor.pending || cursor.checkpoint.Offset != size || sink.uniqueDelivered() != 1 {
		t.Fatalf("failed state write: offset=%d pending=%v delivered=%d err=%v", cursor.checkpoint.Offset, cursor.pending, sink.uniqueDelivered(), err)
	}
	before := sink.attempts.Load()
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
	if err != nil || cursor.pending || cursor.checkpoint.Offset != size {
		t.Fatalf("state recovery: offset=%d pending=%v err=%v", cursor.checkpoint.Offset, cursor.pending, err)
	}
	if sink.attempts.Load() != before {
		t.Fatal("state recovery re-delivered an already acknowledged batch")
	}
	restored, err := readShipCursor(statePath, testShipDestination)
	if err != nil || restored.checkpoint.Offset != size {
		t.Fatalf("restored offset=%d/%d err=%v", restored.checkpoint.Offset, size, err)
	}
}

func TestShipDrainHonorsCancelledContext(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	writeSpool(t, inputPath, "cancel", 10)
	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, newSinkFactory(sink.srv.URL), io.Discard)
	if err != nil || cursor.checkpoint.Offset != 0 || sink.uniqueDelivered() != 0 {
		t.Fatalf("cancelled drain offset=%d delivered=%d err=%v", cursor.checkpoint.Offset, sink.uniqueDelivered(), err)
	}
}

func TestShipDrainsImmediatelyOnStart(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	writeSpool(t, inputPath, "start", 5)
	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- runShipLoop(ctx, inputPath, statePath, testShipDestination, time.Hour, newSinkFactory(sink.srv.URL), io.Discard)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for sink.uniqueDelivered() != 5 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("delivered %d before first poll, want 5", sink.uniqueDelivered())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("runShipLoop returned %d", code)
	}
}

func TestShipRejectsInvalidCLI(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing input", []string{"--http-url", "https://example.com"}, "--input-file is required"},
		{"missing URL", []string{"--input-file", "records.ndjson"}, "--http-url is required"},
		{"zero poll", []string{"--input-file", "records.ndjson", "--http-url", "https://example.com", "--poll", "0"}, "--poll must be a positive"},
		{"same state", []string{"--input-file", "records.ndjson", "--state-file", "./records.ndjson", "--http-url", "https://example.com"}, "must differ from --input-file"},
		{"input is lock", []string{"--input-file", "records.ship-state.lock", "--state-file", "records.ship-state", "--http-url", "https://example.com"}, "must differ from --input-file"},
		{"zero timeout", []string{"--input-file", "records.ndjson", "--http-url", "https://example.com", "--http-timeout", "0"}, "--http-timeout must be a positive"},
		{"signature header without hmac", []string{"--input-file", "records.ndjson", "--http-url", "https://example.com", "--http-sig-header", "X-Sig"}, "--http-sig-header requires --http-auth hmac-sha256"},
		{"timestamp header without hmac", []string{"--input-file", "records.ndjson", "--http-url", "https://example.com", "--http-timestamp-header", "X-Time"}, "--http-timestamp-header requires --http-auth hmac-sha256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := runShip(tt.args, io.Discard, &stderr); code != 2 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr=%q, want %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestShipStateLockRejectsSecondProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ship-state.lock")
	first, err := acquireShipLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquireShipLock(path)
	if err == nil {
		_ = second.Close()
		t.Fatal("second lock unexpectedly succeeded")
	}
}

func TestShipRetryDelayBacksOffAndCaps(t *testing.T) {
	base := 2 * time.Second
	tests := []struct {
		failures int
		min      time.Duration
		max      time.Duration
	}{
		{1, 1800 * time.Millisecond, 2200 * time.Millisecond},
		{2, 3600 * time.Millisecond, 4400 * time.Millisecond},
		{10, 54 * time.Second, 66 * time.Second},
	}
	for _, tt := range tests {
		got := shipRetryDelay(base, tt.failures)
		if got < tt.min || got > tt.max {
			t.Errorf("failures=%d delay=%s, want %s..%s", tt.failures, got, tt.min, tt.max)
		}
	}
}

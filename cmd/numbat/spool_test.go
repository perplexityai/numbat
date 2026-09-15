package main

import (
	"bytes"
	"errors"
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

func TestSpoolSinkDoesNotMergeRecordAfterRejectedPartialWrite(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	sink := spoolSink{store: store}
	first := []byte("{\"n\":1}\n")
	partial := []byte("{\"n\":")
	second := []byte("{\"n\":2}\n")

	if n, err := sink.Write(first); n != len(first) || err != nil {
		t.Fatalf("write first record = (%d, %v), want (%d, nil)", n, err, len(first))
	}
	if n, err := sink.Write(partial); n != 0 || err == nil {
		t.Fatalf("write partial record = (%d, %v), want (0, error)", n, err)
	}
	if n, err := sink.Write(second); n != len(second) || err != nil {
		t.Fatalf("write second record = (%d, %v), want (%d, nil)", n, err, len(second))
	}
	assertQueuedRecords(t, store, first, second)
}

func TestHookSpoolRejectsStateDatabasePathBeforeWriting(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.db")
	payload := `{"session_id":"s1","cwd":"/p","tool_name":"Read","tool_input":{"file_path":"/p/file"}}`
	stdout, stderr, code := runCLIStdin(payload,
		"hook", "pre-tool", "--agent", "claude", "--emit", "events",
		"--state-db", statePath,
		"--output", "spool", "--spool-file", statePath,
	)
	if code != 0 || strings.TrimSpace(stdout) != "{}" {
		t.Fatalf("hook must fail open: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "--spool-file and --state-db must name different files") {
		t.Fatalf("stderr = %q, want state/spool collision error", stderr)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("colliding spool unexpectedly created %q (err=%v)", statePath, err)
	}
}

func TestShipSpoolBatchAcknowledgesOnlyDeliveredPrefix(t *testing.T) {
	store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
	first := []byte("{\"n\":1}\n")
	second := []byte("{\"n\":2}\n")
	third := []byte("{\"n\":3}\n")
	for _, record := range [][]byte{first, second} {
		if err := store.Put(record); err != nil {
			t.Fatalf("put record: %v", err)
		}
	}

	requests := make(chan []byte, 2)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		requests <- body
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if attempts.Add(1) == 1 {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		if err := store.Put(third); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	wantBody := append(bytes.Clone(first), second...)
	if sent, err := shipSpoolBatch(store, maxShipBatchBytes, newSinkFactory(server.URL)); !sent || err == nil {
		t.Fatalf("failed delivery = (%v, %v), want (true, error)", sent, err)
	}
	if got := <-requests; !bytes.Equal(got, wantBody) {
		t.Fatalf("failed request body = %q, want %q", got, wantBody)
	}
	assertQueuedRecords(t, store, first, second)

	if sent, err := shipSpoolBatch(store, maxShipBatchBytes, newSinkFactory(server.URL)); !sent || err != nil {
		t.Fatalf("successful delivery = (%v, %v), want (true, nil)", sent, err)
	}
	if got := <-requests; !bytes.Equal(got, wantBody) {
		t.Fatalf("successful request body = %q, want %q", got, wantBody)
	}
	assertQueuedRecords(t, store, third)
}

func TestSameShipPathFollowsFilesystemIdentity(t *testing.T) {
	root := os.Getenv("NUMBAT_CASE_SENSITIVE_TEST_DIR")
	if root == "" {
		root = t.TempDir()
	}
	dir, err := os.MkdirTemp(root, "numbat-path-case-")
	if err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	lower := filepath.Join(dir, "probe")
	upper := filepath.Join(dir, "Probe")
	if err := os.WriteFile(lower, []byte("lower"), 0o600); err != nil {
		t.Fatalf("write lower-case file: %v", err)
	}
	_, upperErr := os.Stat(upper)
	caseSensitive := os.IsNotExist(upperErr)
	if upperErr != nil && !caseSensitive {
		t.Fatalf("stat case-variant file: %v", upperErr)
	}
	lower = filepath.Join(dir, "records.db")
	upper = filepath.Join(dir, "Records.db")
	same, err := sameShipPath(lower, upper)
	if err != nil {
		t.Fatalf("compare paths: %v", err)
	}
	wantSame := !caseSensitive
	if same != wantSame {
		t.Fatalf("same path = %v, want %v on a case-sensitive=%v filesystem", same, wantSame, caseSensitive)
	}

	composedProbe := filepath.Join(dir, "\u00e9-probe")
	decomposedProbe := filepath.Join(dir, "e\u0301-probe")
	if err := os.WriteFile(composedProbe, []byte("probe"), 0o600); err != nil {
		t.Fatalf("write composed Unicode file: %v", err)
	}
	composedInfo, err := os.Stat(composedProbe)
	if err != nil {
		t.Fatalf("stat composed Unicode file: %v", err)
	}
	decomposedInfo, decomposedErr := os.Stat(decomposedProbe)
	if decomposedErr != nil && !os.IsNotExist(decomposedErr) {
		t.Fatalf("stat decomposed Unicode file: %v", decomposedErr)
	}
	if decomposedErr == nil && os.SameFile(composedInfo, decomposedInfo) {
		composed := filepath.Join(dir, "\u00e9.db")
		decomposed := filepath.Join(dir, "e\u0301.db")
		same, err := sameShipPath(composed, decomposed)
		if err != nil {
			t.Fatalf("compare normalization-equivalent paths: %v", err)
		}
		if !same {
			t.Fatal("normalization-equivalent paths compare as distinct")
		}
	}
}

func TestSameShipPathResolvesDanglingIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("real", filepath.Join(root, "alias")); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	aliasPath := filepath.Join(root, "alias", "records.db")
	targetPath := filepath.Join(root, "real", "records.db")
	same, err := sameShipPath(aliasPath, targetPath)
	if err != nil {
		t.Fatalf("compare paths through dangling symlink: %v", err)
	}
	if !same {
		t.Fatal("paths that converge through a dangling symlink compare as distinct")
	}
}

func assertQueuedRecords(t *testing.T, store spool.Store, want ...[]byte) {
	t.Helper()
	batch, err := store.Peek(maxShipBatchBytes)
	if err != nil {
		t.Fatalf("peek records: %v", err)
	}
	if len(batch.Records) != len(want) {
		t.Fatalf("queued records = %q, want %q", batch.Records, want)
	}
	for i := range want {
		if !bytes.Equal(batch.Records[i], want[i]) {
			t.Fatalf("queued record %d = %q, want %q", i, batch.Records[i], want[i])
		}
	}
}

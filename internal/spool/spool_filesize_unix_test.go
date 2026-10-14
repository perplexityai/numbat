//go:build unix

package spool_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/perplexityai/numbat/internal/spool"
)

const (
	spoolFileSizeHelper = "NUMBAT_SPOOL_FILESIZE_HELPER"
	spoolFileSizePath   = "NUMBAT_SPOOL_FILESIZE_PATH"
	spoolFileSizeLimit  = "NUMBAT_SPOOL_FILESIZE_LIMIT"
	recordBefore        = "{\"record_type\":\"event\",\"event_id\":\"before\"}\n"
	recordAfter         = "{\"record_type\":\"event\",\"event_id\":\"after\"}\n"
)

// TestPutAtFileSizeLimitDoesNotCommit exercises a transaction that cannot grow
// its backing file. The failed Put must not become visible, and the store must
// remain usable after the limit no longer applies.
//
// RLIMIT_FSIZE, set in a child process so the cap cannot disturb the test
// harness, makes file growth fail with EFBIG; it does not simulate ENOSPC. A
// multi-megabyte record forces bbolt to grow the database during commit.
func TestPutAtFileSizeLimitDoesNotCommit(t *testing.T) {
	if os.Getenv(spoolFileSizeHelper) == "1" {
		runFileSizeLimitedPutHelper()
		return
	}

	path := filepath.Join(t.TempDir(), "records.spool")
	store := spool.New(path)
	if err := store.Put([]byte(recordBefore)); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat spool: %v", err)
	}

	// Cap the child at the current database size so any growth during commit
	// fails, then attempt a record far larger than any bbolt pre-allocation.
	cmd := exec.Command(os.Args[0], "-test.run=^TestPutAtFileSizeLimitDoesNotCommit$")
	cmd.Env = append(os.Environ(),
		spoolFileSizeHelper+"=1",
		spoolFileSizePath+"="+path,
		spoolFileSizeLimit+"="+strconv.FormatInt(info.Size(), 10),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("child Put unexpectedly succeeded under a file-size cap: %s", out)
	}
	if !bytes.Contains(out, []byte("put-failed")) {
		t.Fatalf("child did not report a failed Put: %s", out)
	}

	// The failed Put is not visible: the queue still contains only the seed.
	assertSpoolRecords(t, store, recordBefore)

	// The parent process is not file-size-limited, so the queue can accept another
	// record and preserve FIFO order.
	if err := store.Put([]byte(recordAfter)); err != nil {
		t.Fatalf("Put after file-size limit: %v", err)
	}
	assertSpoolRecords(t, store, recordBefore, recordAfter)
}

func runFileSizeLimitedPutHelper() {
	// Exceeding RLIMIT_FSIZE raises SIGXFSZ, whose default action kills the
	// process; ignore it so the offending write returns EFBIG instead.
	signal.Ignore(syscall.SIGXFSZ)
	limit, err := strconv.ParseInt(os.Getenv(spoolFileSizeLimit), 10, 64)
	if err != nil {
		reportFileSizeHelper("bad-limit:", err)
	}
	rlimit := syscall.Rlimit{Cur: uint64(limit), Max: uint64(limit)}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rlimit); err != nil {
		reportFileSizeHelper("setrlimit-failed:", err)
	}
	record := make([]byte, 0, 4<<20)
	record = append(record, []byte("{\"record_type\":\"event\",\"event_id\":\"big\",\"payload\":\"")...)
	record = append(record, bytes.Repeat([]byte("a"), 4<<20)...)
	record = append(record, []byte("\"}\n")...)
	if err := spool.New(os.Getenv(spoolFileSizePath)).Put(record); err != nil {
		reportFileSizeHelper("put-failed:", err)
	}
	reportFileSizeHelper("put-succeeded", nil)
}

// reportFileSizeHelper writes one status line the parent test matches on, then
// exits: success on the "put-succeeded" marker, failure otherwise.
func reportFileSizeHelper(marker string, cause error) {
	if cause != nil {
		_, _ = fmt.Fprintln(os.Stdout, marker, cause)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, marker)
	os.Exit(0)
}

func assertSpoolRecords(t *testing.T, store spool.Store, want ...string) {
	t.Helper()
	batch, err := store.Peek(64 << 20)
	if err != nil {
		t.Fatalf("peek spool: %v", err)
	}
	if len(batch.Records) != len(want) {
		t.Fatalf("queued %d record(s), want %d: %q", len(batch.Records), len(want), batch.Records)
	}
	for i, record := range want {
		if !bytes.Equal(batch.Records[i], []byte(record)) {
			t.Fatalf("queued record %d = %q, want %q", i, batch.Records[i], record)
		}
	}
}

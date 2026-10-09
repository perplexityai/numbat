//go:build unix

package output

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
)

const (
	fileSinkDiskFullHelper = "NUMBAT_FILESINK_DISKFULL_HELPER"
	fileSinkDiskFullPath   = "NUMBAT_FILESINK_DISKFULL_PATH"
	fileSinkDiskFullLimit  = "NUMBAT_FILESINK_DISKFULL_LIMIT"
	fileSinkSeedRecord     = `{"record_type":"event","event_id":"seed"}` + "\n"
	fileSinkNextRecord     = `{"record_type":"event","event_id":"next"}` + "\n"
)

// TestFileSinkShortAppendRollsBack reproduces the failure that corrupted the
// legacy records file: an append that could not grow the file left a partial
// NDJSON line, and the next hook's record concatenated onto it. A short write
// must now roll back to the pre-write size so the file ends on a record boundary
// and the next record starts on its own line.
//
// RLIMIT_FSIZE, set a few bytes past the seed record in a child process (so the
// cap cannot disturb the test harness), forces the next append to write a
// fragment and then fail without a real full filesystem.
func TestFileSinkShortAppendRollsBack(t *testing.T) {
	if os.Getenv(fileSinkDiskFullHelper) == "1" {
		runFileSinkShortAppendHelper()
		return
	}

	path := filepath.Join(t.TempDir(), "records.ndjson")
	seed, err := NewFileSinkAppend(path)
	if err != nil {
		t.Fatalf("open seed sink: %v", err)
	}
	if _, err := seed.Write([]byte(fileSinkSeedRecord)); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed sink: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFileSinkShortAppendRollsBack$")
	cmd.Env = append(os.Environ(),
		fileSinkDiskFullHelper+"=1",
		fileSinkDiskFullPath+"="+path,
		fileSinkDiskFullLimit+"="+strconv.Itoa(len(fileSinkSeedRecord)+8),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("child append unexpectedly succeeded under a file-size cap: %s", out)
	}
	if !bytes.Contains(out, []byte("append-failed")) {
		t.Fatalf("child did not report a failed append: %s", out)
	}

	// The failed append kept none of its bytes: the file still holds exactly the
	// seed record with no trailing fragment.
	if b, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(b) != fileSinkSeedRecord {
		t.Fatalf("file after short append = %q, want the seed record only", b)
	}

	// The next record appends cleanly instead of gluing onto a partial line.
	next, err := NewFileSinkAppend(path)
	if err != nil {
		t.Fatalf("open next sink: %v", err)
	}
	if _, err := next.Write([]byte(fileSinkNextRecord)); err != nil {
		t.Fatalf("next write: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatalf("close next sink: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(b) != fileSinkSeedRecord+fileSinkNextRecord {
		t.Fatalf("file = %q, want the seed then next record", b)
	}
}

func runFileSinkShortAppendHelper() {
	// Exceeding RLIMIT_FSIZE raises SIGXFSZ, whose default action kills the
	// process; ignore it so the offending write returns a short count instead.
	signal.Ignore(syscall.SIGXFSZ)
	limit, err := strconv.ParseInt(os.Getenv(fileSinkDiskFullLimit), 10, 64)
	if err != nil {
		reportFileSinkHelper("bad-limit:", err)
	}
	rlimit := syscall.Rlimit{Cur: uint64(limit), Max: uint64(limit)}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rlimit); err != nil {
		reportFileSinkHelper("setrlimit-failed:", err)
	}
	sink, err := NewFileSinkAppend(os.Getenv(fileSinkDiskFullPath))
	if err != nil {
		reportFileSinkHelper("open-failed:", err)
	}
	record := append([]byte(`{"record_type":"event","event_id":"big","payload":"`), bytes.Repeat([]byte("a"), 1<<20)...)
	record = append(record, []byte("\"}\n")...)
	if _, err := sink.Write(record); err != nil {
		reportFileSinkHelper("append-failed:", err)
	}
	reportFileSinkHelper("append-succeeded", nil)
}

func reportFileSinkHelper(marker string, cause error) {
	if cause != nil {
		_, _ = fmt.Fprintln(os.Stdout, marker, cause)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, marker)
	os.Exit(0)
}

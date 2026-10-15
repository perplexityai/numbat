//go:build linux || darwin

package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFileSinkRollsBackShortWrite(t *testing.T) {
	for name, open := range map[string]func(string) (Sink, error){
		"append":   NewFileSinkAppend,
		"truncate": NewFileSink,
	} {
		t.Run(name, func(t *testing.T) { testFileSinkRollsBackShortWrite(t, open) })
	}
}

func testFileSinkRollsBackShortWrite(t *testing.T, open func(string) (Sink, error)) {
	if os.Getuid() == 0 {
		t.Skip("root is not subject to RLIMIT_FSIZE in every environment; skip")
	}
	var saved syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &saved); err != nil {
		t.Skip("getrlimit:", err)
	}
	path := filepath.Join(t.TempDir(), "records.ndjson")
	sink, err := open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	first := []byte(`{"event_id":"first"}` + "\n")
	if _, err := sink.Write(first); err != nil {
		t.Fatal(err)
	}
	second := []byte(`{"event_id":"second","pad":"` + strings.Repeat("x", 4000) + `"}` + "\n")
	limit := syscall.Rlimit{Cur: uint64(len(first) + 300), Max: saved.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Skip("setrlimit:", err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &saved); err != nil {
				t.Fatalf("restore RLIMIT_FSIZE: %v", err)
			}
		}
	}
	t.Cleanup(restore)

	n, err := sink.Write(second)
	restore()
	if err == nil {
		t.Fatalf("write under RLIMIT_FSIZE succeeded (n=%d); environment does not enforce the limit", n)
	}
	if !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("write under RLIMIT_FSIZE returned %v, want EFBIG", err)
	}
	if n <= 0 || n >= len(second) {
		t.Fatalf("write under RLIMIT_FSIZE returned n=%d, want a short write (0 < n < %d)", n, len(second))
	}

	fi, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if fi.Size() != int64(len(first)) {
		t.Fatalf("after failed write file size = %d, want pre-write size %d (partial record left behind)", fi.Size(), len(first))
	}

	third := []byte(`{"event_id":"third"}` + "\n")
	if _, err := sink.Write(third); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		t.Fatalf("NUL byte at offset %d after rollback (write offset not restored): %q", i, b)
	}
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), b)
	}
	var ids []string
	for _, l := range lines {
		var rec struct {
			ID string `json:"event_id"`
		}
		if err := json.Unmarshal(l, &rec); err != nil {
			t.Fatalf("line is not valid JSON after rollback: %v: %q", err, l)
		}
		ids = append(ids, rec.ID)
	}
	if got := strings.Join(ids, ","); got != "first,third" {
		t.Fatalf("event ids = %s, want first,third", got)
	}
}

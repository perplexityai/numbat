package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func outputModeMatches(got, want os.FileMode) bool {
	return runtime.GOOS == "windows" || got == want
}

func TestFileSinkWritesNDJSONWith0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	em := New(sink, io.Discard, "run1")
	for i := 0; i < 2; i++ {
		if err := em.EmitFinding(testFinding("f")); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); !outputModeMatches(perm, 0o600) {
		t.Fatalf("file perms = %o, want 600", perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(b)), "\n") + 1; n != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d", n)
	}
}

func TestFileSinkMissingParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "out.ndjson")
	if _, err := NewFileSink(path); err == nil {
		t.Fatal("expected error for missing parent directory")
	}
}

func TestFileSinkTightensPreexistingPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	// A planted world-readable file: O_CREATE's mode only applies to NEW files,
	// so without an explicit fchmod the loose 0644 would survive the open.
	if err := os.WriteFile(path, []byte("planted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); !outputModeMatches(perm, 0o600) {
		t.Fatalf("pre-existing file perms = %o, want 600", perm)
	}
}

func TestFileSinkRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.ndjson")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := NewFileSink(link); err == nil {
		t.Fatal("expected refusal to open symlink output path")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error should name the symlink refusal, got %v", err)
	}
	// The symlink target must be untouched: numbat must not have followed it.
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "secret\n" {
		t.Fatalf("symlink target was modified: %q", b)
	}
}

// NewFileSinkAppend must accumulate across opens (a hook fires a fresh process
// per agent event) and create a missing parent directory under numbat's state
// dir, while still landing at 0600.
func TestFileSinkAppendAccumulatesAndCreatesParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "findings.ndjson")
	for i := 0; i < 2; i++ {
		sink, err := NewFileSinkAppend(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		em := New(sink, io.Discard, "run")
		if err := em.EmitFinding(testFinding("f")); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(b)), "\n") + 1; n != 2 {
		t.Fatalf("append sink kept %d lines across two opens, want 2 (not truncated)", n)
	}
	if info, _ := os.Stat(path); !outputModeMatches(info.Mode().Perm(), 0o600) {
		t.Fatalf("append file perms = %o, want 600", info.Mode().Perm())
	}
}

func TestFileSinkAppendSerializesConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "findings.ndjson")
	const writers = 4
	const recordsPerWriter = 150
	payload := strings.Repeat("x", 1024)

	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			sink, err := NewFileSinkAppend(path)
			if err != nil {
				errs <- fmt.Errorf("writer %d open: %w", writer, err)
				return
			}
			defer sink.Close()
			for i := 0; i < recordsPerWriter; i++ {
				line := fmt.Sprintf(`{"writer":%d,"record":%d,"payload":%q}`+"\n", writer, i, payload)
				if _, err := sink.Write([]byte(line)); err != nil {
					errs <- fmt.Errorf("writer %d record %d: %w", writer, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != writers*recordsPerWriter {
		t.Fatalf("line count = %d, want %d", len(lines), writers*recordsPerWriter)
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is not valid JSON: %.120q", i, line)
		}
	}
}

func TestFileSinkTruncatesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	if err := os.WriteFile(path, []byte("stale content that must be gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("file not truncated: %q", b)
	}
}

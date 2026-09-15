//go:build windows

package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSinkAppendHandleCanRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	seed := []byte("seed\n")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileSinkAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	fileSink := sink.(*fileSink)
	if _, err := fileSink.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := fileSink.file.Truncate(int64(len(seed))); err != nil {
		t.Fatalf("roll back append: %v", err)
	}
	next := []byte("next\n")
	if _, err := fileSink.Write(next); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := append(seed, next...)
	if string(got) != string(want) {
		t.Fatalf("file after rollback = %q, want %q", got, want)
	}
}

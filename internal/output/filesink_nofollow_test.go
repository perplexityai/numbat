//go:build unix

package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSinkAppendRepairsWriteOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	const seed = "seed\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o200); err != nil {
		t.Fatal(err)
	}

	sink, err := NewFileSinkAppend(path)
	if err != nil {
		t.Fatalf("open write-only file: %v", err)
	}
	const next = "next\n"
	if _, err := sink.Write([]byte(next)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != fileSinkPerm {
		t.Fatalf("file perms = %o, want %o", got, fileSinkPerm)
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != seed+next {
		t.Fatalf("file = %q, want %q", got, seed+next)
	}
}

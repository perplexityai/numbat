//go:build windows

package winfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenOutputAppendsWithoutTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	for i, body := range []string{"one\n", "two\n"} {
		f, err := OpenOutput(path, i > 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(body); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "one\ntwo\n" {
		t.Fatalf("append output = %q", data)
	}
}

func TestOpenRegularRejectsReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if _, err := OpenRegular(link); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("OpenRegular symlink error = %v, want ErrReparsePoint", err)
	}
}

func TestOpenRegularRejectsDirectoryAsNonRegular(t *testing.T) {
	if _, err := OpenRegular(t.TempDir()); err == nil || err.Error() != "not a regular file" {
		t.Fatalf("OpenRegular directory error = %v, want not a regular file", err)
	}
}

func TestOpenOutputRejectsReparsePointWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if _, err := OpenOutput(link, false); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("OpenOutput symlink error = %v, want ErrReparsePoint", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("reparse target changed to %q", data)
	}
}

func TestReplaceAndRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "from")
	to := filepath.Join(dir, "to")
	if err := os.WriteFile(from, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(from, to); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(to); err != nil || string(data) != "new" {
		t.Fatalf("replaced target = %q, %v", data, err)
	}

	from = filepath.Join(dir, "second-from")
	if err := os.WriteFile(from, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RenameNoReplace(from, to); err == nil {
		t.Fatal("RenameNoReplace replaced an existing target")
	}
	if data, err := os.ReadFile(to); err != nil || string(data) != "new" {
		t.Fatalf("no-replace target changed to %q, %v", data, err)
	}
}

func TestExtendedPathSupportsDeepFiles(t *testing.T) {
	dir := t.TempDir()
	for len(dir) < 280 {
		dir = filepath.Join(dir, "0123456789abcdef")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "deep.jsonl")
	f, err := OpenOutput(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = OpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTruncateSameFileUnderLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	f, err := OpenOutput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("{\"a\":1}\n{\"b\":")); err != nil {
		t.Fatal(err)
	}
	if err := LockExclusive(f); err != nil {
		t.Fatal(err)
	}
	if err := TruncateSameFile(f, 8); err != nil {
		_ = Unlock(f)
		t.Fatalf("TruncateSameFile under lock: %v", err)
	}
	if err := Unlock(f); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("{\"c\":3}\n")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":1}\n{\"c\":3}\n"; string(got) != want {
		t.Fatalf("file = %q, want %q", got, want)
	}

	g, err := OpenOutput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	rotated := filepath.Join(t.TempDir(), "records.ndjson.1")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := TruncateSameFile(g, 0); !errors.Is(err, ErrFileReplaced) {
		t.Fatalf("TruncateSameFile on replaced path: err = %v, want ErrFileReplaced", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "other\n" {
		t.Fatalf("replacement file modified: %q", b)
	}
}

//go:build unix

package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvidencePathPrivacy(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	db, err := OpenEvidence(path, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode: %v %v", info, err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if db, err := OpenEvidence(link, time.Millisecond); err == nil {
		_ = db.Close()
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if db, err := OpenEvidence(path, time.Millisecond); err == nil {
		_ = db.Close()
		t.Fatal("readable content store accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if db, err := OpenEvidence(path, time.Millisecond); err == nil {
		_ = db.Close()
		t.Fatal("shared content directory accepted")
	}
}

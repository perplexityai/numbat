// Package state owns numbat's local bbolt database: it opens the one shared
// file (bolt's lock is exclusive, so a process holds exactly one handle).
// Sibling packages that persist records in the same file — currently the hook's
// sequence windows — take the underlying handle via Bolt and own only their
// bucket.
//
// The store is local-only. Sequence state is content-free; explicitly enabled
// decision evaluation also retains its bounded, approved inference projection.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DB wraps the shared bbolt handle.
type DB struct {
	bolt *bolt.DB
}

// Open opens or creates the state database at path with 0600 permissions,
// creating the parent directory if needed. timeout bounds the wait for bolt's
// exclusive file lock — a long-running command can afford a second; the live
// hook, which blocks the agent, passes a short one and fails open.
func Open(path string, timeout time.Duration) (*DB, error) {
	return open(path, timeout, false)
}

// OpenEvidence refuses shared-readable files and symlinks before retaining the
// explicitly enabled inference projection.
func OpenEvidence(path string, timeout time.Duration) (*DB, error) {
	return open(path, timeout, true)
}

func open(path string, timeout time.Duration, evidence bool) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("state: empty database path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	opts := &bolt.Options{Timeout: timeout}
	if evidence {
		info, err := os.Lstat(filepath.Dir(path))
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("state: evidence directory must be private")
		}
		opts.OpenFile = openEvidenceFile
	}
	b, err := bolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, fmt.Errorf("state: open %q: %w", path, err)
	}
	if info, statErr := os.Stat(path); statErr != nil {
		_ = b.Close()
		return nil, fmt.Errorf("state: stat %q: %w", path, statErr)
	} else if info.Mode().Perm() != 0o600 {
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			_ = b.Close()
			return nil, fmt.Errorf("state: chmod %q to 0600: %w", path, chmodErr)
		}
	}
	return &DB{bolt: b}, nil
}

// Bolt returns the underlying handle so a sibling package can manage its own
// bucket in the shared file. The DB retains ownership; only Close releases it.
func (db *DB) Bolt() *bolt.DB { return db.bolt }

// Close flushes and closes the database. It is idempotent and nil-safe: a
// closed or nil DB returns nil so callers can defer Close unconditionally.
func (db *DB) Close() error {
	if db == nil || db.bolt == nil {
		return nil
	}
	b := db.bolt
	db.bolt = nil
	return b.Close()
}

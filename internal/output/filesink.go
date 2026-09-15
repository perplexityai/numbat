package output

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// fileSinkPerm is the owner-only Unix mode for a records file. Windows protects
// the file through the parent directory's inherited ACL instead.
const fileSinkPerm = 0o600

// NewFileSink opens (creating or truncating) path as a private records file and
// returns it as a Sink. The parent directory must already exist; a missing
// directory is reported clearly rather than silently created, so a mistyped
// path does not scatter forensic output.
//
// The platform open refuses a symlink or reparse point at the final component,
// preventing redirection to another target. On Unix, Chmod on the opened file
// also tightens a pre-existing file to 0600 without a path-based race.
//
// Scope: this hardens only the final component. It does NOT harden ancestor
// directories — a symlinked or swapped PARENT could still redirect creation
// elsewhere, and the os.Stat(dir) check above follows symlinks and is inherently
// raceable. That is by design: --output-file is an operator-chosen path on the
// operator's own machine, so the operator owns the trust of the parent
// directory. numbat does not attempt openat2/dirfd ancestor resolution. Close
// closes the file.
func NewFileSink(path string) (Sink, error) {
	if dir := filepath.Dir(path); dir != "" {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("file sink: parent directory %q: %w", dir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("file sink: parent path %q is not a directory", dir)
		}
	}
	return openFileSink(path, false)
}

// NewFileSinkAppend opens path for append (creating it and its parent directory
// if needed) and returns it as a private records Sink. It is the durable
// destination the installed hook handler writes findings to: a hook fires as a
// fresh process on every agent event, so a truncating sink would keep only the
// last event's findings; appending accumulates them across the session into one
// file. The parent directory is created (unlike NewFileSink) because the default
// destination lives under numbat's own state dir, which need not exist yet.
func NewFileSinkAppend(path string) (Sink, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("file sink: create parent directory %q: %w", dir, err)
		}
	}
	return openFileSink(path, true)
}

// openFileSink performs the shared redirect-refusing open and Unix mode
// tightening for both constructors.
func openFileSink(path string, appendMode bool) (Sink, error) {
	f, err := openNoFollow(path, fileSinkPerm, appendMode)
	if err != nil {
		if isNoFollowErr(err) {
			return nil, fmt.Errorf("file sink: refusing symlink or reparse point %q", path)
		}
		return nil, fmt.Errorf("file sink: open %q: %w", path, err)
	}
	if err := f.Chmod(fileSinkPerm); err != nil {
		f.Close()
		return nil, fmt.Errorf("file sink: tighten perms on %q: %w", path, err)
	}
	return &fileSink{file: f, appendMode: appendMode}, nil
}

// fileSink serializes each write at the file descriptor so separate hook
// processes appending to the same records file cannot interleave NDJSON lines.
type fileSink struct {
	file       *os.File
	appendMode bool
}

func (s *fileSink) Write(p []byte) (int, error) {
	return writeFileLocked(s.file, p, s.appendMode)
}

func (s *fileSink) Close() error {
	return s.file.Close()
}

// appendRecordLocked writes one complete record to f while the caller holds the
// file lock. It keeps the file from ever ending mid-record so the next record
// cannot concatenate onto a partial line: a missing trailing newline left by an
// earlier short append is repaired first (append sinks only, which open for
// reading), and a short or failed write is rolled back to the pre-write size.
func appendRecordLocked(f *os.File, p []byte, repairNewline bool) (int, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := info.Size()
	if info.Mode().IsRegular() {
		if _, err := f.Seek(size, io.SeekStart); err != nil {
			return 0, err
		}
	}
	if repairNewline && size > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, size-1); err != nil {
			return 0, err
		}
		if last[0] != '\n' {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				_ = f.Truncate(size)
				return 0, err
			}
			size++
		}
	}
	n, err := f.Write(p)
	if err == nil && n == len(p) {
		return n, nil
	}
	if truncErr := f.Truncate(size); truncErr != nil {
		err = errors.Join(err, truncErr)
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

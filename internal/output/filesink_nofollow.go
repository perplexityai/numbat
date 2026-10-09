//go:build unix

package output

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollow opens path for create with O_NOFOLLOW so a symlink at the final
// path component is refused (the kernel returns ELOOP) rather than followed.
// This stops numbat being redirected to truncate/write an arbitrary target via a
// planted symlink at an attacker-influenced output path. When appendMode is
// false the file is truncated write-only (scan's fresh-file-per-run behavior);
// regular append files are reopened read-write to repair missing newlines.
// FIFOs stay write-only so a disconnected reader is reported as a write failure.
func openNoFollow(path string, perm os.FileMode, appendMode bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | syscall.O_NOFOLLOW
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil || !appendMode {
		return f, err
	}
	before, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return f, nil
	}
	// Keep the write-only descriptor open until the read-write descriptor is
	// verified, including when repairing an owner-write-only file's permissions.
	defer func() { _ = f.Close() }()
	if err := f.Chmod(perm); err != nil {
		return nil, err
	}
	readWrite, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, err
	}
	after, err := readWrite.Stat()
	if err != nil {
		_ = readWrite.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		_ = readWrite.Close()
		return nil, errors.New("file changed while tightening permissions")
	}
	return readWrite, nil
}

// isNoFollowErr reports whether err is the ELOOP that O_NOFOLLOW returns when
// the final path component is a symlink. Kept separate so the symlink-refusal
// message is precise rather than a raw ELOOP.
func isNoFollowErr(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

func writeFileLocked(f *os.File, p []byte, repairNewline bool) (int, error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}
	defer func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}()
	return appendRecordLocked(f, p, repairNewline)
}

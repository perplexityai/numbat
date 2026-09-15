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
// when true it is opened read-write for append (the hook handler accumulates
// findings across repeated per-event invocations into one durable file, and read
// access lets writeFileLocked repair a missing trailing newline).
func openNoFollow(path string, perm os.FileMode, appendMode bool) (*os.File, error) {
	flags := os.O_CREATE | syscall.O_NOFOLLOW
	if appendMode {
		flags |= os.O_RDWR | os.O_APPEND
	} else {
		flags |= os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, perm)
	if err == nil || !appendMode || !errors.Is(err, os.ErrPermission) {
		return f, err
	}

	// A pre-existing owner-write-only file can be tightened safely, but it
	// cannot be opened read-write until after that repair. Keep the write-only
	// descriptor open while reopening and verify that both refer to the same
	// file, so a path replacement cannot redirect the append.
	repair, repairErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, perm)
	if repairErr != nil {
		return nil, repairErr
	}
	defer func() { _ = repair.Close() }()
	before, repairErr := repair.Stat()
	if repairErr != nil {
		return nil, repairErr
	}
	if err := repair.Chmod(perm); err != nil {
		return nil, err
	}

	f, repairErr = os.OpenFile(path, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, perm)
	if repairErr != nil {
		return nil, repairErr
	}
	after, repairErr := f.Stat()
	if repairErr != nil {
		f.Close()
		return nil, repairErr
	}
	if !os.SameFile(before, after) {
		f.Close()
		return nil, errors.New("file changed while tightening permissions")
	}
	return f, nil
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

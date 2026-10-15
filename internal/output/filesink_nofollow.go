//go:build unix

package output

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollow opens path for create/write-only with O_NOFOLLOW so a symlink at
// the final path component is refused (the kernel returns ELOOP) rather than
// followed. This stops numbat being redirected to truncate/write an arbitrary
// target via a planted symlink at an attacker-influenced output path. When
// appendMode is false the file is truncated (scan's fresh-file-per-run
// behavior); when true it is opened for append (the hook handler accumulates
// findings across repeated per-event invocations into one durable file).
func openNoFollow(path string, perm os.FileMode, appendMode bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | syscall.O_NOFOLLOW
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	return os.OpenFile(path, flags, perm)
}

// isNoFollowErr reports whether err is the ELOOP that O_NOFOLLOW returns when
// the final path component is a symlink. Kept separate so the symlink-refusal
// message is precise rather than a raw ELOOP.
func isNoFollowErr(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

func writeFileLocked(f *os.File, p []byte) (int, error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}
	defer func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}()
	return writeWholeOrRollback(f, p)
}

func truncateForRollback(f *os.File, size int64) error {
	return f.Truncate(size)
}

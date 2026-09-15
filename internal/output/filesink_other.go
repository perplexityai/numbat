//go:build !unix && !windows

package output

import "os"

// openNoFollow falls back to a plain create open on platforms without
// O_NOFOLLOW. The symlink hardening is a no-op there; the fchmod tightening in
// NewFileSink still applies. appendMode selects append vs truncate, matching the
// unix build, and opens read-write for append so writeFileLocked can repair a
// missing trailing newline.
func openNoFollow(path string, perm os.FileMode, appendMode bool) (*os.File, error) {
	flags := os.O_CREATE
	if appendMode {
		flags |= os.O_RDWR | os.O_APPEND
	} else {
		flags |= os.O_WRONLY | os.O_TRUNC
	}
	return os.OpenFile(path, flags, perm)
}

// isNoFollowErr is always false where O_NOFOLLOW is unavailable.
func isNoFollowErr(error) bool { return false }

func writeFileLocked(f *os.File, p []byte, repairNewline bool) (int, error) {
	return appendRecordLocked(f, p, repairNewline)
}

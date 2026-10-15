//go:build windows

package output

import (
	"errors"
	"os"

	"github.com/perplexityai/numbat/internal/winfile"
)

func openNoFollow(path string, _ os.FileMode, appendMode bool) (*os.File, error) {
	return winfile.OpenOutput(path, appendMode)
}

func isNoFollowErr(err error) bool {
	return errors.Is(err, winfile.ErrReparsePoint)
}

func writeFileLocked(f *os.File, p []byte) (n int, err error) {
	if err := winfile.LockExclusive(f); err != nil {
		return 0, err
	}
	defer func() {
		err = errors.Join(err, winfile.Unlock(f))
	}()
	return writeWholeOrRollback(f, p)
}

// truncateForRollback shrinks f to size while the caller holds LockExclusive.
// The append handle deliberately lacks FILE_WRITE_DATA (so every write stays
// pinned to EOF) and shrinking a file (Ftruncate, which Go implements with
// SetFileInformationByHandle/FileEndOfFileInfo) needs it, so winfile truncates through a
// separate short-lived handle on the same file object. Cross-compiled and
// vetted only: the author ran neither this path nor the winfile unit test on
// a Windows host, so cross-handle truncation under LockExclusive is
// unverified. The temporary handle needs FILE_WRITE_DATA; if that is refused,
// the write error is returned and the partial tail stays (pre-fix behaviour).
func truncateForRollback(f *os.File, size int64) error {
	return winfile.TruncateSameFile(f, size)
}

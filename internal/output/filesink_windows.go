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

func truncateForRollback(f *os.File, size int64) error {
	return winfile.TruncateSameFile(f, size)
}

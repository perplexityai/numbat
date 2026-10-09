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

func writeFileLocked(f *os.File, p []byte, repairNewline bool) (n int, err error) {
	if err := winfile.LockExclusive(f); err != nil {
		return 0, err
	}
	defer func() {
		err = errors.Join(err, winfile.Unlock(f))
	}()
	return appendRecordLocked(f, p, repairNewline)
}

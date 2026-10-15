//go:build unix || windows

package output

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func writeWholeOrRollback(f *os.File, p []byte) (int, error) {
	fi, err := f.Stat()
	if err != nil {
		return f.Write(p)
	}
	before := fi.Size()
	n, err := f.Write(p)
	if err == nil && n == len(p) {
		return n, nil
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	if after, serr := f.Stat(); serr != nil || after.Size() <= before {
		return n, err
	}
	if terr := truncateForRollback(f, before); terr != nil {
		return n, errors.Join(err, fmt.Errorf("roll back partial write: %w", terr))
	}
	if _, serr := f.Seek(before, io.SeekStart); serr != nil {
		return n, errors.Join(err, fmt.Errorf("roll back partial write: %w", serr))
	}
	return n, err
}

//go:build unix

package state

import (
	"errors"
	"os"
	"syscall"
)

func openEvidenceFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, errors.New("state: evidence file must be private and regular")
	}
	return f, nil
}

func prepareEvidenceDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state: evidence directory must be private")
	}
	return nil
}

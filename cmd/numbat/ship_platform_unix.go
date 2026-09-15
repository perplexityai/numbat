//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

func openShipInput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("not a regular file")
	}
	return f, nil
}

func shipFileIdentity(f *os.File) (string, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x", uint64(stat.Dev), uint64(stat.Ino)), nil
}

func replaceShipState(from, to string) error { return os.Rename(from, to) }

type unixShipLock struct{ file *os.File }

func acquireShipLock(path string) (io.Closer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another ship process is using this source: %w", err)
	}
	return &unixShipLock{file: f}, nil
}

func (l *unixShipLock) Close() error {
	return errors.Join(syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN), l.file.Close())
}

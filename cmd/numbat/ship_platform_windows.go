//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/perplexityai/numbat/internal/winfile"
	"golang.org/x/sys/windows"
)

func openShipInput(path string) (*os.File, error) { return winfile.OpenRegular(path) }

func shipFileIdentity(f *os.File) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x:%x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func replaceShipState(from, to string) error { return winfile.Replace(from, to) }

type windowsShipLock struct{ file *os.File }

func acquireShipLock(path string) (io.Closer, error) {
	f, err := winfile.OpenOutput(path, true)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		^uint32(0),
		^uint32(0),
		&overlapped,
	); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another ship process is using this source: %w", err)
	}
	return &windowsShipLock{file: f}, nil
}

func (l *windowsShipLock) Close() error {
	var overlapped windows.Overlapped
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, ^uint32(0), ^uint32(0), &overlapped)
	return errors.Join(unlockErr, l.file.Close())
}

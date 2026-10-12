//go:build !unix && !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const shipFileIdentityFields = 0

func openShipInput(path string) (*os.File, error) {
	f, err := os.Open(path)
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

func shipFileIdentity(*os.File) (string, error) { return "", nil }

func replaceShipState(from, to string) error { return os.Rename(from, to) }

func acquireShipLock(string) (io.Closer, error) {
	return nil, errors.New("numbat ship is unsupported on this platform")
}

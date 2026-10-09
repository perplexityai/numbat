//go:build windows

// Package winfile provides the small set of Win32 file primitives numbat needs
// where os.OpenFile cannot express reparse-point refusal or whole-file locking.
package winfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// ErrReparsePoint reports that the final path component is a Windows reparse
// point. It covers symlinks, junctions, and other redirecting filesystem nodes.
var ErrReparsePoint = errors.New("reparse point not allowed")

// OpenRegular opens an existing regular file without following a reparse point
// at the final path component.
func OpenRegular(path string) (*os.File, error) {
	return open(path, windows.GENERIC_READ, windows.OPEN_EXISTING)
}

// OpenOutput opens a regular output file without following a reparse point at
// the final path component. appendMode selects append or truncate behavior.
func OpenOutput(path string, appendMode bool) (*os.File, error) {
	access := uint32(windows.GENERIC_WRITE)
	if appendMode {
		// FILE_WRITE_DATA permits rollback with os.File.Truncate. That right
		// disables FILE_APPEND_DATA's implicit EOF positioning, so this open and
		// the locked record writer explicitly seek to EOF.
		access = windows.GENERIC_READ | windows.FILE_APPEND_DATA | windows.FILE_WRITE_DATA | windows.SYNCHRONIZE
	}
	f, err := open(path, access, windows.OPEN_ALWAYS)
	if err != nil {
		return nil, err
	}
	if appendMode {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	if !appendMode {
		// Verify the opened handle before truncating. CREATE_ALWAYS could mutate
		// an existing reparse point before open had a chance to reject it.
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// OpenExistingReadWrite opens an existing regular file for bbolt. It refuses a
// reparse point at the final component.
func OpenExistingReadWrite(path string) (*os.File, error) {
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE | windows.SYNCHRONIZE)
	return open(path, access, windows.OPEN_EXISTING)
}

func open(path string, access, creation uint32) (*os.File, error) {
	winPath, err := extendedPath(path)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(winPath)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		name,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		creation,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, err
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, ErrReparsePoint
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("not a regular file")
	}
	return os.NewFile(uintptr(h), path), nil
}

// LockExclusive locks the full byte range used by numbat record files.
func LockExclusive(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		^uint32(0),
		^uint32(0),
		&overlapped,
	)
}

// Unlock releases a lock obtained by LockExclusive.
func Unlock(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		^uint32(0),
		^uint32(0),
		&overlapped,
	)
}

// Replace atomically moves from over to, flushing the move before returning.
func Replace(from, to string) error {
	return move(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// RenameNoReplace atomically moves from to and fails if to already exists.
func RenameNoReplace(from, to string) error {
	return move(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func move(from, to string, flags uint32) error {
	from, err := extendedPath(from)
	if err != nil {
		return err
	}
	to, err = extendedPath(to)
	if err != nil {
		return err
	}
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, flags)
}

func extendedPath(path string) (string, error) {
	full, err := windows.FullPath(path)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(full, `\\?\`) {
		return full, nil
	}
	if strings.HasPrefix(full, `\\.\`) {
		return "", fmt.Errorf("Windows device paths are not supported")
	}
	if strings.HasPrefix(full, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(full, `\\`), nil
	}
	return `\\?\` + full, nil
}

//go:build unix

package evaluator

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Parent directories must be controlled by the operator (or explicitly allowed
// local user). A trusted-owner sticky temporary directory is safe as an ancestor,
// but the file's immediate parent must not be shared-writable.
func readProtected(path string, maxBytes int, allowUser, secret bool) ([]byte, error) {
	if !absolutePath(path) {
		return nil, errors.New("protected path must be absolute and clean")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("protected directory %q unavailable: %w", dir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("protected directory %q must be a directory, not a symlink", dir)
		}
		if !trustedOwner(info, allowUser) {
			return nil, fmt.Errorf("protected directory %q must be root-owned or explicitly permitted current-user-owned", dir)
		}
		if info.Mode().Perm()&0o022 != 0 &&
			(dir == filepath.Dir(path) || info.Mode()&os.ModeSticky == 0) {
			return nil, fmt.Errorf("protected directory %q must not be group/other writable", dir)
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("protected file %q unavailable or a symlink: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("protected file %q metadata unavailable: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("protected file %q must be a regular file", path)
	}
	if !trustedOwner(info, allowUser) {
		return nil, fmt.Errorf("protected file %q must be root-owned or explicitly permitted current-user-owned", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("protected file %q must not be group/other writable", path)
	}
	if secret && info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("protected credential %q must not be accessible to other users", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil || len(data) > maxBytes {
		return nil, errors.New("protected file unreadable or oversized")
	}
	return data, nil
}

func trustedOwner(info os.FileInfo, allowUser bool) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && (s.Uid == 0 || (allowUser && s.Uid == uint32(os.Geteuid())))
}

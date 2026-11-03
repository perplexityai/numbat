//go:build windows

package evaluator

import (
	"errors"
	"io"

	"github.com/perplexityai/numbat/internal/winfile"
)

func readProtected(path string, maxBytes int, _ bool, secret bool) ([]byte, error) {
	if !absolutePath(path) {
		return nil, errors.New("protected path must be absolute and clean")
	}
	if err := winfile.CheckProtectedParents(path); err != nil {
		return nil, err
	}
	f, err := winfile.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := winfile.CheckProtected(f, secret); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil || len(data) > maxBytes {
		return nil, errors.New("protected file unreadable or oversized")
	}
	return data, nil
}

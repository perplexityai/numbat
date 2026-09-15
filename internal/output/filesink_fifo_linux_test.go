//go:build linux

package output

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFileSinksWriteFIFO(t *testing.T) {
	constructors := []struct {
		name string
		open func(string) (Sink, error)
	}{
		{name: "truncate", open: NewFileSink},
		{name: "append", open: NewFileSinkAppend},
	}

	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "records.fifo")
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}

			reader, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reader.Close() })
			if err := syscall.SetNonblock(int(reader.Fd()), false); err != nil {
				t.Fatal(err)
			}

			type readResult struct {
				data []byte
				err  error
			}

			sink, err := constructor.open(path)
			if err != nil {
				t.Fatal(err)
			}
			record := []byte("{\"record_type\":\"event\"}\n")
			n, writeErr := sink.Write(record)
			closeErr := sink.Close()

			readDone := make(chan readResult, 1)
			go func() {
				data, err := io.ReadAll(reader)
				readDone <- readResult{data: data, err: err}
			}()
			var result readResult
			select {
			case result = <-readDone:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out reading FIFO")
			}
			if err := reader.Close(); err != nil {
				t.Errorf("close reader: %v", err)
			}
			if writeErr != nil {
				t.Errorf("write: %v", writeErr)
			}
			if n != len(record) {
				t.Errorf("write count = %d, want %d", n, len(record))
			}
			if closeErr != nil {
				t.Errorf("close: %v", closeErr)
			}
			if result.err != nil {
				t.Errorf("read: %v", result.err)
			}
			if string(result.data) != string(record) {
				t.Errorf("FIFO data = %q, want %q", result.data, record)
			}
		})
	}
}

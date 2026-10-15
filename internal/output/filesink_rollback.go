//go:build unix

package output

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// writeWholeOrRollback writes p to f and, when the write fails or is short
// (ENOSPC, EDQUOT, EFBIG, ...), truncates the file back to its pre-write size
// so no partial record is left behind. Without this a hook that hit a full
// disk left a truncated NDJSON prefix at the tail; the next hook, once space
// returned, appended its record straight onto that prefix and both records
// became one unparseable line. The caller must hold the exclusive file lock;
// platforms without the lock (filesink_other.go) do not roll back, because a
// truncate there could remove a record another process appended in between.
// The original write error is returned (joined with the truncate error if the
// rollback itself fails) so the hook keeps its fail-open behavior.
func writeWholeOrRollback(f *os.File, p []byte) (int, error) {
	fi, err := f.Stat()
	if err != nil {
		// Cannot learn the pre-write size; keep the previous behavior rather
		// than drop the record.
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
	// Only shrink. The lock is advisory, so a writer that ignores it (a
	// copy+truncate log rotation, for example) can still shrink the file
	// between the size snapshot and this point. The check below keeps a
	// rollback from growing such a file; it cannot close the window between
	// the check and the truncate, so the rollback guarantee covers only
	// writers that take the lock. Numbat's own shipper does not truncate the
	// file, and no external rotation was observed on the devboxes.
	if after, serr := f.Stat(); serr != nil || after.Size() <= before {
		return n, err
	}
	if terr := truncateForRollback(f, before); terr != nil {
		return n, errors.Join(err, fmt.Errorf("roll back partial write: %w", terr))
	}
	// Truncate does not move the file offset. The append sink writes at EOF
	// regardless, but the truncating sink (scan) writes at the offset, which
	// would now sit past EOF and leave a zero-filled hole before the next record.
	if _, serr := f.Seek(before, io.SeekStart); serr != nil {
		return n, errors.Join(err, fmt.Errorf("roll back partial write: %w", serr))
	}
	return n, err
}

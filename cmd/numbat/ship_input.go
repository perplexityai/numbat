package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// resumeOldestUndrainedRotated anchors the cursor to the oldest retained
// segment after the checkpoint can no longer identify the next input.
func resumeOldestUndrainedRotated(inputPath string, cursor *shipCursor, stderr io.Writer) (bool, error) {
	nextID, err := nextRotatedShipFileID(inputPath, cursor.checkpoint.DrainedFileIDs, time.Time{})
	if err != nil {
		return false, err
	}
	if nextID == "" {
		return false, nil
	}
	drained := append([]string(nil), cursor.checkpoint.DrainedFileIDs...)
	cursor.checkpoint = newShipCheckpoint(cursor.checkpoint.DestinationSHA256, nextID, 0, nil)
	cursor.checkpoint.DrainedFileIDs = drained
	cursor.rotationEOFID = ""
	cursor.rotationEOFOffset = 0
	fmt.Fprintf(stderr, "ship: re-anchored to %s in the retained rotation backlog; records may be delivered again\n", nextID)
	return true, nil
}

func isShipRecordFile(f *os.File) (bool, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	line, err := readShipLine(bufio.NewReader(f), maxShipRecordBytes)
	if errors.Is(err, errShipRecordTooLarge) {
		return line.complete, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if !line.complete {
		return false, nil
	}
	var record struct {
		RecordType string `json:"record_type"`
	}
	if json.Unmarshal(line.bytes, &record) != nil || record.RecordType == "" {
		return false, nil
	}
	return true, nil
}

func appendShipFileID(ids []string, id string) []string {
	if id == "" || containsShipFileID(ids, id) {
		return append([]string(nil), ids...)
	}
	return append(append([]string(nil), ids...), id)
}

func containsShipFileID(ids []string, id string) bool {
	if id == "" {
		return false
	}
	for _, candidate := range ids {
		if shipDrainedFileIDMatches(candidate, id) {
			return true
		}
	}
	return false
}

func shipDrainedFileIDMatches(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	if left == right {
		return true
	}
	leftPortable, leftOK := portableShipFileIdentity(left, 2)
	rightPortable, rightOK := portableShipFileIdentity(right, 2)
	return leftOK && rightOK && leftPortable == rightPortable
}

func shipFileIdentityMatches(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	if left == right {
		return true
	}
	leftPortable, leftOK := portableShipFileIdentity(left, 0)
	rightPortable, rightOK := portableShipFileIdentity(right, 0)
	return leftOK && rightOK && leftPortable == rightPortable
}

func portableShipFileIdentity(id string, trailingFields int) (string, bool) {
	if shipFileIdentityFields == 0 {
		return "", false
	}
	parts := strings.Split(id, ":")
	if len(parts) != shipFileIdentityFields+trailingFields {
		return "", false
	}
	for _, field := range parts[:shipFileIdentityFields] {
		if field == "" {
			return "", false
		}
		if _, err := strconv.ParseUint(field, 16, 64); err != nil {
			return "", false
		}
	}
	if trailingFields == 2 {
		if _, err := strconv.ParseUint(parts[len(parts)-2], 16, 64); err != nil {
			return "", false
		}
		digest, err := hex.DecodeString(parts[len(parts)-1])
		if err != nil || len(digest) != sha256.Size {
			return "", false
		}
	}
	return strings.Join(parts[1:], ":"), true
}

// shipDrainedFileID combines the platform file identity with a bounded content
// fingerprint. File identities can be reused after deletion; size plus prefix
// and tail samples distinguish a new segment without hashing the whole file on
// every rotation scan.
func shipDrainedFileID(f *os.File) (string, error) {
	id, err := shipFileIdentity(f)
	if err != nil {
		return "", err
	}
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := info.Size()
	h := sha256.New()
	var sizeBytes [8]byte
	binary.BigEndian.PutUint64(sizeBytes[:], uint64(size))
	_, _ = h.Write(sizeBytes[:])

	prefixBytes := min(int64(shipGuardBytes), size)
	if err := hashShipFileRange(h, f, 0, prefixBytes); err != nil {
		return "", err
	}
	if size > prefixBytes {
		tailBytes := min(int64(shipGuardBytes), size)
		if err := hashShipFileRange(h, f, size-tailBytes, tailBytes); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s:%x:%s", id, uint64(size), hex.EncodeToString(h.Sum(nil))), nil
}

func hashShipFileRange(dst io.Writer, f *os.File, offset, size int64) error {
	if size == 0 {
		return nil
	}
	buf := make([]byte, int(size))
	if _, err := f.ReadAt(buf, offset); err != nil {
		return err
	}
	n, err := dst.Write(buf)
	if err == nil && n != len(buf) {
		return io.ErrShortWrite
	}
	return err
}

func shipCheckpointMatches(f *os.File, fileID string, checkpoint shipCheckpoint) (bool, error) {
	if checkpoint.FileID == "" && checkpoint.Offset == 0 {
		return true, nil
	}
	if checkpoint.FileID != "" && fileID != "" && checkpoint.FileID != fileID {
		if checkpoint.GuardBytes == 0 || !shipFileIdentityMatches(checkpoint.FileID, fileID) {
			return false, nil
		}
	}
	return shipCheckpointContentMatches(f, checkpoint)
}

func shipCheckpointContentMatches(f *os.File, checkpoint shipCheckpoint) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if checkpoint.Offset > info.Size() || checkpoint.GuardOffset+int64(checkpoint.GuardBytes) > info.Size() {
		return false, nil
	}
	if checkpoint.GuardBytes == 0 {
		return true, nil
	}
	guard := make([]byte, checkpoint.GuardBytes)
	if _, err := f.ReadAt(guard, checkpoint.GuardOffset); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}
	sum := sha256.Sum256(guard)
	return hex.EncodeToString(sum[:]) == checkpoint.GuardSHA256, nil
}

// shipLineRead is the outcome of reading one NDJSON record. bytes holds an
// in-limit record; tail retains the bounded checkpoint guard for an oversized
// record. consumed includes the terminating newline, and complete distinguishes
// a finished record from a line that may still be growing.
type shipLineRead struct {
	bytes    []byte
	tail     []byte
	consumed int64
	complete bool
}

func readShipLine(br *bufio.Reader, maxBytes int) (shipLineRead, error) {
	var out shipLineRead
	for {
		fragment, err := br.ReadSlice('\n')
		out.consumed += int64(len(fragment))
		if len(out.bytes)+len(fragment) > maxBytes {
			// Keep counting through the newline without retaining the full record.
			out.tail = appendShipTail(out.tail, out.bytes)
			out.tail = appendShipTail(out.tail, fragment)
			out.bytes = nil
			for errors.Is(err, bufio.ErrBufferFull) {
				fragment, err = br.ReadSlice('\n')
				out.consumed += int64(len(fragment))
				out.tail = appendShipTail(out.tail, fragment)
			}
			out.complete = err == nil
			return out, fmt.Errorf("NDJSON record exceeds %d-byte limit: %w", maxBytes, errShipRecordTooLarge)
		}
		out.bytes = append(out.bytes, fragment...)
		switch {
		case err == nil:
			out.complete = true
			return out, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return out, err
		}
	}
}

func appendShipTail(tail, p []byte) []byte {
	if len(p) >= shipGuardBytes {
		return append(tail[:0], p[len(p)-shipGuardBytes:]...)
	}
	if overflow := len(tail) + len(p) - shipGuardBytes; overflow > 0 {
		copy(tail, tail[overflow:])
		tail = tail[:len(tail)-overflow]
	}
	return append(tail, p...)
}

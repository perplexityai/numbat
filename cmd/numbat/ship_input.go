package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxShipDrainedFiles = 1024

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

func appendShipFileID(inputPath string, ids []string, id string) ([]string, error) {
	if id == "" || containsShipFileID(ids, id) {
		return append([]string(nil), ids...), nil
	}
	if len(ids) >= maxShipDrainedFiles {
		var err error
		ids, err = retainedShipFileIDs(inputPath, ids)
		if err != nil {
			return nil, err
		}
		if len(ids) >= maxShipDrainedFiles {
			return nil, fmt.Errorf("retained rotation cache exceeds %d files; archive drained segments before continuing", maxShipDrainedFiles)
		}
	}
	return append(append([]string(nil), ids...), id), nil
}

// Prune only identities whose retained files are gone. Evicting a still-live
// file could cycle through equal-timestamp rotations and starve active input.
func retainedShipFileIDs(inputPath string, ids []string) ([]string, error) {
	dir, base := filepath.Dir(inputPath), filepath.Base(inputPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var retained []string
	for _, entry := range entries {
		if entry.Name() == base || !strings.HasPrefix(entry.Name(), base) ||
			entry.IsDir() || entry.Type()&os.ModeSymlink != 0 ||
			(entry.Type() != 0 && !entry.Type().IsRegular()) {
			continue
		}
		file, err := openShipInput(filepath.Join(dir, entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		id, err := shipDrainedFileID(file)
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		if containsShipFileID(ids, id) && !containsShipFileID(retained, id) {
			retained = append(retained, id)
		}
	}
	return retained, nil
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
	sameFile := checkpoint.FileID != "" && checkpoint.FileID == fileID
	if !sameFile && (checkpoint.GuardBytes == 0 || checkpoint.PrefixSHA256 == "" || !shipFileIdentityMatches(checkpoint.FileID, fileID)) {
		return false, nil
	}
	volumeMatches := true
	if checkpoint.VolumeID != "" {
		volumeID, err := shipVolumeIdentity(f)
		if err != nil {
			return false, err
		}
		volumeMatches = volumeID == checkpoint.VolumeID
	}
	if checkpoint.PrefixSHA256 == "" {
		if !volumeMatches {
			return false, nil
		}
	} else if !sameFile || !volumeMatches || !checkpoint.verified {
		matches, err := shipPrefixMatches(f, checkpoint.Offset, checkpoint.PrefixSHA256)
		if err != nil || !matches {
			return matches, err
		}
	}
	return shipCheckpointContentMatches(f, checkpoint)
}

var shipPrefixSeed = sha256.Sum256([]byte("numbat ship prefix v1"))

func nextShipPrefixHash(previous string, size int64, digest [sha256.Size]byte) (string, error) {
	var block [2*sha256.Size + 8]byte
	if previous == "" {
		copy(block[:sha256.Size], shipPrefixSeed[:])
	} else {
		decoded, err := hex.DecodeString(previous)
		if err != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("invalid ship prefix hash")
		}
		copy(block[:sha256.Size], decoded)
	}
	binary.BigEndian.PutUint64(block[sha256.Size:], uint64(size))
	copy(block[sha256.Size+8:], digest[:])
	sum := sha256.Sum256(block[:])
	return hex.EncodeToString(sum[:]), nil
}

func appendShipPrefixHash(previous string, records []byte) (string, error) {
	for len(records) > 0 {
		end := bytes.IndexByte(records, '\n')
		if end < 0 {
			return "", fmt.Errorf("ship prefix record is incomplete")
		}
		line := records[:end+1]
		var err error
		previous, err = nextShipPrefixHash(previous, int64(len(line)), sha256.Sum256(line))
		if err != nil {
			return "", err
		}
		records = records[end+1:]
	}
	return previous, nil
}

func hashShipPrefix(f *os.File, offset int64) (string, error) {
	if offset == 0 {
		return "", nil
	}
	reader := bufio.NewReader(io.NewSectionReader(f, 0, offset))
	var prefix string
	var consumed int64
	for consumed < offset {
		h := sha256.New()
		var lineBytes int64
		for {
			fragment, err := reader.ReadSlice('\n')
			_, _ = h.Write(fragment)
			lineBytes += int64(len(fragment))
			if err == nil {
				break
			}
			if !errors.Is(err, bufio.ErrBufferFull) {
				if errors.Is(err, io.EOF) {
					return "", io.ErrUnexpectedEOF
				}
				return "", err
			}
		}
		if lineBytes > offset-consumed {
			return "", io.ErrUnexpectedEOF
		}
		var digest [sha256.Size]byte
		copy(digest[:], h.Sum(nil))
		var err error
		prefix, err = nextShipPrefixHash(prefix, lineBytes, digest)
		if err != nil {
			return "", err
		}
		consumed += lineBytes
	}
	return prefix, nil
}

func shipPrefixMatches(f *os.File, offset int64, expected string) (bool, error) {
	prefix, err := hashShipPrefix(f, offset)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil
	}
	return err == nil && prefix == expected, err
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
	digest   [sha256.Size]byte
	consumed int64
	complete bool
}

func readShipLine(br *bufio.Reader, maxBytes int) (shipLineRead, error) {
	var out shipLineRead
	for {
		fragment, err := br.ReadSlice('\n')
		out.consumed += int64(len(fragment))
		if len(out.bytes)+len(fragment) > maxBytes {
			h := sha256.New()
			_, _ = h.Write(out.bytes)
			_, _ = h.Write(fragment)
			// Keep counting through the newline without retaining the full record.
			out.tail = appendShipTail(out.tail, out.bytes)
			out.tail = appendShipTail(out.tail, fragment)
			out.bytes = nil
			for errors.Is(err, bufio.ErrBufferFull) {
				fragment, err = br.ReadSlice('\n')
				out.consumed += int64(len(fragment))
				_, _ = h.Write(fragment)
				out.tail = appendShipTail(out.tail, fragment)
			}
			copy(out.digest[:], h.Sum(nil))
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

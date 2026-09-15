package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/perplexityai/numbat/internal/output"
)

const (
	defaultShipPoll     = 2 * time.Second
	maxShipRetryDelay   = time.Minute
	maxShipBatchBytes   = 4 << 20
	maxShipRecordBytes  = 8 << 20
	shipHTTPBufferBytes = maxShipBatchBytes + maxShipRecordBytes
	shipStateVersion    = 1
	shipGuardBytes      = 4 << 10
)

// errShipRecordTooLarge is a sentinel (distinct from a fatal read error) for an
// NDJSON record larger than maxShipRecordBytes.
var errShipRecordTooLarge = errors.New("NDJSON record exceeds size limit")

type shipCheckpoint struct {
	Version           int      `json:"version"`
	Offset            int64    `json:"offset"`
	FileID            string   `json:"file_id,omitempty"`
	GuardOffset       int64    `json:"guard_offset,omitempty"`
	GuardBytes        int      `json:"guard_bytes,omitempty"`
	GuardSHA256       string   `json:"guard_sha256,omitempty"`
	DestinationSHA256 string   `json:"destination_sha256"`
	DrainedFileIDs    []string `json:"drained_file_ids,omitempty"`
}

// shipCursor retains an acknowledged offset in memory when persisting the
// checkpoint fails. The next pass retries the checkpoint before sending more.
type shipCursor struct {
	checkpoint        shipCheckpoint
	pending           bool
	resetReason       string
	rotationEOFID     string
	rotationEOFOffset int64
}

type shipRead struct {
	blob             []byte
	n                int64
	fileID           string
	drainedID        string
	activeFileID     string
	modTime          time.Time
	rotated          bool
	reset            bool
	skippedOversized bool
	guard            []byte
}

type shipSource struct {
	file         *os.File
	fileID       string
	activeFileID string
	rotated      bool
	reset        bool
}

type shipSinkFactory func() (output.Sink, error)

func runShip(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ship", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inputPath := fs.String("input-file", "", "append-only NDJSON file to ship (required)")
	statePath := fs.String("state-file", "", "delivery checkpoint (default <input-file>.ship-state)")
	poll := fs.Duration("poll", defaultShipPoll, "interval between input-file polls")
	httpURL := fs.String("http-url", "", "ingest URL (required)")
	httpTimeout := fs.Duration("http-timeout", 30*time.Second, "HTTP request timeout")
	httpAuth := fs.String("http-auth", output.AuthNone, "HTTP delivery auth: none|bearer|hmac-sha256")
	httpSigHeader := fs.String("http-sig-header", output.DefaultHMACHeader, "header carrying the hmac-sha256 signature")
	httpTSHeader := fs.String("http-timestamp-header", output.DefaultTimestampHeader, "header carrying the signed timestamp")
	httpAllowInsecure := fs.Bool("http-allow-insecure", false, "allow plain http to non-loopback hosts")
	httpGzip := fs.Bool("http-gzip", false, "gzip the HTTP POST body")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat ship --input-file PATH --http-url URL [--state-file PATH] [--poll DUR] [HTTP options]")
		fmt.Fprintln(stderr, "\nTails an append-only numbat NDJSON file to an HTTP endpoint with a durable")
		fmt.Fprintln(stderr, "checkpoint. Retained records up to 8 MiB are delivered at least once while the")
		fmt.Fprintln(stderr, "input and rotated files remain available. Receivers must tolerate duplicates.")
		fmt.Fprintln(stderr, "Records larger than 8 MiB remain in the input file but are skipped.")
		printHTTPAuthEnvHelp(stderr, false)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "ship: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	if strings.TrimSpace(*inputPath) == "" {
		fmt.Fprintln(stderr, "ship: --input-file is required")
		fs.Usage()
		return 2
	}
	if strings.TrimSpace(*httpURL) == "" {
		fmt.Fprintln(stderr, "ship: --http-url is required")
		fs.Usage()
		return 2
	}
	if *poll <= 0 {
		fmt.Fprintf(stderr, "ship: --poll must be a positive duration, got %s\n", *poll)
		fs.Usage()
		return 2
	}
	if *statePath == "" {
		*statePath = *inputPath + ".ship-state"
	}
	if sameShipPath(*inputPath, *statePath) || sameShipPath(*inputPath, *statePath+".lock") {
		fmt.Fprintln(stderr, "ship: --state-file and its lock must differ from --input-file")
		fs.Usage()
		return 2
	}
	var httpFlagsSet []string
	fs.Visit(func(f *flag.Flag) {
		if httpOnlyFlags[f.Name] {
			httpFlagsSet = append(httpFlagsSet, f.Name)
		}
	})

	// The input batch is already assembled, so let Close perform the only POST.
	// A line needs at least one byte, making this threshold unreachable here.
	factory := func() (output.Sink, error) {
		return buildSink(sinkConfig{
			modes:         []string{outputModeHTTP},
			defaultMode:   outputModeHTTP,
			httpURL:       *httpURL,
			httpBatch:     maxShipBatchBytes + 1,
			httpMaxBuffer: shipHTTPBufferBytes,
			httpTimeout:   *httpTimeout,
			httpAuth:      *httpAuth,
			httpSigHeader: *httpSigHeader,
			httpTSHeader:  *httpTSHeader,
			allowInsecure: *httpAllowInsecure,
			gzip:          *httpGzip,
			httpFlagsSet:  httpFlagsSet,
		}, stdout)
	}
	if s, err := factory(); err != nil {
		fmt.Fprintf(stderr, "ship: %v\n", err)
		fs.Usage()
		return 2
	} else {
		_ = s.Close()
	}

	if err := os.MkdirAll(filepath.Dir(*statePath), 0o700); err != nil {
		fmt.Fprintf(stderr, "ship: create state directory: %v\n", err)
		return 1
	}
	lock, err := acquireShipLock(*statePath + ".lock")
	if err != nil {
		fmt.Fprintf(stderr, "ship: acquire state lock: %v\n", err)
		return 1
	}
	defer lock.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stderr, "numbat ship: shipping %s to the configured HTTP endpoint (Ctrl-C to stop)\n", *inputPath)
	return runShipLoop(ctx, *inputPath, *statePath, shipDestinationID(*httpURL), *poll, factory, stderr)
}

func runShipLoop(ctx context.Context, inputPath, statePath, destination string, poll time.Duration, factory shipSinkFactory, stderr io.Writer) int {
	cursor, err := readShipCursor(statePath, destination)
	if err != nil {
		fmt.Fprintf(stderr, "ship: read state %s: %v\n", statePath, err)
		return 1
	}
	if cursor.resetReason != "" {
		fmt.Fprintf(stderr, "ship: %s; replaying retained records\n", cursor.resetReason)
		cursor.resetReason = ""
	}
	stalled := false
	failures := 0
	for {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, stderr)
		if ctx.Err() != nil {
			return 0
		}
		switch {
		case err != nil && !stalled:
			fmt.Fprintf(stderr, "ship: %v; delivery paused, retrying with backoff\n", err)
			stalled = true
		case err == nil && stalled:
			fmt.Fprintln(stderr, "ship: recovered; delivery resumed")
			stalled = false
		}
		delay := poll
		if err != nil {
			failures++
			delay = shipRetryDelay(poll, failures)
		} else {
			failures = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}

func shipRetryDelay(base time.Duration, failures int) time.Duration {
	capDelay := maxShipRetryDelay
	if base > capDelay {
		capDelay = base
	}
	delay := base
	for i := 1; i < failures && delay < capDelay; i++ {
		if delay > capDelay/2 {
			delay = capDelay
			break
		}
		delay *= 2
	}
	// Add +/-10% jitter so identically configured hosts do not retry together.
	spread := delay / 5
	if spread <= 0 || delay > time.Duration(1<<62) {
		return delay
	}
	return delay - spread/2 + time.Duration(rand.Int64N(int64(spread)+1))
}

func drainAvailable(ctx context.Context, inputPath, statePath string, cursor shipCursor, maxBytes int64, factory shipSinkFactory, stderr io.Writer) (shipCursor, error) {
	if cursor.pending {
		if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
			return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
		}
		cursor.pending = false
	}
	// A fresh or corrupt-then-empty checkpoint that ignores an on-disk rotated
	// backlog would silently jump past it; resume the oldest undrained segment.
	if cursor.checkpoint.FileID == "" && cursor.checkpoint.Offset == 0 && cursor.checkpoint.GuardBytes == 0 {
		resumed, err := resumeOldestUndrainedRotated(inputPath, &cursor, stderr)
		if err != nil {
			return cursor, fmt.Errorf("scan rotated backlog %s: %w", inputPath, err)
		}
		if resumed {
			cursor.pending = true
			if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
				return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
			}
			cursor.pending = false
		}
	}
	for {
		if ctx.Err() != nil {
			return cursor, nil
		}
		batch, err := readShipBatch(inputPath, cursor.checkpoint, maxBytes)
		if err != nil {
			if os.IsNotExist(err) {
				return cursor, nil
			}
			return cursor, fmt.Errorf("read input %s: %w", inputPath, err)
		}
		if batch.reset {
			resumed, err := resumeOldestUndrainedRotated(inputPath, &cursor, stderr)
			if err != nil {
				return cursor, fmt.Errorf("scan rotated backlog %s: %w", inputPath, err)
			}
			if !resumed {
				cursor.checkpoint = newShipCheckpoint(cursor.checkpoint.DestinationSHA256, batch.activeFileID, 0, nil)
				cursor.rotationEOFID = ""
				cursor.rotationEOFOffset = 0
			}
			cursor.pending = true
			if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
				return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
			}
			cursor.pending = false
			continue
		}
		if cursor.checkpoint.Offset == 0 && cursor.checkpoint.GuardBytes == 0 && len(batch.blob) > 0 && !batch.rotated {
			cursor.checkpoint = newPendingShipCheckpoint(cursor.checkpoint.DestinationSHA256, batch.fileID, batch.blob)
			cursor.pending = true
			if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
				return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
			}
			cursor.pending = false
		}
		if len(batch.blob) == 0 {
			if batch.n > 0 {
				// readShipBatch reports n>0 with an empty blob only when it
				// skipped an oversized record; the offset must still advance
				// past those bytes or the same record blocks the next read.
				if batch.skippedOversized {
					fmt.Fprintf(stderr, "ship: %s: record at offset %d exceeds %d-byte limit; skipped from HTTP delivery and retained in the input file\n", inputPath, cursor.checkpoint.Offset, maxShipRecordBytes)
				}
				drained := cursor.checkpoint.DrainedFileIDs
				cursor.checkpoint = newShipCheckpoint(
					cursor.checkpoint.DestinationSHA256,
					batch.fileID,
					cursor.checkpoint.Offset+batch.n,
					batch.guard,
				)
				cursor.checkpoint.DrainedFileIDs = append([]string(nil), drained...)
				cursor.pending = true
				if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
					return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
				}
				cursor.pending = false
				continue
			}
			if batch.rotated {
				if cursor.rotationEOFID == batch.fileID && cursor.rotationEOFOffset == cursor.checkpoint.Offset {
					drained := appendShipFileID(cursor.checkpoint.DrainedFileIDs, batch.drainedID)
					nextID, err := nextRotatedShipFileID(inputPath, drained, batch.modTime)
					if err != nil {
						return cursor, fmt.Errorf("find next rotated input %s: %w", inputPath, err)
					}
					if nextID == "" {
						cursor.checkpoint = newShipCheckpoint(cursor.checkpoint.DestinationSHA256, batch.activeFileID, 0, nil)
					} else {
						cursor.checkpoint = newShipCheckpoint(cursor.checkpoint.DestinationSHA256, nextID, 0, nil)
						cursor.checkpoint.DrainedFileIDs = drained
					}
					cursor.pending = true
					cursor.rotationEOFID = ""
					cursor.rotationEOFOffset = 0
					if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
						return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
					}
					cursor.pending = false
					continue
				}
				cursor.rotationEOFID = batch.fileID
				cursor.rotationEOFOffset = cursor.checkpoint.Offset
			}
			return cursor, nil
		}
		cursor.rotationEOFID = ""
		cursor.rotationEOFOffset = 0
		if err := shipBatch(factory, batch.blob); err != nil {
			return cursor, err
		}
		drained := cursor.checkpoint.DrainedFileIDs
		cursor.checkpoint = newShipCheckpoint(
			cursor.checkpoint.DestinationSHA256,
			batch.fileID,
			cursor.checkpoint.Offset+batch.n,
			batch.blob,
		)
		cursor.checkpoint.DrainedFileIDs = append([]string(nil), drained...)
		cursor.pending = true
		if err := writeShipCheckpoint(statePath, cursor.checkpoint); err != nil {
			return cursor, fmt.Errorf("persist state %s: %w", statePath, err)
		}
		cursor.pending = false
	}
}

// readShipBatch returns complete NDJSON lines after the checkpoint. File
// identity and a hash of the delivered tail detect rotation even when a new or
// truncated file has already grown beyond the old offset.
func readShipBatch(path string, checkpoint shipCheckpoint, maxBytes int64) (shipRead, error) {
	if maxBytes <= 0 {
		return shipRead{}, fmt.Errorf("batch size must be positive")
	}
	source, err := openShipSource(path, checkpoint)
	if err != nil {
		return shipRead{}, err
	}
	defer source.file.Close()
	if source.reset {
		return shipRead{activeFileID: source.activeFileID, reset: true}, nil
	}
	info, err := source.file.Stat()
	if err != nil {
		return shipRead{}, err
	}
	if _, err := source.file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return shipRead{}, err
	}

	br := bufio.NewReader(source.file)
	var buf bytes.Buffer
	var consumed int64
	var skipped bool
	var skippedGuard []byte
	for buf.Len() == 0 || int64(buf.Len()) < maxBytes {
		line, readErr := readShipLine(br, maxShipRecordBytes)
		if errors.Is(readErr, errShipRecordTooLarge) {
			// A batch with delivered bytes must stay contiguous for its guard
			// fingerprint, and a record without a terminating newline may still
			// be growing, so in both cases stop and skip on a later empty batch.
			if buf.Len() > 0 || !line.complete {
				break
			}
			consumed += line.consumed
			skipped = true
			skippedGuard = line.tail
			break
		}
		if line.complete {
			_, _ = buf.Write(line.bytes)
			consumed += line.consumed
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return shipRead{}, readErr
		}
	}
	// This gate must stay in sync with the only reader of drainedID: the
	// rotated-EOF advance in drainAvailable (rotated segment, empty blob, no
	// bytes consumed). Widening it here recomputes the fingerprint needlessly.
	var drainedID string
	if source.rotated && consumed == 0 && buf.Len() == 0 {
		drainedID, err = shipDrainedFileID(source.file)
		if err != nil {
			return shipRead{}, err
		}
	}
	return shipRead{
		blob:             buf.Bytes(),
		n:                consumed,
		fileID:           source.fileID,
		drainedID:        drainedID,
		activeFileID:     source.activeFileID,
		modTime:          info.ModTime(),
		rotated:          source.rotated,
		skippedOversized: skipped,
		guard:            skippedGuard,
	}, nil
}

func openShipSource(path string, checkpoint shipCheckpoint) (shipSource, error) {
	active, err := openShipInput(path)
	if err != nil {
		return shipSource{}, err
	}
	activeID, err := shipFileIdentity(active)
	if err != nil {
		_ = active.Close()
		return shipSource{}, err
	}
	matches, err := shipCheckpointMatches(active, activeID, checkpoint)
	if err != nil {
		_ = active.Close()
		return shipSource{}, err
	}
	if matches {
		return shipSource{file: active, fileID: activeID, activeFileID: activeID}, nil
	}

	rotated, rotatedID, err := findRotatedShipInput(path, checkpoint)
	if err != nil {
		_ = active.Close()
		return shipSource{}, err
	}
	if rotated != nil {
		_ = active.Close()
		return shipSource{
			file:         rotated,
			fileID:       rotatedID,
			activeFileID: activeID,
			rotated:      true,
		}, nil
	}
	return shipSource{file: active, activeFileID: activeID, reset: true}, nil
}

func findRotatedShipInput(activePath string, checkpoint shipCheckpoint) (*os.File, string, error) {
	dir := filepath.Dir(activePath)
	base := filepath.Base(activePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", err
	}
	var candidateErr error
	for _, entry := range entries {
		entryType := entry.Type()
		if entry.IsDir() || entryType&os.ModeSymlink != 0 ||
			(entryType != 0 && !entryType.IsRegular()) ||
			entry.Name() == base || !strings.HasPrefix(entry.Name(), base) {
			continue
		}
		candidatePath := filepath.Join(dir, entry.Name())
		candidate, err := openShipInput(candidatePath)
		if err != nil {
			candidateErr = errors.Join(candidateErr, fmt.Errorf("inspect rotated candidate %s: %w", candidatePath, err))
			continue
		}
		candidateID, err := shipFileIdentity(candidate)
		if err != nil {
			_ = candidate.Close()
			candidateErr = errors.Join(candidateErr, fmt.Errorf("identify rotated candidate %s: %w", candidatePath, err))
			continue
		}
		candidateDrainedID, err := shipDrainedFileID(candidate)
		if err != nil {
			_ = candidate.Close()
			candidateErr = errors.Join(candidateErr, fmt.Errorf("identify rotated candidate %s: %w", candidatePath, err))
			continue
		}
		if containsShipFileID(checkpoint.DrainedFileIDs, candidateDrainedID) {
			_ = candidate.Close()
			continue
		}
		matches, err := shipCheckpointMatches(candidate, candidateID, checkpoint)
		if err != nil {
			_ = candidate.Close()
			candidateErr = errors.Join(candidateErr, fmt.Errorf("inspect rotated candidate %s: %w", candidatePath, err))
			continue
		}
		if matches && checkpoint.FileID != "" && candidateID != "" {
			return candidate, candidateID, nil
		}
		_ = candidate.Close()
	}
	return nil, "", candidateErr
}

type rotatedShipCandidate struct {
	name    string
	fileID  string
	modTime time.Time
}

// nextRotatedShipFileID returns the oldest retained numbat record file that has
// not already been drained. This keeps a long outage spanning several rotations
// from jumping directly from the oldest retained file to the active file.
func nextRotatedShipFileID(activePath string, drained []string, currentModTime time.Time) (string, error) {
	dir := filepath.Dir(activePath)
	base := filepath.Base(activePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var candidates []rotatedShipCandidate
	var candidateErr error
	for _, entry := range entries {
		entryType := entry.Type()
		if entry.IsDir() || entryType&os.ModeSymlink != 0 ||
			(entryType != 0 && !entryType.IsRegular()) ||
			entry.Name() == base || !strings.HasPrefix(entry.Name(), base) {
			continue
		}
		candidatePath := filepath.Join(dir, entry.Name())
		candidate, err := openShipInput(candidatePath)
		if err != nil {
			candidateErr = errors.Join(candidateErr, fmt.Errorf("inspect rotated candidate %s: %w", candidatePath, err))
			continue
		}
		candidateID, err := shipFileIdentity(candidate)
		if err != nil {
			_ = candidate.Close()
			candidateErr = errors.Join(candidateErr, fmt.Errorf("identify rotated candidate %s: %w", candidatePath, err))
			continue
		}
		candidateDrainedID, err := shipDrainedFileID(candidate)
		if err != nil {
			_ = candidate.Close()
			candidateErr = errors.Join(candidateErr, fmt.Errorf("identify rotated candidate %s: %w", candidatePath, err))
			continue
		}
		if containsShipFileID(drained, candidateDrainedID) {
			_ = candidate.Close()
			continue
		}
		valid, err := isShipRecordFile(candidate)
		info, statErr := candidate.Stat()
		_ = candidate.Close()
		if err != nil || statErr != nil {
			candidateErr = errors.Join(candidateErr, fmt.Errorf("inspect rotated candidate %s: %w", candidatePath, errors.Join(err, statErr)))
			continue
		}
		// A retained file older than the segment just drained is a backup or
		// duplicate, not the next rotation. Equal timestamps remain eligible so
		// coarse filesystems favor replay over skipping a segment.
		if valid && !info.ModTime().Before(currentModTime) {
			candidates = append(candidates, rotatedShipCandidate{name: entry.Name(), fileID: candidateID, modTime: info.ModTime()})
		}
	}
	if len(candidates) == 0 {
		return "", candidateErr
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].modTime.Before(candidates[j].modTime)
	})
	return candidates[0].fileID, nil
}

func shipBatch(factory shipSinkFactory, blob []byte) error {
	sink, err := factory()
	if err != nil {
		return fmt.Errorf("build sink: %w", err)
	}
	if _, err := sink.Write(blob); err != nil {
		_ = sink.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := sink.Close(); err != nil {
		return fmt.Errorf("deliver: %w", err)
	}
	return nil
}

func newShipCheckpoint(destination, fileID string, offset int64, delivered []byte) shipCheckpoint {
	cp := shipCheckpoint{
		Version:           shipStateVersion,
		Offset:            offset,
		FileID:            fileID,
		DestinationSHA256: destination,
	}
	if offset == 0 || len(delivered) == 0 {
		return cp
	}
	guard := delivered
	if len(guard) > shipGuardBytes {
		guard = guard[len(guard)-shipGuardBytes:]
	}
	sum := sha256.Sum256(guard)
	cp.GuardOffset = offset - int64(len(guard))
	cp.GuardBytes = len(guard)
	cp.GuardSHA256 = hex.EncodeToString(sum[:])
	return cp
}

func newPendingShipCheckpoint(destination, fileID string, pending []byte) shipCheckpoint {
	cp := newShipCheckpoint(destination, fileID, 0, nil)
	if len(pending) == 0 {
		return cp
	}
	sum := sha256.Sum256(pending)
	cp.GuardBytes = len(pending)
	cp.GuardSHA256 = hex.EncodeToString(sum[:])
	return cp
}

func readShipCursor(path, destination string) (shipCursor, error) {
	empty := shipCursor{checkpoint: newShipCheckpoint(destination, "", 0, nil)}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return empty, nil
		}
		return shipCursor{}, err
	}
	var cp shipCheckpoint
	if json.Unmarshal(b, &cp) != nil || !validShipCheckpoint(cp, destination) {
		empty.resetReason = fmt.Sprintf("state %s is invalid, incompatible, or belongs to another destination", path)
		return empty, nil
	}
	return shipCursor{checkpoint: cp}, nil
}

func validShipCheckpoint(cp shipCheckpoint, destination string) bool {
	if cp.Version != shipStateVersion || cp.Offset < 0 || cp.DestinationSHA256 != destination {
		return false
	}
	if len(cp.DrainedFileIDs) > 1024 {
		return false
	}
	seenFileIDs := make(map[string]struct{}, len(cp.DrainedFileIDs))
	for _, id := range cp.DrainedFileIDs {
		if id == "" || id == cp.FileID {
			return false
		}
		if _, ok := seenFileIDs[id]; ok {
			return false
		}
		seenFileIDs[id] = struct{}{}
	}
	if cp.GuardBytes == 0 {
		return cp.GuardOffset == 0 && cp.GuardSHA256 == ""
	}
	if cp.GuardOffset < 0 || cp.GuardBytes < 0 || cp.GuardBytes > shipHTTPBufferBytes {
		return false
	}
	if cp.GuardOffset > (1<<63-1)-int64(cp.GuardBytes) {
		return false
	}
	if cp.Offset > 0 && (cp.GuardBytes > shipGuardBytes || cp.GuardOffset+int64(cp.GuardBytes) != cp.Offset) {
		return false
	}
	if cp.Offset == 0 && cp.GuardOffset != 0 {
		return false
	}
	decoded, err := hex.DecodeString(cp.GuardSHA256)
	return err == nil && len(decoded) == sha256.Size
}

func writeShipCheckpoint(path string, cp shipCheckpoint) error {
	b, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".numbat-ship-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return replaceShipState(tmp, path)
}

func shipDestinationID(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:])
}

func sameShipPath(a, b string) bool {
	a, errA := filepath.Abs(filepath.Clean(a))
	b, errB := filepath.Abs(filepath.Clean(b))
	if errA != nil || errB != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

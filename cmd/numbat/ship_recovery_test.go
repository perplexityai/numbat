package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShipOversizedRecordDoesNotWedgeDrain(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	rec := func(id string) string {
		return fmt.Sprintf(`{"record_type":"event","event_id":%q}`, id) + "\n"
	}
	oversized := string(shipTestEnvelope(t, map[string]any{
		"record_type": "event", "event_type": "command.exec", "event_id": "oversized",
		"evidence": map[string]string{"artifact_type": "hook"}, "command": strings.Repeat("x", maxShipRecordBytes+1024),
	}))
	appendRaw(t, inputPath, []byte(rec("before-1")+rec("before-2")+oversized+rec("after-1")+rec("after-2")))
	info, err := os.Stat(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	fullSize := info.Size()

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)

	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := sink.uniqueDelivered(); got != 5 {
		t.Fatalf("oversized record wedged drain: want 5 records delivered, got %d (offset=%d, err=%v)", got, cursor.checkpoint.Offset, err)
	}
	if cursor.checkpoint.Offset != fullSize {
		t.Fatalf("offset did not advance past oversized record: got %d, want %d", cursor.checkpoint.Offset, fullSize)
	}
}

func TestShipRecoverySkipsOversizedFirstRecord(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	torn := strings.Repeat("x", maxShipRecordBytes+1024)
	rotated := []byte(torn + `{"record_type":"event","event_id":"glued"}` + "\n" + `{"record_type":"event","event_id":"rotated"}` + "\n")
	appendRaw(t, inputPath, rotated)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "active", 1)

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	cursor := newTestShipCursor()
	var err error
	var logs bytes.Buffer
	for i := 0; i < 6; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, newSinkFactory(sink.srv.URL), &logs)
		if err != nil {
			t.Fatalf("drain pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 2 {
		t.Fatalf("delivered=%d, want retained suffix and active record", got)
	}
	if !strings.Contains(logs.String(), "not a single JSON object; skipped from HTTP delivery and retained in the input file") {
		t.Fatalf("missing explicit malformed-line diagnostic: %s", &logs)
	}
	if got, err := os.ReadFile(inputPath + ".1"); err != nil || !bytes.Equal(got, rotated) {
		t.Fatalf("rotated original changed: bytes=%d err=%v", len(got), err)
	}
}

func TestShipOversizedRecordPersistsTailGuard(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	record := string(shipTestEnvelope(t, map[string]any{
		"record_type": "event", "event_type": "command.exec", "event_id": "oversized",
		"evidence": map[string]string{"artifact_type": "hook"}, "command": strings.Repeat("x", maxShipRecordBytes+1024),
	}))
	appendRaw(t, inputPath, []byte(record))

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)

	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if cursor.checkpoint.Offset != int64(len(record)) {
		t.Fatalf("offset=%d, want %d", cursor.checkpoint.Offset, len(record))
	}
	if cursor.checkpoint.GuardBytes != shipGuardBytes || cursor.checkpoint.GuardSHA256 == "" {
		t.Fatalf("oversized checkpoint lost tail guard: %+v", cursor.checkpoint)
	}
}

func TestShipCorruptStateDoesNotSkipRotatedBacklog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	writeSpool(t, inputPath, "rotated", 20)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "active", 5)
	if err := os.WriteFile(statePath, []byte("{ this is not valid ship state"), 0o600); err != nil {
		t.Fatal(err)
	}

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)

	cursor, err := readShipCursor(statePath, testShipDestination)
	if err != nil {
		t.Fatalf("read corrupt state: %v", err)
	}
	for i := 0; i < 6; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("drain pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 25 {
		t.Fatalf("corrupt state recovery delivered %d records, want 25", got)
	}
}

func TestShipRetriesReanchorCheckpointBeforeDelivery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")
	writeSpool(t, inputPath, "rotated", 2)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "active", 1)
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	cursor, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
	if err == nil || !cursor.pending || sink.attempts.Load() != 0 {
		t.Fatalf("failed re-anchor: pending=%v attempts=%d err=%v", cursor.pending, sink.attempts.Load(), err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("recovery pass %d: %v", i+1, err)
		}
	}
	if cursor.pending || sink.uniqueDelivered() != 3 {
		t.Fatalf("recovery pending=%v delivered=%d", cursor.pending, sink.uniqueDelivered())
	}
}

func TestShipLostCheckpointResumesUndrainedRotatedSegment(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	// The checkpointed oldest segment disappears while a newer rotation remains.
	checkpointSize := writeSpool(t, inputPath, "checkpointed", 10)
	if err := os.Rename(inputPath, inputPath+".2"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "undrained", 15)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "active", 5)

	checkpointContent, err := os.ReadFile(inputPath + ".2")
	if err != nil {
		t.Fatal(err)
	}
	f, err := openShipInput(inputPath + ".2")
	if err != nil {
		t.Fatal(err)
	}
	checkpointID, err := shipFileIdentity(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	cursor := shipCursor{checkpoint: newShipCheckpoint(testShipDestination, checkpointID, checkpointSize, checkpointContent)}
	if err := os.Remove(inputPath + ".2"); err != nil {
		t.Fatal(err)
	}

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	for i := 0; i < 6; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, io.Discard)
		if err != nil {
			t.Fatalf("drain pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 20 {
		t.Fatalf("lost checkpoint reset to active and dropped undrained rotated segment: want 20 delivered (15 rotated + 5 active), got %d", got)
	}
}

func TestShipDrainedIdentityDistinguishesReusedFileID(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	rotatedPath := inputPath + ".1"
	writeSpool(t, rotatedPath, "old", 3)

	f, err := openShipInput(rotatedPath)
	if err != nil {
		t.Fatal(err)
	}
	oldFileID, err := shipFileIdentity(f)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	oldDrainedID, err := shipDrainedFileID(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Truncate(rotatedPath, 0); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, rotatedPath, "new", 4)
	writeSpool(t, inputPath, "active", 1)

	f, err = openShipInput(rotatedPath)
	if err != nil {
		t.Fatal(err)
	}
	newFileID, err := shipFileIdentity(f)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	newDrainedID, err := shipDrainedFileID(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if newFileID != oldFileID {
		t.Fatalf("truncate changed file identity: old=%q new=%q", oldFileID, newFileID)
	}
	if newDrainedID == oldDrainedID {
		t.Fatal("drained identity ignored replacement content")
	}

	nextID, err := nextRotatedShipFileID(inputPath, []string{oldDrainedID}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if nextID != newFileID {
		t.Fatalf("next rotated file=%q, want reused file id %q", nextID, newFileID)
	}
}

func TestShipReanchorEmitsReDeliverySignal(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	writeSpool(t, inputPath, "rotated", 12)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "active", 4)

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)

	var logs bytes.Buffer
	cursor := newTestShipCursor()
	var err error
	for i := 0; i < 6; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, &logs)
		if err != nil {
			t.Fatalf("drain pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 16 {
		t.Fatalf("want 16 delivered (12 rotated + 4 active), got %d", got)
	}
	if !strings.Contains(logs.String(), "re-anchored") {
		t.Fatalf("re-anchor to a retained rotated segment was silent: injected writer got %q", logs.String())
	}
}

func TestShipBoundedNoticeRoutedToWriter(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	rec := func(id string) string {
		return fmt.Sprintf(`{"record_type":"event","event_id":%q}`, id) + "\n"
	}
	oversized := string(shipTestEnvelope(t, map[string]any{
		"record_type": "event", "event_type": "command.exec", "event_id": "oversized",
		"evidence": map[string]string{"artifact_type": "hook"}, "command": strings.Repeat("x", maxShipRecordBytes+1024),
	}))
	appendRaw(t, inputPath, []byte(rec("before")+oversized+rec("after")))

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)

	var logs bytes.Buffer
	_, err := drainAvailable(ctx, inputPath, statePath, newTestShipCursor(), maxShipBatchBytes, factory, &logs)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if !strings.Contains(logs.String(), "accepted bounded representation") {
		t.Fatalf("bounded-delivery notice was not routed to the injected writer: got %q", logs.String())
	}
}

func TestShipResetReDeliversRetainedSegmentWithSignal(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "records.ndjson")
	statePath := filepath.Join(dir, "records.ship-state")

	writeSpool(t, inputPath, "retained", 10)
	if err := os.Rename(inputPath, inputPath+".1"); err != nil {
		t.Fatal(err)
	}
	writeSpool(t, inputPath, "active", 5)

	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)

	var logs bytes.Buffer
	cursor := newTestShipCursor()
	var err error
	for i := 0; i < 6; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, &logs)
		if err != nil {
			t.Fatalf("initial drain pass %d: %v", i+1, err)
		}
	}
	if got := sink.uniqueDelivered(); got != 15 {
		t.Fatalf("want 15 delivered before reset (10 retained + 5 active), got %d", got)
	}
	logs.Reset()

	if err := os.WriteFile(inputPath, []byte(`{"record_type":"event","event_id":"active-1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		cursor, err = drainAvailable(ctx, inputPath, statePath, cursor, maxShipBatchBytes, factory, &logs)
		if err != nil {
			t.Fatalf("reset drain pass %d: %v", i+1, err)
		}
	}

	if !strings.Contains(logs.String(), "re-anchored") {
		t.Fatalf("reset re-delivery was silent: injected writer got %q", logs.String())
	}
	sink.mu.Lock()
	replays := sink.accepted["retained-1"]
	sink.mu.Unlock()
	if replays < 2 {
		t.Fatalf("retained segment was not re-delivered after reset: retained-1 accepted %d time(s), want >= 2", replays)
	}
	if replays > 3 {
		t.Fatalf("retained segment re-delivery is not bounded: retained-1 accepted %d times", replays)
	}
}

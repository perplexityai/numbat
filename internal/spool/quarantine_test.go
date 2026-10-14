package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestQuarantinePreservesOriginalAndSeparateDisposition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.spool")
	store := New(path)
	original := []byte("{\"id\":\"quarantined\"}\n")
	for _, record := range [][]byte{original, []byte("{\"id\":\"delivered\"}\n")} {
		if err := store.Put(record); err != nil {
			t.Fatal(err)
		}
	}
	stale, err := store.Peek(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	head, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Quarantine(stale, QuarantineHTTP413); err == nil {
		t.Fatal("quarantined a multi-record batch")
	}
	if err := store.Quarantine(head, QuarantineReason(0)); err == nil {
		t.Fatal("accepted unknown reason")
	}
	if err := store.Quarantine(head, QuarantineHTTP413); err != nil {
		t.Fatal(err)
	}
	if err := New(path).Quarantine(head, QuarantineHTTP413); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if err := store.Quarantine(head, QuarantineUnrepresentable); err == nil {
		t.Fatal("silently changed quarantine reason")
	}
	if err := store.Ack(head); err == nil {
		t.Fatal("quarantined head reported acknowledged")
	}
	if err := store.Ack(stale); err == nil {
		t.Fatal("stale batch acknowledged a quarantined record")
	}
	if _, _, err := store.AckRepresented(head); err == nil {
		t.Fatal("quarantined original reported represented")
	}
	next, err := New(path).Peek(1)
	if err != nil || len(next.Records) != 1 || bytes.Equal(next.Records[0], original) {
		t.Fatalf("later record not available: %v", err)
	}
	if err := store.Ack(next); err != nil {
		t.Fatal(err)
	}
	status, err := store.Status()
	if err != nil || status.Format != "numbat-spool-v2" || status.PendingRecords != 0 ||
		status.QuarantinedRecords != 1 || status.RetainedRecords != 0 || !status.NeedsAttention {
		t.Fatalf("status: %+v, %v", status, err)
	}
	if err := store.withReadOnlyDB(func(db *bolt.DB) error {
		return db.View(func(tx *bolt.Tx) error {
			if tx.Bucket(metadataBucket).Get(ackedKey) != nil {
				t.Error("v2 retained ambiguous acknowledged-through metadata")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(t.TempDir(), "export")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.ExportOriginals(exportPath)
	if err != nil || len(summary.Quarantined) != 1 || len(summary.Retained) != 0 ||
		summary.SettledThrough == nil || *summary.SettledThrough != 2 || summary.AckedThrough != nil {
		t.Fatalf("summary: %+v, %v", summary, err)
	}
	exported, err := os.ReadFile(filepath.Join(exportPath, summary.Quarantined[0].File))
	digest := sha256.Sum256(original)
	if err != nil || !bytes.Equal(exported, original) || summary.Quarantined[0].SHA256 != hex.EncodeToString(digest[:]) ||
		summary.Quarantined[0].Reason != "http_413" {
		t.Fatalf("export lost provenance: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("export changed source: %v", err)
	}
	if _, err := store.ExportOriginals(exportPath); err == nil {
		t.Fatal("export overwrote existing evidence")
	}
}

func TestQuarantineCapacityFailureLeavesOriginalPending(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "records.spool"))
	record := []byte("{\"id\":1}\n")
	for i := 0; i < maxQuarantinedRecords; i++ {
		if err := store.Put(record); err != nil {
			t.Fatal(err)
		}
		batch, err := store.Peek(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Quarantine(batch, QuarantineHTTP413); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Put(record); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Quarantine(batch, QuarantineHTTP413); err == nil {
		t.Fatal("quarantine exceeded capacity")
	}
	status, err := store.Status()
	if err != nil || status.QuarantinedRecords != maxQuarantinedRecords || status.PendingRecords != 1 {
		t.Fatalf("full quarantine lost data: %+v, %v", status, err)
	}
}

func TestQuarantineByteAccountingLimit(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "records.spool"))
	if err := store.Put([]byte("first")); err != nil {
		t.Fatal(err)
	}
	first, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Quarantine(first, QuarantineHTTP413); err != nil {
		t.Fatal(err)
	}
	// Seed boundary accounting rather than allocate 256 MiB in a unit test.
	if err := store.withDB(func(db *bolt.DB, _ os.FileInfo) error {
		return db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(metadataBucket).Put(quarantineBytesKey, key(maxQuarantinedBytes-1))
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put([]byte("xx")); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Quarantine(batch, QuarantineHTTP413); err == nil {
		t.Fatal("quarantine exceeded its byte budget")
	}
	pending, err := store.Peek(1)
	if err != nil || len(pending.Records) != 1 || string(pending.Records[0]) != "xx" {
		t.Fatalf("byte limit removed pending original: %v", err)
	}
}

func TestQuarantineRejectsAlteredAndReplacedBatch(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "records.spool"))
	if err := store.Put([]byte("{\"id\":1}\n")); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	changed := batch
	changed.Records = [][]byte{[]byte("{\"id\":2}\n")}
	if err := store.Quarantine(changed, QuarantineHTTP413); err == nil {
		t.Fatal("quarantined altered content")
	}
	other := New(filepath.Join(t.TempDir(), "other.spool"))
	if err := other.Put(batch.Records[0]); err != nil {
		t.Fatal(err)
	}
	if err := other.Quarantine(batch, QuarantineHTTP413); err == nil {
		t.Fatal("quarantined an unrelated store")
	}
	if err := store.withDB(func(db *bolt.DB, _ os.FileInfo) error {
		return db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(metadataBucket).Put(generationKey, bytes.Repeat([]byte{0xff}, generationBytes))
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Quarantine(batch, QuarantineHTTP413); err == nil {
		t.Fatal("quarantined a different generation")
	}
}

func TestQuarantineUpgradePreservesPriorAcceptedOriginals(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "records.spool"))
	record := []byte("{\"id\":1}\n")
	if err := store.Put(record); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AckRepresented(batch); err != nil {
		t.Fatal(err)
	}
	legacy, err := store.ExportOriginals(filepath.Join(t.TempDir(), "v1"))
	if err != nil || legacy.Format != "numbat-spool-v1" || legacy.AckedThrough == nil || *legacy.AckedThrough != 1 {
		t.Fatalf("legacy summary: %+v, %v", legacy, err)
	}
	if err := store.Put(record); err != nil {
		t.Fatal(err)
	}
	batch, err = store.Peek(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Quarantine(batch, QuarantineUnrepresentable); err != nil {
		t.Fatal(err)
	}
	upgraded, err := store.ExportOriginals(filepath.Join(t.TempDir(), "v2"))
	if err != nil || upgraded.RetainedCount != 1 || upgraded.QuarantinedCount != 1 {
		t.Fatalf("upgrade lost accepted original: %+v, %v", upgraded, err)
	}
	raw, err := json.Marshal(upgraded)
	if err != nil || bytes.Contains(raw, []byte("acked_through")) || !bytes.Contains(raw, []byte("settled_through")) {
		t.Fatalf("ambiguous v2 receipt: %s, %v", raw, err)
	}
}

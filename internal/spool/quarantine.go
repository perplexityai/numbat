package spool

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

const (
	maxQuarantinedRecords = 256
	maxQuarantinedBytes   = 256 << 20
)

var (
	quarantineBucket   = []byte("numbat.spool.quarantine")
	quarantineCountKey = []byte("quarantine-count")
	quarantineBytesKey = []byte("quarantine-bytes")
)

// QuarantineReason describes a local disposition, never a delivery receipt.
// Only record-specific failures may leave the pending FIFO this way.
type QuarantineReason byte

const (
	QuarantineUnrepresentable QuarantineReason = iota + 1
	QuarantineHTTP413
	QuarantineRetentionFull
)

func (reason QuarantineReason) String() string {
	switch reason {
	case QuarantineUnrepresentable:
		return "unrepresentable"
	case QuarantineHTTP413:
		return "http_413"
	case QuarantineRetentionFull:
		return "retention_full"
	default:
		return ""
	}
}

// Quarantine atomically preserves the exact head record and its reason before
// removing it from the pending FIFO. It does not acknowledge remote delivery.
// The first quarantine upgrades v1 to v2 in the same transaction; old binaries
// refuse this format rather than mistake local disposition for acceptance.
func (store Store) Quarantine(batch Batch, reason QuarantineReason) error {
	if reason.String() == "" || len(batch.Records) != 1 || batch.lastID == 0 ||
		batch.firstID != batch.lastID || batch.fileInfo == nil {
		return errors.New("spool: quarantine requires one head record and a known reason")
	}
	return store.withDB(func(db *bolt.DB, info os.FileInfo) error {
		if !os.SameFile(batch.fileInfo, info) {
			return errors.New("quarantine belongs to a replaced store")
		}
		return db.Update(func(tx *bolt.Tx) error {
			meta, records := tx.Bucket(metadataBucket), tx.Bucket(recordsBucket)
			if !bytes.Equal(meta.Get(generationKey), batch.generation[:]) {
				return errors.New("quarantine belongs to a replaced store")
			}
			value := append(bytes.Clone(batch.boundary[:]), byte(reason))
			value = append(value, batch.Records[0]...)
			if quarantined := tx.Bucket(quarantineBucket); quarantined != nil {
				if previous := quarantined.Get(key(batch.lastID)); previous != nil {
					if bytes.Equal(previous, value) {
						return nil
					}
					return errors.New("quarantine disposition does not match")
				}
			}
			k, pending := records.Cursor().First()
			if k == nil || !bytes.Equal(k, key(batch.lastID)) ||
				len(pending) < recordIDBytes || !bytes.Equal(pending[:recordIDBytes], batch.boundary[:]) ||
				!bytes.Equal(pending[recordIDBytes:], batch.Records[0]) {
				return errors.New("quarantine no longer matches the pending head")
			}
			count, size := quarantineTotals(meta)
			if count >= maxQuarantinedRecords || uint64(len(batch.Records[0])) > maxQuarantinedBytes-size {
				return errors.New("quarantine capacity exhausted; original remains pending")
			}
			quarantined, err := tx.CreateBucketIfNotExists(quarantineBucket)
			if err != nil {
				return err
			}
			if err := quarantined.Put(k, value); err != nil {
				return err
			}
			if err := meta.Put(quarantineCountKey, key(count+1)); err != nil {
				return err
			}
			if err := meta.Put(quarantineBytesKey, key(size+uint64(len(batch.Records[0])))); err != nil {
				return err
			}
			if err := records.Delete(k); err != nil {
				return err
			}
			if err := meta.Put(markerKey, quarantineFormat); err != nil {
				return err
			}
			if err := meta.Delete(ackedKey); err != nil {
				return err
			}
			return meta.Put(settledKey, key(batch.lastID))
		})
	})
}

func quarantineTotals(meta *bolt.Bucket) (count, size uint64) {
	if raw := meta.Get(quarantineCountKey); len(raw) == 8 {
		count = binary.BigEndian.Uint64(raw)
	}
	if raw := meta.Get(quarantineBytesKey); len(raw) == 8 {
		size = binary.BigEndian.Uint64(raw)
	}
	return count, size
}

func validateQuarantine(tx *bolt.Tx, v2 bool) error {
	meta, quarantined := tx.Bucket(metadataBucket), tx.Bucket(quarantineBucket)
	for _, k := range [][]byte{quarantineCountKey, quarantineBytesKey} {
		if raw := meta.Get(k); len(raw) != 0 && (!v2 || len(raw) != 8) {
			return errors.New("invalid quarantine accounting")
		}
	}
	count, size := quarantineTotals(meta)
	if (!v2 && quarantined != nil) || count > maxQuarantinedRecords || size > maxQuarantinedBytes ||
		(count > 0 && quarantined == nil) {
		return errors.New("invalid quarantine")
	}
	return nil
}

// Status is a read-only local recovery check, not an HTTP receiver health check.
type Status struct {
	Format             string `json:"format"`
	PendingRecords     int    `json:"pending_records"`
	RetainedRecords    uint64 `json:"retained_records"`
	RetainedBytes      uint64 `json:"retained_bytes"`
	QuarantinedRecords uint64 `json:"quarantined_records"`
	QuarantinedBytes   uint64 `json:"quarantined_bytes"`
	NeedsAttention     bool   `json:"needs_attention"`
}

// Status opens an existing spool without creating or modifying it.
func (store Store) Status() (status Status, err error) {
	err = store.withReadOnlyDB(func(db *bolt.DB) error {
		return db.View(func(tx *bolt.Tx) error {
			meta := tx.Bucket(metadataBucket)
			status.Format = string(meta.Get(markerKey))
			status.PendingRecords = tx.Bucket(recordsBucket).Stats().KeyN
			status.RetainedRecords, status.RetainedBytes = retainedTotals(meta)
			status.QuarantinedRecords, status.QuarantinedBytes = quarantineTotals(meta)
			status.NeedsAttention = status.QuarantinedRecords > 0 ||
				status.RetainedRecords >= maxRetainedRecords || status.RetainedBytes >= maxRetainedBytes
			return nil
		})
	})
	if err != nil {
		return status, fmt.Errorf("spool status: %w", err)
	}
	return status, nil
}

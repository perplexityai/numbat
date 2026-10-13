package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// ExportOriginals reads a stopped copy of a spool. It leaves the database
// unchanged and creates a private directory containing the exact retained
// originals, pending FIFO bytes, and a manifest written last.
func (store Store) ExportOriginals(outputDir string) (summary ExportSummary, err error) {
	info, err := os.Lstat(store.path)
	if err != nil {
		return summary, err
	}
	if !info.Mode().IsRegular() {
		return summary, errors.New("spool export requires a regular copied database")
	}
	if err := validateDatabaseMode(info); err != nil {
		return summary, err
	}
	parentInfo, err := os.Lstat(filepath.Dir(store.path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return summary, errors.New("spool export requires a real input parent directory")
	}
	if err := validateParentMode(parentInfo); err != nil {
		return summary, err
	}
	outputParent, err := os.Lstat(filepath.Dir(outputDir))
	if err != nil || !outputParent.IsDir() || outputParent.Mode()&os.ModeSymlink != 0 {
		return summary, errors.New("spool export requires a real output parent directory")
	}
	if err := validateParentMode(outputParent); err != nil {
		return summary, err
	}
	db, err := bolt.Open(store.path, 0, &bolt.Options{
		ReadOnly: true,
		Timeout:  lockTimeout,
		OpenFile: func(path string, _ int, _ os.FileMode) (*os.File, error) {
			file, openErr := openExistingDatabaseFile(path, os.O_RDONLY)
			if openErr != nil {
				return nil, openErr
			}
			opened, statErr := file.Stat()
			if statErr != nil || !os.SameFile(info, opened) {
				_ = file.Close()
				return nil, errors.New("spool export source changed while opening")
			}
			return file, nil
		},
	})
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	if err := db.View(validateStore); err != nil {
		return summary, err
	}
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		return summary, fmt.Errorf("create new export directory: %w", err)
	}
	if err := os.Mkdir(filepath.Join(outputDir, "retained"), 0o700); err != nil {
		return summary, err
	}
	output, err := os.OpenFile(filepath.Join(outputDir, "pending.ndjson"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return summary, err
	}
	pendingHash := sha256.New()
	summary.Format = "numbat-spool-v1"
	err = db.View(func(tx *bolt.Tx) error {
		meta, records := tx.Bucket(metadataBucket), tx.Bucket(recordsBucket)
		summary.AckedThrough = binary.BigEndian.Uint64(meta.Get(ackedKey))
		summary.Sequence = records.Sequence()
		if retained := tx.Bucket(retainedBucket); retained != nil {
			if err := retained.ForEach(func(k, value []byte) error {
				if len(k) != 8 || binary.BigEndian.Uint64(k) > summary.AckedThrough ||
					len(value) == 0 || value[len(value)-1] != '\n' || bytes.Count(value, []byte{'\n'}) != 1 || !json.Valid(value[:len(value)-1]) {
					return errors.New("invalid retained original")
				}
				name := fmt.Sprintf("%020d.ndjson", binary.BigEndian.Uint64(k))
				if err := writeExportFile(filepath.Join(outputDir, "retained", name), value); err != nil {
					return err
				}
				digest := sha256.Sum256(value)
				summary.Retained = append(summary.Retained, ExportEntry{Sequence: binary.BigEndian.Uint64(k), Bytes: len(value), SHA256: hex.EncodeToString(digest[:]), File: filepath.Join("retained", name)})
				summary.RetainedBytes += uint64(len(value))
				return nil
			}); err != nil {
				return err
			}
		}
		count, retainedBytes := retainedTotals(meta)
		if uint64(len(summary.Retained)) != count || summary.RetainedBytes != retainedBytes {
			return errors.New("retained accounting does not match original bytes")
		}
		var previous uint64
		return records.ForEach(func(k, value []byte) error {
			if len(k) != 8 || len(value) < recordIDBytes || binary.BigEndian.Uint64(k) <= summary.AckedThrough ||
				binary.BigEndian.Uint64(k) <= previous || binary.BigEndian.Uint64(k) > summary.Sequence {
				return errors.New("invalid pending record")
			}
			record := value[recordIDBytes:]
			if len(record) == 0 || record[len(record)-1] != '\n' || bytes.Count(record, []byte{'\n'}) != 1 || !json.Valid(record[:len(record)-1]) {
				return errors.New("pending record lacks a complete NDJSON line")
			}
			if _, err := output.Write(record); err != nil {
				return err
			}
			_, _ = pendingHash.Write(record)
			summary.PendingCount++
			summary.PendingBytes += uint64(len(record))
			previous = binary.BigEndian.Uint64(k)
			return nil
		})
	})
	err = errors.Join(err, output.Sync(), output.Close())
	if err != nil {
		return summary, err
	}
	summary.PendingSHA256 = hex.EncodeToString(pendingHash.Sum(nil))
	summary.RetainedCount = len(summary.Retained)
	manifest, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return summary, err
	}
	if err := writeExportFile(filepath.Join(outputDir, "manifest.json"), append(manifest, '\n')); err != nil {
		return summary, err
	}
	for _, dir := range []string{filepath.Join(outputDir, "retained"), outputDir, filepath.Dir(outputDir)} {
		f, err := os.Open(dir)
		if err != nil {
			return summary, err
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			return summary, err
		}
	}
	return summary, nil
}

type ExportSummary struct {
	Format        string        `json:"format"`
	AckedThrough  uint64        `json:"acked_through"`
	Sequence      uint64        `json:"sequence"`
	PendingCount  uint64        `json:"pending_count"`
	PendingBytes  uint64        `json:"pending_bytes"`
	PendingSHA256 string        `json:"pending_sha256"`
	RetainedCount int           `json:"retained_count"`
	RetainedBytes uint64        `json:"retained_bytes"`
	Retained      []ExportEntry `json:"retained"`
}

type ExportEntry struct {
	Sequence uint64 `json:"sequence"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
	File     string `json:"file"`
}

func writeExportFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// Package spool stores complete records until a shipper acknowledges them.
// Each operation opens, transacts against, and closes the database. A hook
// process therefore holds no database lock while it does unrelated work.
package spool

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

const (
	generationBytes = 16
	recordIDBytes   = 16
	maxBatchRecords = 500
	lockTimeout     = time.Second
)

var (
	// ErrBusy reports that another process held the bbolt lock for the full
	// operation timeout. A long-running shipper can retry this error.
	ErrBusy     = bolterrors.ErrTimeout
	errNotSpool = errors.New("not a numbat spool")

	metadataBucket = []byte("numbat.spool.meta")
	recordsBucket  = []byte("numbat.spool.records")
	markerKey      = []byte("format")
	markerValue    = []byte("numbat-spool-v1")
	generationKey  = []byte("generation")
	ackedKey       = []byte("acked-through")
)

// Store is a path-bound durable record queue. It owns no open resources
// between method calls and is safe to copy or use from concurrent processes.
// Its parent directory must not be writable by untrusted users.
type Store struct{ path string }

// Batch is a FIFO prefix returned by Peek. Its acknowledgment identity is
// opaque; callers can only pass the complete batch to Ack.
type Batch struct {
	Records    [][]byte
	generation [generationBytes]byte
	boundary   [recordIDBytes]byte
	lastID     uint64
	fileInfo   os.FileInfo
}

// New binds a store value to path without opening or creating the database.
func New(path string) Store { return Store{path: path} }

// Put atomically appends one opaque record. A nil error means bbolt committed
// the complete value; an interrupted transaction exposes none of it.
func (store Store) Put(record []byte) error {
	return store.withDB(func(db *bolt.DB, _ os.FileInfo) error {
		return db.Update(func(tx *bolt.Tx) error {
			records := tx.Bucket(recordsBucket)
			id, err := records.NextSequence()
			if err != nil {
				return err
			}
			if id == 0 {
				return errors.New("record sequence exhausted")
			}
			value := make([]byte, recordIDBytes+len(record))
			if _, err := rand.Read(value[:recordIDBytes]); err != nil {
				return err
			}
			copy(value[recordIDBytes:], record)
			return records.Put(key(id), value)
		})
	})
}

// Peek returns at most 500 oldest whole records whose combined size fits
// maxBytes. It returns the first record when that record alone exceeds the
// budget. Records remain visible until Ack commits.
func (store Store) Peek(maxBytes int) (batch Batch, err error) {
	if maxBytes <= 0 {
		return batch, errors.New("spool: maxBytes must be positive")
	}
	err = store.withDB(func(db *bolt.DB, info os.FileInfo) error {
		return db.View(func(tx *bolt.Tx) error {
			metadata := tx.Bucket(metadataBucket)
			records := tx.Bucket(recordsBucket)
			copy(batch.generation[:], metadata.Get(generationKey))
			batch.fileInfo = info
			size := 0
			cursor := records.Cursor()
			for k, value := cursor.First(); k != nil && len(batch.Records) < maxBatchRecords; k, value = cursor.Next() {
				if len(k) != 8 || len(value) < recordIDBytes {
					return errors.New("invalid record entry")
				}
				record := value[recordIDBytes:]
				if len(batch.Records) > 0 && size+len(record) > maxBytes {
					break
				}
				batch.Records = append(batch.Records, bytes.Clone(record))
				copy(batch.boundary[:], value[:recordIDBytes])
				batch.lastID = binary.BigEndian.Uint64(k)
				size += len(record)
			}
			return nil
		})
	})
	return batch, err
}

// Ack removes only the exact FIFO prefix represented by batch. File identity,
// store generation, and a random record identity reject replacement and
// rollback cases before any record is removed.
func (store Store) Ack(batch Batch) error {
	if batch.lastID == 0 || batch.fileInfo == nil {
		return errors.New("spool: cannot acknowledge an empty batch")
	}
	return store.withDB(func(db *bolt.DB, info os.FileInfo) error {
		if !os.SameFile(batch.fileInfo, info) {
			return errors.New("acknowledgment belongs to a replaced store")
		}
		return db.Update(func(tx *bolt.Tx) error {
			metadata := tx.Bucket(metadataBucket)
			records := tx.Bucket(recordsBucket)
			if !bytes.Equal(metadata.Get(generationKey), batch.generation[:]) {
				return errors.New("acknowledgment belongs to a replaced store")
			}
			acked := binary.BigEndian.Uint64(metadata.Get(ackedKey))
			if acked >= batch.lastID {
				return nil
			}
			boundary := records.Get(key(batch.lastID))
			if len(boundary) < recordIDBytes || !bytes.Equal(boundary[:recordIDBytes], batch.boundary[:]) {
				return errors.New("acknowledgment boundary no longer matches the store")
			}

			last := key(batch.lastID)
			keys := make([][]byte, 0, maxBatchRecords)
			cursor := records.Cursor()
			for k, _ := cursor.First(); k != nil && bytes.Compare(k, last) <= 0; k, _ = cursor.Next() {
				if len(k) != 8 {
					return errors.New("invalid record key")
				}
				keys = append(keys, bytes.Clone(k))
			}
			for _, k := range keys {
				if err := records.Delete(k); err != nil {
					return err
				}
			}
			return metadata.Put(ackedKey, key(batch.lastID))
		})
	})
}

func (store Store) withDB(fn func(*bolt.DB, os.FileInfo) error) (err error) {
	if store.path == "" {
		return errors.New("spool: empty database path")
	}
	parent := filepath.Dir(store.path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("spool: create parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("spool: inspect parent: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("spool: parent must be a real directory")
	}
	if err := validateParentMode(parentInfo); err != nil {
		return fmt.Errorf("spool: parent %q: %w", parent, err)
	}

	if err := ensureDatabaseFile(store.path); err != nil {
		return fmt.Errorf("spool: initialize %q: %w", store.path, err)
	}
	file, err := openExistingDatabaseFile(store.path, os.O_RDWR)
	if err != nil {
		return fmt.Errorf("spool: open %q: %w", store.path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("spool: inspect database: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return errors.New("spool: database is not a regular file")
	}
	if err := validateDatabaseMode(info); err != nil {
		_ = file.Close()
		return fmt.Errorf("spool: database %q: %w", store.path, err)
	}
	if err := validateDatabaseReadOnly(store.path, info); err != nil {
		_ = file.Close()
		return fmt.Errorf("spool: validate %q: %w", store.path, err)
	}
	db, err := bolt.Open(store.path, 0o600, &bolt.Options{
		Timeout: lockTimeout,
		OpenFile: func(string, int, os.FileMode) (*os.File, error) {
			return file, nil
		},
	})
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("spool: open %q: %w", store.path, err)
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	if err := db.View(validateStore); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	if err := fn(db, info); err != nil {
		return fmt.Errorf("spool: %w", err)
	}
	return nil
}

func ensureDatabaseFile(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	candidate, err := createDatabaseCandidate(path)
	if err != nil {
		return err
	}
	defer os.Remove(candidate)
	return installDatabaseFile(candidate, path)
}

// createDatabaseCandidate builds and closes a fully marked database beside the
// final path. An interruption can leave this private temporary file, but it
// cannot leave an unmarked database at the final path.
func createDatabaseCandidate(path string) (candidate string, err error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	candidate = file.Name()
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(candidate)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	db, err := bolt.Open(candidate, 0o600, &bolt.Options{
		OpenFile: func(string, int, os.FileMode) (*os.File, error) {
			return file, nil
		},
	})
	if err != nil {
		return "", err
	}
	err = db.Update(initializeStore)
	if err == nil {
		err = db.View(validateStore)
	}
	if err = errors.Join(err, db.Close()); err != nil {
		return "", err
	}
	complete = true
	return candidate, nil
}

func validateDatabaseReadOnly(path string, want os.FileInfo) (err error) {
	db, err := bolt.Open(path, 0, &bolt.Options{
		ReadOnly: true,
		Timeout:  lockTimeout,
		OpenFile: func(path string, _ int, _ os.FileMode) (*os.File, error) {
			file, err := openExistingDatabaseFile(path, os.O_RDONLY)
			if err != nil {
				return nil, err
			}
			info, err := file.Stat()
			if err != nil || !os.SameFile(want, info) {
				_ = file.Close()
				if err != nil {
					return nil, err
				}
				return nil, errors.New("database changed during validation")
			}
			return file, nil
		},
	})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	return db.View(validateStore)
}

func initializeStore(tx *bolt.Tx) error {
	metadata, err := tx.CreateBucket(metadataBucket)
	if err != nil {
		return err
	}
	if _, err := tx.CreateBucket(recordsBucket); err != nil {
		return err
	}
	generation := make([]byte, generationBytes)
	if _, err := rand.Read(generation); err != nil {
		return err
	}
	if err := metadata.Put(markerKey, markerValue); err != nil {
		return err
	}
	if err := metadata.Put(generationKey, generation); err != nil {
		return err
	}
	return metadata.Put(ackedKey, key(0))
}

func validateStore(tx *bolt.Tx) error {
	metadata := tx.Bucket(metadataBucket)
	records := tx.Bucket(recordsBucket)
	if metadata == nil || records == nil || !bytes.Equal(metadata.Get(markerKey), markerValue) {
		return errNotSpool
	}
	if len(metadata.Get(generationKey)) != generationBytes || len(metadata.Get(ackedKey)) != 8 {
		return fmt.Errorf("%w: invalid metadata", errNotSpool)
	}
	if binary.BigEndian.Uint64(metadata.Get(ackedKey)) > records.Sequence() {
		return fmt.Errorf("%w: invalid acknowledged sequence", errNotSpool)
	}
	return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if bytes.Equal(name, metadataBucket) || bytes.Equal(name, recordsBucket) {
			return nil
		}
		return fmt.Errorf("%w: unexpected bucket %q", errNotSpool, name)
	})
}

func key(id uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, id)
	return k
}

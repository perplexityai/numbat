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

func TestShipDrainedCacheStaysWithinCheckpointBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	cp := newShipCheckpoint(testShipDestination, "active", 2, []byte("x\n"))
	for i := 0; i < maxShipDrainedFiles*2; i++ {
		var err error
		cp.DrainedFileIDs, err = appendShipFileID(path, cp.DrainedFileIDs, fmt.Sprintf("retained-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if !validShipCheckpoint(cp, testShipDestination) {
			t.Fatalf("rotation %d produced invalid checkpoint with %d identities", i, len(cp.DrainedFileIDs))
		}
	}
	ids, err := appendShipFileID(path, cp.DrainedFileIDs, "retained-2047")
	if err != nil || len(ids) != maxShipDrainedFiles {
		t.Fatal("duplicate identity expanded the cache")
	}
}

func TestShipFullRetainedCacheStopsUntilFilesAreArchived(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	var ids []string
	for i := 0; i <= maxShipDrainedFiles; i++ {
		name := fmt.Sprintf("%s.%04d", path, i)
		if err := os.WriteFile(name, []byte("{\"record_type\":\"event\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := time.Unix(1, 0)
		if err := os.Chtimes(name, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		file, err := openShipInput(name)
		if err != nil {
			t.Fatal(err)
		}
		id, err := shipDrainedFileID(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := appendShipFileID(path, ids[:maxShipDrainedFiles], ids[maxShipDrainedFiles]); err == nil {
		t.Fatal("full live cache silently evicted an equal-timestamp retained file")
	}
	if err := os.Remove(path + ".0000"); err != nil {
		t.Fatal(err)
	}
	next, err := appendShipFileID(path, ids[:maxShipDrainedFiles], ids[maxShipDrainedFiles])
	if err != nil || len(next) != maxShipDrainedFiles ||
		containsShipFileID(next, ids[0]) || !containsShipFileID(next, ids[maxShipDrainedFiles]) {
		t.Fatalf("archive did not release cache capacity: count=%d err=%v", len(next), err)
	}
}

func TestShipCheckpointVerifiesWholeCommittedPrefix(t *testing.T) {
	original := []byte(`{"record_type":"event","event_id":"old","padding":"` + strings.Repeat("x", shipGuardBytes*2) + "\"}\n")
	for _, test := range []struct {
		name, replacement string
		portable, legacy  bool
		want              bool
	}{
		{name: "unchanged", want: true},
		{name: "changed prefix identical tail", replacement: "new"},
		{name: "portable unchanged", portable: true, want: true},
		{name: "portable changed prefix", portable: true, replacement: "new"},
		{name: "legacy exact identity", legacy: true, want: true},
		{name: "legacy cannot prove portable identity", legacy: true, portable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "records.ndjson")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := openShipInput(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			id, err := shipFileIdentity(file)
			if err != nil {
				t.Fatal(err)
			}
			if id == "" {
				t.Skip("platform has no file identity")
			}
			cp := newShipCheckpoint(testShipDestination, id, int64(len(original)), original)
			if !test.legacy {
				cp.PrefixSHA256, err = appendShipPrefixHash("", original)
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.portable {
				parts := strings.Split(cp.FileID, ":")
				parts[0] = "0"
				if strings.HasPrefix(cp.FileID, "0:") {
					parts[0] = "1"
				}
				cp.FileID = strings.Join(parts, ":")
			}
			if test.replacement != "" {
				replaced := bytes.Replace(original, []byte(`"old"`), []byte(`"`+test.replacement+`"`), 1)
				if err := os.WriteFile(path, replaced, 0o600); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(original[len(original)-shipGuardBytes:], replaced[len(replaced)-shipGuardBytes:]) {
					t.Fatal("fixture changed the tail guard")
				}
			}
			got, err := shipCheckpointMatches(file, id, cp)
			if err != nil || got != test.want {
				t.Fatalf("match=%v err=%v, want %v", got, err, test.want)
			}
		})
	}
}

func TestShipCursorRestoresOnlyVolumeBoundDrainedCache(t *testing.T) {
	for _, knownVolume := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "known"}[knownVolume], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			cp := newShipCheckpoint(testShipDestination, "active", 2, []byte("x\n"))
			cp.DrainedFileIDs = []string{"retained"}
			if knownVolume {
				cp.VolumeID = strings.Repeat("1", 32)
			}
			if err := writeShipCheckpoint(path, cp); err != nil {
				t.Fatal(err)
			}
			cursor, err := readShipCursor(path, testShipDestination)
			if err != nil {
				t.Fatal(err)
			}
			if knownVolume {
				if cursor.pending || cursor.checkpoint.Offset != 2 || len(cursor.checkpoint.DrainedFileIDs) != 1 {
					t.Fatalf("lost volume-bound checkpoint: %+v", cursor)
				}
			} else if !cursor.pending || cursor.checkpoint.Offset != 0 || len(cursor.checkpoint.DrainedFileIDs) != 0 {
				t.Fatalf("trusted unverifiable drained cache: %+v", cursor)
			}
		})
	}
}

func TestShipRestartReplaysChangedCommittedPrefix(t *testing.T) {
	dir := t.TempDir()
	path, state := filepath.Join(dir, "records.ndjson"), filepath.Join(dir, "checkpoint.json")
	original := []byte(`{"record_type":"event","event_id":"old","padding":"` + strings.Repeat("x", shipGuardBytes*2) + "\"}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	sink := newFlakySink()
	sink.healthy.Store(true)
	defer sink.srv.Close()
	factory := newSinkFactory(sink.srv.URL)
	if _, err := drainAvailable(context.Background(), path, state, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard); err != nil {
		t.Fatal(err)
	}
	replacement := bytes.Replace(original, []byte(`"old"`), []byte(`"new"`), 1)
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	cursor, err := readShipCursor(state, testShipDestination)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err = drainAvailable(context.Background(), path, state, cursor, maxShipBatchBytes, factory, io.Discard)
	if err != nil || cursor.checkpoint.Offset != int64(len(replacement)) || sink.uniqueDelivered() != 2 {
		t.Fatalf("restart err=%v offset=%d delivered=%d", err, cursor.checkpoint.Offset, sink.uniqueDelivered())
	}
}

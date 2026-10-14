package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/perplexityai/numbat/internal/spool"
)

func oversizedTestEvent(t *testing.T) []byte {
	t.Helper()
	return shipTestEnvelope(t, map[string]any{
		"record_type": "event",
		"event_id":    "synthetic-event", "event_type": "command.exec",
		"command":  strings.Repeat("界", 2048),
		"evidence": map[string]any{"artifact_type": "hook"},
	})
}

func shipTestEnvelope(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	fields["schema_version"] = "0.4.0"
	fields["run_id"] = "synthetic-run"
	fields["source_agent"] = "unknown"
	fields["source_type"] = "hook"
	fields["confidence"] = "high"
	fields["endpoint"] = map[string]string{"hostname": "synthetic", "os": "linux", "arch": "amd64", "username": "synthetic", "uid": "1234"}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestBoundedShipRecordRequiresKnownVersion(t *testing.T) {
	for _, version := range []string{"0.2.0", "0.3.0", "0.4.0", "0.5.0", "", "unknown"} {
		original := bytes.Replace(oversizedTestEvent(t), []byte(`"0.4.0"`), []byte(`"`+version+`"`), 1)
		bounded, err := boundedShipRecord(original, 16)
		supported := version == "0.2.0" || version == "0.3.0" || version == "0.4.0"
		if (err == nil) != supported {
			t.Fatalf("version %q: err=%v", version, err)
		}
		if supported && !bytes.Contains(bounded, []byte(`"schema_version":"0.5.0"`)) {
			t.Fatalf("version %q: bounded bytes lack new version", version)
		}
	}
	unversioned := bytes.Replace(oversizedTestEvent(t), []byte(`"schema_version":"0.4.0",`), nil, 1)
	if _, err := boundedShipRecord(unversioned, 16); err == nil {
		t.Fatal("invented a version for an unversioned original")
	}
}

func TestBoundedShipRecordRejectsMissingEnvelope(t *testing.T) {
	for _, key := range []string{"run_id", "endpoint", "source_agent", "source_type", "confidence", "event_type", "event_id", "evidence"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(oversizedTestEvent(t), &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, key)
		original, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := boundedShipRecord(append(original, '\n'), 16); err == nil {
			t.Fatalf("accepted missing %s in a versioned envelope", key)
		}
	}
}

func TestBoundedShipRecordPreservesIdentityAndProvenance(t *testing.T) {
	original := oversizedTestEvent(t)
	saved := bytes.Clone(original)
	bounded, err := boundedShipRecord(original, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, saved) || !utf8.Valid(bounded) {
		t.Fatal("representation mutated the original or split UTF-8")
	}
	var got struct {
		SchemaVersion string `json:"schema_version"`
		EventID       string `json:"event_id"`
		Command       string `json:"command"`
		Evidence      struct {
			ArtifactType string `json:"artifact_type"`
			Transport    struct {
				Version     int    `json:"version"`
				Field       string `json:"truncated_field"`
				RecordBytes int    `json:"original_record_bytes"`
				RecordHash  string `json:"original_record_sha256"`
				FieldBytes  int    `json:"original_field_bytes"`
				FieldHash   string `json:"original_field_sha256"`
			} `json:"transport"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(bounded, &got); err != nil {
		t.Fatal(err)
	}
	recordHash := sha256.Sum256(original)
	fieldHash := sha256.Sum256([]byte(strings.Repeat("界", 2048)))
	marker := got.Evidence.Transport
	if got.SchemaVersion != "0.5.0" || got.EventID != "synthetic-event" || got.Command != "界" || got.Evidence.ArtifactType != "hook" ||
		marker.Version != 1 || marker.Field != "command" || marker.RecordBytes != len(original) ||
		marker.RecordHash != hex.EncodeToString(recordHash[:]) || marker.FieldBytes != 3*2048 ||
		marker.FieldHash != hex.EncodeToString(fieldHash[:]) {
		t.Fatalf("incorrect bounded provenance: %+v", got)
	}
	if _, err := boundedShipRecord(bounded, 1); err == nil {
		t.Fatal("accepted a second, conflicting transport marker")
	}
	duplicate := bytes.Replace(original, []byte(`"event_id":`), []byte(`"event_id":"other","event_id":`), 1)
	if _, err := boundedShipRecord(duplicate, 1); err == nil {
		t.Fatal("accepted duplicate identity fields")
	}
}

func TestBoundedShipContentAndFinding(t *testing.T) {
	for _, test := range []struct {
		name, raw, field string
	}{
		{"content", `{"schema_version":"0.4.0","record_type":"event","event_id":"e","event_type":"message.assistant","content":"abcdef","content_bytes":6,"evidence":{"artifact_type":"hook"}}`, "content"},
		{"finding", `{"record_type":"finding","finding_id":"f","severity":"high","observed_command":"abcdef","evidence_refs":[{"artifact_type":"hook"}],"rule_id":"synthetic","rule_version":"1","title":"synthetic finding","redacted":true,"detected_at":"2026-01-01T00:00:00Z","cited_event_ids":["e"]}`, "observed_command"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var original map[string]any
			if err := json.Unmarshal([]byte(test.raw), &original); err != nil {
				t.Fatal(err)
			}
			bounded, err := boundedShipRecord(shipTestEnvelope(t, original), 2)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(bounded, &got); err != nil {
				t.Fatal(err)
			}
			if got[test.field] != "ab" {
				t.Fatalf("wrong preview: %s", bounded)
			}
			if test.name == "content" && (got["content_bytes"] != float64(6) || got["content_truncated"] != true) {
				t.Fatalf("content size contract changed: %s", bounded)
			}
		})
	}
}

func TestBoundedSpoolAcknowledgesOnlyAcceptedRepresentation(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "accepted"}[accept], func(t *testing.T) {
			store := spool.New(filepath.Join(t.TempDir(), "records.spool"))
			original := oversizedTestEvent(t)
			if err := store.Put(original); err != nil {
				t.Fatal(err)
			}
			var attempts, represented atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				attempts.Add(1)
				if bytes.Contains(body, []byte(`"transport"`)) {
					represented.Add(1)
					if accept {
						w.WriteHeader(http.StatusOK)
						return
					}
				}
				w.WriteHeader(http.StatusRequestEntityTooLarge)
			}))
			defer server.Close()
			sent, err := shipSpoolBatch(context.Background(), store, maxShipBatchBytes, newSinkFactory(server.URL), io.Discard)
			if !sent || err != nil {
				t.Fatalf("sent=%v err=%v accept=%v", sent, err, accept)
			}
			pending, err := store.Peek(maxShipBatchBytes)
			if err != nil {
				t.Fatal(err)
			}
			count, size, err := store.RetainedStats()
			if err != nil {
				t.Fatal(err)
			}
			if !accept {
				if attempts.Load() != 6 || represented.Load() != 5 || count != 0 || size != 0 ||
					len(pending.Records) != 0 {
					t.Fatal("rejected representation lost the original or exceeded retry bound")
				}
				status, err := store.Status()
				if err != nil || status.QuarantinedRecords != 1 || status.QuarantinedBytes != uint64(len(original)) {
					t.Fatalf("quarantine status: %+v, %v", status, err)
				}
				return
			}
			if attempts.Load() != 2 || represented.Load() != 1 || len(pending.Records) != 0 ||
				count != 1 || size != uint64(len(original)) {
				t.Fatal("accepted representation did not atomically retain and acknowledge")
			}
			exportDir := filepath.Join(t.TempDir(), "export")
			summary, err := store.ExportOriginals(exportDir)
			if err != nil {
				t.Fatal(err)
			}
			if summary.PendingCount != 0 || len(summary.Retained) != 1 {
				t.Fatalf("export summary: %+v", summary)
			}
			exported, err := os.ReadFile(filepath.Join(exportDir, summary.Retained[0].File))
			if err != nil || !bytes.Equal(exported, original) {
				t.Fatalf("export changed original bytes: %v", err)
			}
			hash := sha256.Sum256(original)
			if summary.Retained[0].SHA256 != hex.EncodeToString(hash[:]) {
				t.Fatal("export manifest hash does not identify the original")
			}
		})
	}
}

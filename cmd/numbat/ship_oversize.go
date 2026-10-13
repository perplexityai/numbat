package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/perplexityai/numbat/internal/output"
)

const (
	// The hook accepts at most 4 MiB of input, but JSON escaping can expand
	// a native command beyond the former 8 MiB ship reader limit.
	maxShipOriginalBytes      = 32 << 20
	maxBoundedShipRecordBytes = 512 << 10
)

var errBoundedRecordTooLarge = errors.New("bounded representation still exceeds local transport limit")

// shipBoundedHTTP reacts only to an actual 413 or the local representation
// bound. It makes at most five attempts and never acknowledges the source.
func shipBoundedHTTP(ctx context.Context, factory shipSinkFactory, original []byte) error {
	var lastErr error
	for _, prefixBytes := range []int{1024, 256, 64, 16, 1} {
		if err := ctx.Err(); err != nil {
			return err
		}
		bounded, err := boundedShipRecord(original, prefixBytes)
		if errors.Is(err, errBoundedRecordTooLarge) {
			lastErr = err
			continue
		}
		if err != nil {
			return err
		}
		if err := shipBatch(factory, bounded); err != nil {
			lastErr = err
			if status, ok := output.HTTPStatusCode(err); ok && status == http.StatusRequestEntityTooLarge {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("bounded representation remained unaccepted; original remains pending: %w", lastErr)
}

// boundedShipRecord constructs a deliberately incomplete, detectable transport
// representation. It never changes the original line used for checkpointing or
// spool retention. It shortens only observed command or message content fields;
// an identity or finding envelope is never shortened.
func boundedShipRecord(original []byte, prefixBytes int) ([]byte, error) {
	if prefixBytes < 1 {
		return nil, errors.New("invalid bounded preview length")
	}
	if len(original) > maxShipOriginalBytes || len(original) == 0 || original[len(original)-1] != '\n' ||
		!utf8.Valid(original) || !isShippableRecord(original) {
		return nil, errors.New("oversized source is not a bounded complete UTF-8 JSON object")
	}
	fields, err := uniqueJSONObject(bytes.TrimSuffix(original, []byte{'\n'}))
	if err != nil {
		return nil, fmt.Errorf("oversized source: %w", err)
	}
	var recordType string
	if err := json.Unmarshal(fields["record_type"], &recordType); err != nil {
		return nil, errors.New("oversized source has no record_type")
	}
	var field, idField string
	var contentField bool
	switch recordType {
	case "event":
		idField = "event_id"
		if _, hasCommand := fields["command"]; hasCommand {
			field = "command"
		} else if _, hasContent := fields["content"]; hasContent {
			eventType, err := requiredShipString(fields, "event_type")
			if err != nil {
				return nil, err
			}
			if eventType != "prompt.user" && eventType != "message.assistant" && eventType != "message.reasoning" {
				return nil, fmt.Errorf("oversized event type %q has no supported content fallback", eventType)
			}
			field, contentField = "content", true
		} else {
			return nil, errors.New("oversized event has no supported variable field")
		}
	case "finding":
		field, idField = "observed_command", "finding_id"
		for _, required := range []string{"severity", "confidence"} {
			if _, err := requiredShipString(fields, required); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("oversized %q record cannot be represented without changing identity", recordType)
	}
	if _, err := requiredShipString(fields, idField); err != nil {
		return nil, err
	}
	fieldRaw, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("oversized source lacks %s", field)
	}
	var observed string
	if err := json.Unmarshal(fieldRaw, &observed); err != nil || observed == "" {
		return nil, fmt.Errorf("oversized source has invalid %s", field)
	}
	firstRune, _ := utf8.DecodeRuneInString(observed)
	if len(observed) <= utf8.RuneLen(firstRune) {
		return nil, fmt.Errorf("oversized %s has no shorten-able %s", recordType, field)
	}
	if contentField {
		var contentBytes int
		if err := json.Unmarshal(fields["content_bytes"], &contentBytes); err != nil || contentBytes <= 0 {
			return nil, errors.New("oversized content lacks valid content_bytes")
		}
		if raw, ok := fields["content_truncated"]; ok {
			var previous bool
			if err := json.Unmarshal(raw, &previous); err != nil {
				return nil, errors.New("oversized content has invalid content_truncated")
			}
		}
	}
	digest := sha256.Sum256(original)
	fieldDigest := sha256.Sum256([]byte(observed))
	marker, err := json.Marshal(struct {
		Version              int    `json:"version"`
		TruncatedField       string `json:"truncated_field"`
		OriginalRecordBytes  int    `json:"original_record_bytes"`
		OriginalRecordSHA256 string `json:"original_record_sha256"`
		OriginalFieldBytes   int    `json:"original_field_bytes"`
		OriginalFieldSHA256  string `json:"original_field_sha256"`
	}{1, field, len(original), hex.EncodeToString(digest[:]), len(observed), hex.EncodeToString(fieldDigest[:])})
	if err != nil {
		return nil, err
	}
	if recordType == "event" {
		evidence := make(map[string]json.RawMessage)
		if raw, ok := fields["evidence"]; ok {
			evidence, err = uniqueJSONObject(raw)
			if err != nil {
				return nil, fmt.Errorf("oversized source evidence: %w", err)
			}
		}
		if raw, present := fields["schema_version"]; present {
			var schemaVersion string
			if err := json.Unmarshal(raw, &schemaVersion); err != nil || schemaVersion == "" {
				return nil, errors.New("oversized event has invalid schema_version")
			}
			if schemaVersion == "0.4.0" {
				if _, err := requiredShipString(evidence, "artifact_type"); err != nil {
					return nil, err
				}
			}
		}
		if _, collision := evidence["transport"]; collision {
			return nil, errors.New("oversized source already has evidence.transport")
		}
		evidence["transport"] = marker
		fields["evidence"], err = json.Marshal(evidence)
	} else {
		var refs []json.RawMessage
		if err := json.Unmarshal(fields["evidence_refs"], &refs); err != nil || len(refs) == 0 {
			return nil, errors.New("oversized finding has no evidence_refs")
		}
		first, err := uniqueJSONObject(refs[0])
		if err != nil {
			return nil, fmt.Errorf("oversized finding evidence_refs[0]: %w", err)
		}
		if _, err := requiredShipString(first, "artifact_type"); err != nil {
			return nil, err
		}
		if _, collision := first["transport"]; collision {
			return nil, errors.New("oversized finding already has evidence_refs[0].transport")
		}
		first["transport"] = marker
		refs[0], err = json.Marshal(first)
		if err == nil {
			fields["evidence_refs"], err = json.Marshal(refs)
		}
	}
	if err != nil {
		return nil, err
	}
	end := min(prefixBytes, len(observed)-1)
	prefix := observed[:end]
	for !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	if prefix == "" {
		prefix = observed[:utf8.RuneLen(firstRune)]
	}
	fields[field], err = json.Marshal(prefix)
	if err != nil {
		return nil, err
	}
	if contentField {
		fields["content_truncated"] = json.RawMessage("true")
	}
	bounded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	bounded = append(bounded, '\n')
	if len(bounded) > maxBoundedShipRecordBytes {
		return nil, fmt.Errorf("oversized %s still exceeds %d-byte bounded transport limit: %w", recordType, maxBoundedShipRecordBytes, errBoundedRecordTooLarge)
	}
	return bounded, nil
}

func requiredShipString(fields map[string]json.RawMessage, key string) (string, error) {
	raw, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("oversized source lacks %s", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("oversized source has invalid %s", key)
	}
	return value, nil
}

// uniqueJSONObject rejects duplicate top-level names before a map projection
// could silently replace a type, identity, evidence field, or command.
func uniqueJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON object name")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate JSON field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON content")
	}
	return fields, nil
}

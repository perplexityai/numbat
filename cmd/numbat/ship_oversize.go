package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	// The hook accepts at most 4 MiB of input, but JSON escaping can expand
	// a native command beyond the former 8 MiB ship reader limit.
	maxShipOriginalBytes      = 32 << 20
	maxBoundedShipRecordBytes = 512 << 10
	boundedCommandPrefixBytes = 32 << 10
)

// boundedShipRecord constructs a deliberately incomplete, detectable transport
// representation. It never changes the original line used for checkpointing or
// spool retention. Only the two command fields with observed source reachability
// may be shortened; an identity or finding envelope is never shortened.
func boundedShipRecord(original []byte) ([]byte, error) {
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
	switch recordType {
	case "event":
		field, idField = "command", "event_id"
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
	commandRaw, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("oversized source lacks %s", field)
	}
	var command string
	if err := json.Unmarshal(commandRaw, &command); err != nil || command == "" {
		return nil, fmt.Errorf("oversized source has invalid %s", field)
	}
	if len(command) <= boundedCommandPrefixBytes {
		return nil, fmt.Errorf("oversized %s has no shorten-able %s", recordType, field)
	}
	evidence := make(map[string]json.RawMessage)
	if raw, ok := fields["evidence"]; ok {
		evidence, err = uniqueJSONObject(raw)
		if err != nil {
			return nil, fmt.Errorf("oversized source evidence: %w", err)
		}
	}
	if _, collision := evidence["transport"]; collision {
		return nil, errors.New("oversized source already has evidence.transport")
	}
	digest := sha256.Sum256(original)
	fieldDigest := sha256.Sum256([]byte(command))
	marker, err := json.Marshal(struct {
		Version              int    `json:"version"`
		TruncatedField       string `json:"truncated_field"`
		OriginalRecordBytes  int    `json:"original_record_bytes"`
		OriginalRecordSHA256 string `json:"original_record_sha256"`
		OriginalFieldBytes   int    `json:"original_field_bytes"`
		OriginalFieldSHA256  string `json:"original_field_sha256"`
	}{1, field, len(original), hex.EncodeToString(digest[:]), len(command), hex.EncodeToString(fieldDigest[:])})
	if err != nil {
		return nil, err
	}
	evidence["transport"] = marker
	fields["evidence"], err = json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	prefix := command[:boundedCommandPrefixBytes]
	for !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	fields[field], err = json.Marshal(prefix)
	if err != nil {
		return nil, err
	}
	bounded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	bounded = append(bounded, '\n')
	if len(bounded) > maxBoundedShipRecordBytes {
		return nil, fmt.Errorf("oversized %s still exceeds %d-byte bounded transport limit", recordType, maxBoundedShipRecordBytes)
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

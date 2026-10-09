package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/perplexityai/numbat/internal/model"
)

// limitRecord runs after content projection and envelope encoding. It only
// removes event bodies; typed metadata and capture completeness stay intact.
func limitRecord(fields map[string]json.RawMessage, line []byte, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("max-record-bytes must be non-negative")
	}
	if limit == 0 || len(line) <= limit {
		return line, nil
	}
	tooLarge := fmt.Errorf("record exceeds max-record-bytes: %d bytes, limit %d; cannot fit without removing metadata", len(line), limit)
	if string(fields["record_type"]) != `"event"` || string(fields["schema_version"]) != `"`+model.SchemaVersion+`"` {
		return nil, tooLarge
	}

	var omitted []string
	if raw, ok := fields["content_omitted"]; ok {
		if err := json.Unmarshal(raw, &omitted); err != nil || len(omitted) == 0 || len(omitted) > 3 {
			return nil, errors.New("invalid content_omitted")
		}
	}
	names := []string{"content", "tool_input", "tool_result"}
	for i, name := range omitted {
		if !slices.Contains(names, name) || slices.Contains(omitted[:i], name) || fields[name] != nil {
			return nil, errors.New("invalid content_omitted")
		}
	}
	slices.SortStableFunc(names, func(a, b string) int { return len(fields[b]) - len(fields[a]) })
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			continue
		}
		delete(fields, name)
		omitted = append(omitted, name)
		fields["content_omitted"], _ = json.Marshal(omitted)
		reduced, err := marshalRecordJSON(fields)
		if err != nil {
			return nil, err
		}
		reduced = append(reduced, '\n')
		if len(reduced) <= limit {
			return reduced, nil
		}
	}
	return nil, tooLarge
}

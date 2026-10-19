package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

func TestPublishedRecordSchemasStayCurrent(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "schema", "v"+model.SchemaVersion)
	cases := map[string]struct {
		recordType string
		fields     map[string]struct{}
	}{
		"event-record.schema.json": {
			recordType: RecordEvent,
			fields:     withEnvelope(jsonFields(reflect.TypeOf(model.Event{})), true),
		},
		"finding-record.schema.json": {
			recordType: RecordFinding,
			fields:     withEnvelope(jsonFields(reflect.TypeOf(model.Finding{})), true),
		},
		"enforcement-record.schema.json": {
			recordType: RecordEnforcement,
			fields:     withEnvelope(jsonFields(reflect.TypeOf(model.EnforcementDecision{})), true),
		},
		"assessment-record.schema.json": {
			recordType: RecordAssessment,
			fields:     withEnvelope(jsonFields(reflect.TypeOf(DecisionAssessment{})), true),
		},
		"indicator-record.schema.json": {
			recordType: RecordIndicator,
			fields:     withEnvelope(jsonFields(reflect.TypeOf(Indicator{})), false),
		},
		"scan-summary-record.schema.json": {
			recordType: RecordScanSummary,
			fields:     withEnvelope(jsonFields(reflect.TypeOf(ScanSummary{})), false),
		},
		"diagnostic-record.schema.json": {
			recordType: RecordDiagnostic,
			fields:     jsonFields(reflect.TypeOf(Diagnostic{})),
		},
	}
	for file, tc := range cases {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				AdditionalProperties *bool    `json:"additionalProperties"`
				Required             []string `json:"required"`
				Properties           map[string]struct {
					Const string `json:"const"`
				} `json:"properties"`
				Defs map[string]struct {
					AdditionalProperties *bool                      `json:"additionalProperties"`
					Required             []string                   `json:"required"`
					Properties           map[string]json.RawMessage `json:"properties"`
				} `json:"$defs"`
			}
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatalf("invalid JSON schema: %v", err)
			}
			if got := schema.Properties["schema_version"].Const; got != model.SchemaVersion {
				t.Fatalf("schema_version const = %q, want %q", got, model.SchemaVersion)
			}
			if got := schema.Properties["record_type"].Const; got != tc.recordType {
				t.Fatalf("record_type const = %q, want %q", got, tc.recordType)
			}
			if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
				t.Fatal("published record schemas must explicitly reject unknown fields")
			}
			if !containsString(schema.Required, "endpoint") {
				t.Fatal("published record schemas must require endpoint")
			}
			assertEndpointSchema(t, schema.Defs["endpoint"])
			for field := range tc.fields {
				if _, ok := schema.Properties[field]; !ok {
					t.Fatalf("schema missing emitted field %q", field)
				}
			}
			for field := range schema.Properties {
				if _, ok := tc.fields[field]; !ok {
					t.Fatalf("schema documents non-emitted field %q", field)
				}
			}
		})
	}

	raw, err := os.ReadFile(filepath.Join(dir, "record-stream.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var streamSchema struct {
		OneOf []struct {
			Ref string `json:"$ref"`
		} `json:"oneOf"`
	}
	if err := json.Unmarshal(raw, &streamSchema); err != nil {
		t.Fatalf("invalid record-stream schema JSON: %v", err)
	}
	refs := make(map[string]struct{}, len(streamSchema.OneOf))
	for _, entry := range streamSchema.OneOf {
		refs[entry.Ref] = struct{}{}
	}
	for file := range cases {
		if _, ok := refs[file]; !ok {
			t.Errorf("record-stream schema does not reference %s", file)
		}
	}
}

func TestPublishedSchemaReferencesStayLocal(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "schema", "v"+model.SchemaVersion)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			ID    string `json:"$id"`
			OneOf []struct {
				Ref string `json:"$ref"`
			} `json:"oneOf"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("invalid JSON schema %s: %v", entry.Name(), err)
		}
		if schema.ID != "" {
			t.Fatalf("%s: $id must be omitted so sibling references resolve from the schema directory", entry.Name())
		}
		for _, ref := range schema.OneOf {
			if ref.Ref == "" || filepath.Base(ref.Ref) != ref.Ref {
				t.Fatalf("%s has non-local reference %q", entry.Name(), ref.Ref)
			}
			if _, err := os.Stat(filepath.Join(dir, ref.Ref)); err != nil {
				t.Fatalf("%s reference %q: %v", entry.Name(), ref.Ref, err)
			}
		}
	}
}

func TestFindingSchemaTimeContract(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "schema", "v"+model.SchemaVersion, "finding-record.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Format    string `json:"format"`
			Pattern   string `json:"pattern"`
			MinLength int    `json:"minLength"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if containsString(schema.Required, "timestamp") {
		t.Fatal("finding activity timestamp must remain optional")
	}
	if !containsString(schema.Required, "detected_at") {
		t.Fatal("finding detected_at must be required")
	}
	timestamp := schema.Properties["timestamp"]
	if timestamp.Format != "date-time" || timestamp.Pattern == "" || timestamp.MinLength != 1 {
		t.Fatalf("timestamp schema = %+v, want non-empty date-time", timestamp)
	}
	detectedAt := schema.Properties["detected_at"]
	if detectedAt.Format != "date-time" || detectedAt.Pattern == "" || detectedAt.MinLength != 1 {
		t.Fatalf("detected_at schema = %+v, want non-empty UTC date-time", detectedAt)
	}
	assertTimeContract(t, "timestamp", timestamp.Pattern,
		[]string{"2026-06-02T10:00:00Z", "2026-06-02t10:00:00.123+05:30"},
		[]string{"", "not-a-time", "2026-06-02T1:00:00Z", "2026-06-02T10:00:00,1Z", "2026-06-02T10:00:00+24:00", "2026-02-30T10:00:00Z", "2026-04-31T10:00:00Z"},
	)
	assertTimeContract(t, "detected_at", detectedAt.Pattern,
		[]string{"2026-06-02T10:00:00Z", "2026-06-02T10:00:00.123Z"},
		[]string{"", "not-a-time", "2026-06-02t10:00:00z", "2026-06-02T10:00:00+00:00", "2026-02-30T10:00:00Z", "2026-04-31T10:00:00Z"},
	)
}

func assertTimeContract(t *testing.T, field, pattern string, valid, invalid []string) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	accepts := func(value string) bool {
		if !re.MatchString(value) {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, strings.ToUpper(value))
		return err == nil
	}
	for _, value := range valid {
		if !accepts(value) {
			t.Errorf("%s schema rejected valid value %q", field, value)
		}
	}
	for _, value := range invalid {
		if accepts(value) {
			t.Errorf("%s schema accepted invalid value %q", field, value)
		}
	}
}

func assertEndpointSchema(
	t *testing.T,
	schema struct {
		AdditionalProperties *bool                      `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	},
) {
	t.Helper()
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatal("endpoint schema must reject unknown fields")
	}
	want := jsonFields(reflect.TypeOf(Endpoint{}))
	for field := range want {
		if _, ok := schema.Properties[field]; !ok {
			t.Fatalf("endpoint schema missing field %q", field)
		}
	}
	for field := range schema.Properties {
		if _, ok := want[field]; !ok {
			t.Fatalf("endpoint schema documents non-emitted field %q", field)
		}
	}
	for _, field := range []string{"hostname", "os", "arch", "username", "uid"} {
		if !containsString(schema.Required, field) {
			t.Fatalf("endpoint schema must require %q", field)
		}
	}
	if containsString(schema.Required, "device_id") {
		t.Fatal("endpoint.device_id must remain optional")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func jsonFields(typ reflect.Type) map[string]struct{} {
	fields := make(map[string]struct{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if typ.Field(i).Anonymous && name == "" && typ.Field(i).Type.Kind() == reflect.Struct {
			for embedded := range jsonFields(typ.Field(i).Type) {
				fields[embedded] = struct{}{}
			}
		}
		if name != "" && name != "-" {
			fields[name] = struct{}{}
		}
	}
	return fields
}

func withEnvelope(fields map[string]struct{}, hasSchemaVersion bool) map[string]struct{} {
	fields["record_type"] = struct{}{}
	fields["run_id"] = struct{}{}
	fields["endpoint"] = struct{}{}
	if !hasSchemaVersion {
		fields["schema_version"] = struct{}{}
	}
	return fields
}

package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var expectedCELFieldTypes = map[string]string{
	"source_agent":              "string",
	"source_type":               "string",
	"timestamp":                 "string",
	"project_path":              "string",
	"session_id":                "string",
	"actor":                     "string",
	"event_type":                "string",
	"tool_name":                 "string",
	"command":                   "string",
	"file_path":                 "string",
	"decision":                  "string",
	"tool_call_id":              "string",
	"exit_code":                 "int|null",
	"duration_ms":               "int|null",
	"approval_required":         "bool|null",
	"approval_decision":         "string",
	"approval_reason":           "string",
	"diff_sha256":               "string",
	"diff_bytes":                "int",
	"mcp_server":                "string",
	"mcp_tool":                  "string",
	"url":                       "string",
	"model":                     "string",
	"model_provider":            "string",
	"git_branch":                "string",
	"entrypoint":                "string",
	"cli_version":               "string",
	"sub_agent":                 "string",
	"content_preview":           "string",
	"content_preview_truncated": "bool",
	"content":                   "string",
	"content_bytes":             "int",
	"content_truncated":         "bool",
	"tags":                      "list(string)",
	"confidence":                "string",
}

func TestIsValidEventType(t *testing.T) {
	if !IsValidEventType(EventCommandExec) {
		t.Fatalf("command.exec should be valid")
	}
	if IsValidEventType(EventType("bogus.type")) {
		t.Fatalf("bogus.type should be invalid")
	}
}

func TestCELActivationMirrorsJSON(t *testing.T) {
	ev := Event{
		EventType: EventCommandExec,
		Command:   "cat .env",
		FilePath:  "/x/.env",
		Tags:      []string{"secret_file_read"},
	}
	act := ev.CELActivation()
	evMap, ok := act["event"].(map[string]any)
	if !ok {
		t.Fatalf("activation missing event map")
	}
	if evMap["event_type"] != "command.exec" {
		t.Fatalf("event_type = %v, want command.exec", evMap["event_type"])
	}
	if evMap["command"] != "cat .env" {
		t.Fatalf("command = %v", evMap["command"])
	}
	tags, ok := evMap["tags"].([]any)
	if !ok || len(tags) != 1 || tags[0] != "secret_file_read" {
		t.Fatalf("tags = %v", evMap["tags"])
	}
}

// celView exposes exit_code as the int when a command.result carries one, and as
// nil (not a zero sentinel) when absent, so a real exit 0 stays distinct from "no
// code". The key is ALWAYS present (nil when unset), which is why rules must test
// `event.exit_code != null`, not has(event.exit_code); the engine-level contract
// is proven in internal/rule (TestEngineExitCodeNullContract).
func TestCELViewExitCode(t *testing.T) {
	code := 2
	withCode := Event{EventType: EventCommandResult, ExitCode: &code}.CELActivation()["event"].(map[string]any)
	if withCode["exit_code"] != 2 {
		t.Errorf("exit_code = %v, want 2", withCode["exit_code"])
	}

	zero := 0
	withZero := Event{EventType: EventCommandResult, ExitCode: &zero}.CELActivation()["event"].(map[string]any)
	if withZero["exit_code"] != 0 {
		t.Errorf("exit_code = %v, want 0 (a real exit, not absent)", withZero["exit_code"])
	}

	absent := Event{EventType: EventCommandResult}.CELActivation()["event"].(map[string]any)
	if absent["exit_code"] != nil {
		t.Errorf("exit_code = %v, want nil when unset", absent["exit_code"])
	}
	if _, present := absent["exit_code"]; !present {
		t.Errorf("exit_code key missing from celView; rules reference it by name")
	}
}

// celView exposes duration_ms as the int64 when a command.result carries one, and
// as nil when absent, so a real 0ms stays distinct from "no duration". Like
// exit_code, the key is always present and rules test `event.duration_ms != null`.
func TestCELViewDurationMs(t *testing.T) {
	d := int64(1500)
	withDur := Event{EventType: EventCommandResult, DurationMs: &d}.CELActivation()["event"].(map[string]any)
	if withDur["duration_ms"] != int64(1500) {
		t.Errorf("duration_ms = %v, want 1500", withDur["duration_ms"])
	}

	zero := int64(0)
	withZero := Event{EventType: EventCommandResult, DurationMs: &zero}.CELActivation()["event"].(map[string]any)
	if withZero["duration_ms"] != int64(0) {
		t.Errorf("duration_ms = %v, want 0 (a real 0ms, not absent)", withZero["duration_ms"])
	}

	absent := Event{EventType: EventCommandResult}.CELActivation()["event"].(map[string]any)
	if absent["duration_ms"] != nil {
		t.Errorf("duration_ms = %v, want nil when unset", absent["duration_ms"])
	}
	if _, present := absent["duration_ms"]; !present {
		t.Errorf("duration_ms key missing from celView; rules reference it by name")
	}
}

// celView exposes approval_required as the bool when a permission.* event records
// one, and as nil when absent, so an explicit "not required" (false) stays
// distinct from "no gate recorded". Rules test `event.approval_required != null`.
func TestCELViewApprovalRequired(t *testing.T) {
	yes := true
	withReq := Event{EventType: EventPermissionRequested, ApprovalRequired: &yes}.CELActivation()["event"].(map[string]any)
	if withReq["approval_required"] != true {
		t.Errorf("approval_required = %v, want true", withReq["approval_required"])
	}

	no := false
	withFalse := Event{EventType: EventPermissionRequested, ApprovalRequired: &no}.CELActivation()["event"].(map[string]any)
	if withFalse["approval_required"] != false {
		t.Errorf("approval_required = %v, want false (an explicit not-required, not absent)", withFalse["approval_required"])
	}

	absent := Event{EventType: EventPermissionRequested}.CELActivation()["event"].(map[string]any)
	if absent["approval_required"] != nil {
		t.Errorf("approval_required = %v, want nil when unset", absent["approval_required"])
	}
	if _, present := absent["approval_required"]; !present {
		t.Errorf("approval_required key missing from celView; rules reference it by name")
	}
}

func TestHashContentStable(t *testing.T) {
	a := HashContent([]byte("hello"))
	b := HashContent([]byte("hello"))
	if a != b {
		t.Fatalf("hash not stable: %s != %s", a, b)
	}
	if a == HashContent([]byte("world")) {
		t.Fatalf("distinct inputs hashed equal")
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex len = %d, want 64", len(a))
	}
}

func TestHashPathNormalizes(t *testing.T) {
	if HashPath("/a/b") != HashPath("/a/b/") {
		t.Fatalf("trailing slash changed hash")
	}
	if HashPath("/a/b") != HashPath("  /a/b  ") {
		t.Fatalf("surrounding whitespace changed hash")
	}
	if HashPath("/a/b") == HashPath("/a/c") {
		t.Fatalf("distinct paths hashed equal")
	}
	if got := HashPath("/a"); got[:7] != "sha256:" {
		t.Fatalf("missing sha256 prefix: %s", got)
	}
	// Logically-equal paths with . / .. / duplicate separators collide.
	if HashPath("/a/b") != HashPath("/a/./b") {
		t.Fatalf(". segment changed hash")
	}
	if HashPath("/a/b") != HashPath("/a//b") {
		t.Fatalf("duplicate separator changed hash")
	}
	if HashPath("/a/b") != HashPath("/a/x/../b") {
		t.Fatalf(".. segment changed hash")
	}
	if HashPath(`C:\Users\dev\repo`) != HashPath("C:/Users/dev/repo") {
		t.Fatalf("Windows path separators changed hash")
	}
	if got := HashPath("  "); got != "" {
		t.Fatalf("HashPath(blank) = %q, want empty", got)
	}
}

func TestNormalizePathsKeepsEvidenceHostNative(t *testing.T) {
	ev := Event{
		ProjectPath: `C:\Users\dev\repo`,
		FilePath:    `C:\Users\dev\repo\.env`,
		Evidence:    Evidence{LocalPath: `C:\Users\dev\.codex\sessions\s.jsonl`},
	}.NormalizePaths()
	if ev.ProjectPath != "C:/Users/dev/repo" || ev.FilePath != "C:/Users/dev/repo/.env" {
		t.Fatalf("normalized paths = %q, %q", ev.ProjectPath, ev.FilePath)
	}
	if ev.Evidence.LocalPath != `C:\Users\dev\.codex\sessions\s.jsonl` {
		t.Fatalf("evidence.local_path was changed: %q", ev.Evidence.LocalPath)
	}
}

func TestModelVocabularyValidators(t *testing.T) {
	if !IsValidSourceAgent(AgentClaudeCode) || !IsValidSourceAgent(AgentUnknown) || IsValidSourceAgent("") || IsValidSourceAgent("claude") {
		t.Fatalf("IsValidSourceAgent wrong")
	}
	if !IsValidConfidence(ConfidenceHigh) || IsValidConfidence("bogus") {
		t.Fatalf("IsValidConfidence wrong")
	}
	if !IsValidSourceType(SourceArtifact) || IsValidSourceType("bogus") {
		t.Fatalf("IsValidSourceType wrong")
	}
	if !IsValidActor(ActorTool) || IsValidActor("") || IsValidActor("bogus") {
		t.Fatalf("IsValidActor wrong")
	}
	// Empty decision is valid (DecisionUnknown); an unknown string is not.
	if !IsValidDecision(DecisionDenied) || !IsValidDecision("") || IsValidDecision("bogus") {
		t.Fatalf("IsValidDecision wrong")
	}
	if !IsCELField("file_path") || IsCELField("file_pathh") {
		t.Fatalf("IsCELField wrong")
	}
}

func TestCELFieldTypesCoverCompilerFields(t *testing.T) {
	if len(expectedCELFieldTypes) != len(celFields) {
		t.Fatalf("documented %d field types, want %d", len(expectedCELFieldTypes), len(celFields))
	}
	for name := range celFields {
		if expectedCELFieldTypes[name] == "" {
			t.Fatalf("CEL field %q has no documented type", name)
		}
	}
	for name := range expectedCELFieldTypes {
		if !IsCELField(name) {
			t.Fatalf("documented unknown CEL field %q", name)
		}
	}
}

func TestRuleDocsListCELFieldSet(t *testing.T) {
	raw, err := os.ReadFile("../../docs/rules.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for name, typ := range expectedCELFieldTypes {
		if !strings.Contains(doc, "`event."+name+"`") || !strings.Contains(doc, typ) {
			t.Fatalf("rules guide missing CEL field %s (%s)", name, typ)
		}
	}
}

func TestPublishedSchemasListSourceAgentVocabulary(t *testing.T) {
	want := make([]string, 0, len(sourceAgents))
	for agent := range sourceAgents {
		want = append(want, agent)
	}
	sort.Strings(want)

	dir := filepath.Join("..", "..", "docs", "schema", "v"+SchemaVersion)
	for _, file := range []string{"event-record.schema.json", "finding-record.schema.json", "indicator-record.schema.json"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			got := append([]string(nil), schema.Properties["source_agent"].Enum...)
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("source_agent enum = %v, want %v", got, want)
			}
		})
	}
}

func TestMergeTags(t *testing.T) {
	got := MergeTags([]string{"b", "a", ""}, []string{"a", "c"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %v, want %v", got, want)
	}
}

func TestIsValidSeverity(t *testing.T) {
	for _, s := range []string{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !IsValidSeverity(s) {
			t.Fatalf("%q should be valid", s)
		}
	}
	if IsValidSeverity("catastrophic") {
		t.Fatalf("catastrophic should be invalid")
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	ev := Event{
		SchemaVersion: SchemaVersion,
		EventID:       "e1",
		SourceAgent:   AgentClaudeCode,
		SourceType:    SourceArtifact,
		EventType:     EventFileRead,
		FilePath:      "/x/.env",
		Confidence:    ConfidenceHigh,
		Evidence:      Evidence{ArtifactType: "claude_jsonl", LocalPath: "/x", Line: 42},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ev, got) {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", ev, got)
	}
}

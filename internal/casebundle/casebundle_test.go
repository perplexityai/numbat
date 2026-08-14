package casebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// jline marshals one NDJSON record line for a test stream.
func jline(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ref is a finding evidence reference / event evidence pointing at path:line.
func ref(path string, line int) map[string]any {
	return map[string]any{"artifact_type": "claude_jsonl", "local_path": path, "line": line}
}

func sha256StringHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func finding(t *testing.T, id, caseID, ts string, refs ...map[string]any) string {
	return findingWithCitedEvents(t, id, caseID, ts, []string{"event-for-" + id}, refs...)
}

func findingWithCitedEvents(t *testing.T, id, caseID, ts string, cited []string, refs ...map[string]any) string {
	m := map[string]any{
		"record_type": "finding", "schema_version": "0.3.0",
		"finding_id": id, "case_id": caseID, "timestamp": ts, "detected_at": "2026-06-10T12:00:00Z",
		"rule_id": "r1", "rule_version": "1.0", "severity": "high", "source_agent": "claude-code", "source_type": sourceTypeForRefs(refs),
		"title": "t", "evidence_refs": refs, "redacted": true, "confidence": "high",
	}
	if len(cited) != 0 {
		m["cited_event_ids"] = cited
	}
	return jline(t, m)
}

func sourceTypeForRefs(refs []map[string]any) string {
	if len(refs) == 0 {
		return "artifact"
	}
	switch refs[0]["artifact_type"] {
	case "hook":
		return "hook"
	case "otel":
		return "otel"
	default:
		return "artifact"
	}
}

func event(t *testing.T, id, ts string, ev map[string]any) string {
	return eventWithSourceType(t, id, ts, "artifact", ev)
}

func eventWithSourceType(t *testing.T, id, ts, sourceType string, ev map[string]any) string {
	return jline(t, map[string]any{
		"record_type": "event", "schema_version": "0.3.0",
		"event_id": id, "timestamp": ts, "source_agent": "claude-code",
		"source_type": sourceType, "event_type": "file.read",
		"confidence": "high", "evidence": ev,
	})
}

// writeStream writes one source record-stream file from lines.
func writeStream(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "records.ndjson")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sampleStream is the canonical fixture: two findings for case-1 (one line
// duplicated), one finding for another case, two cited events, one uncited
// event, and a terminal summary record.
func sampleStream(t *testing.T, artifact string) string {
	t.Helper()
	f1 := findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:02Z", []string{"ev-1"}, ref(artifact, 2))
	f2 := findingWithCitedEvents(t, "fnd-b", "case-1", "2026-06-02T10:00:01Z", []string{"ev-2"}, ref(artifact, 9))
	other := findingWithCitedEvents(t, "fnd-c", "case-2", "2026-06-02T10:00:03Z", []string{"ev-3"}, ref(artifact, 5))
	e1 := event(t, "ev-1", "2026-06-02T10:00:00Z", ref(artifact, 2))
	e2 := event(t, "ev-2", "2026-06-02T10:00:01Z", ref(artifact, 9))
	uncited := event(t, "ev-3", "2026-06-02T10:00:02Z", ref(artifact, 5))
	summary := jline(t, map[string]any{"record_type": "scan_summary", "status": "complete"})
	return writeStream(t, e1, f1, e2, f2, f1, uncited, other, summary)
}

func buildOpts(src ...string) Options {
	return Options{
		CaseID:  "case-1",
		Sources: src,
		Now:     time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	}
}

func mustBuild(t *testing.T, opts Options) Result {
	t.Helper()
	res, err := Build(opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return res
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(b), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func TestBuildBundleShape(t *testing.T) {
	src := sampleStream(t, "/a/t.jsonl")
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)

	if res.Findings != 2 || res.Events != 2 || res.EvidenceFiles != 0 {
		t.Fatalf("result = %+v, want 2 findings, 2 events, 0 evidence", res)
	}
	// Findings: case-filtered, deduplicated, sorted by timestamp (fnd-b is
	// earlier), each line byte-identical to its source line.
	fl := readLines(t, filepath.Join(opts.Out, "findings.ndjson"))
	if len(fl) != 2 || !strings.Contains(fl[0], "fnd-b") || !strings.Contains(fl[1], "fnd-a") {
		t.Fatalf("findings.ndjson = %v", fl)
	}
	if strings.Contains(strings.Join(fl, ""), "fnd-c") {
		t.Fatal("other case's finding leaked into the bundle")
	}
	// Events: cited only, in timestamp order.
	el := readLines(t, filepath.Join(opts.Out, "events.ndjson"))
	if len(el) != 2 || !strings.Contains(el[0], "ev-1") || !strings.Contains(el[1], "ev-2") {
		t.Fatalf("events.ndjson = %v", el)
	}
	if strings.Contains(strings.Join(el, ""), "ev-3") {
		t.Fatal("uncited event leaked into the bundle")
	}

	var m Manifest
	b, err := os.ReadFile(filepath.Join(opts.Out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.CaseID != "case-1" || m.SchemaVersion != "0.3.0" || m.Tool != "numbat" || m.ToolVersion == "" || m.EvidenceMode != "none" {
		t.Fatalf("manifest = %+v", m)
	}
	if m.CreatedAt != "2026-06-10T12:00:00Z" {
		t.Fatalf("created_at = %q, want injected now", m.CreatedAt)
	}
	if len(m.Files) != 2 || m.Files[0].Path != "events.ndjson" || m.Files[1].Path != "findings.ndjson" {
		t.Fatalf("manifest files = %+v", m.Files)
	}
	for _, mf := range m.Files {
		if mf.SHA256 == "" || mf.Records != 2 {
			t.Fatalf("manifest entry = %+v", mf)
		}
	}

	v, err := Verify(opts.Out)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK() || v.CaseID != "case-1" {
		t.Fatalf("fresh bundle must verify: %+v", v)
	}
}

func TestBuildCarriesCaseEnforcementDecisions(t *testing.T) {
	f := findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:01Z", []string{"ev-1"}, map[string]any{"artifact_type": "hook"})
	e := eventWithSourceType(t, "ev-1", "2026-06-02T10:00:00Z", "hook", map[string]any{"artifact_type": "hook"})
	o := jline(t, map[string]any{
		"record_type": "enforcement", "schema_version": "0.3.0",
		"decision_id": "enf-0123456789abcdef01234567", "case_id": "case-1",
		"timestamp": "2026-06-02T10:00:02Z", "decision": "deny",
		"mode": "enforce", "reason": "enforce_rule_match", "source_agent": "claude-code",
		"source_type": "hook", "action_event_ids": []string{"ev-1"},
		"finding_ids": []string{"fnd-a"}, "rule_ids": []string{"test.rule"},
		"deny_rule_id": "test.rule", "deny_rule_version": "1.0",
	})
	src := writeStream(t, e, f, o)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)
	if res.Enforcements != 1 {
		t.Fatalf("enforcements = %d, want 1", res.Enforcements)
	}
	lines := readLines(t, filepath.Join(opts.Out, "enforcements.ndjson"))
	if len(lines) != 1 || lines[0] != o {
		t.Fatalf("enforcements.ndjson = %v", lines)
	}
	verified, err := Verify(opts.Out)
	if err != nil || !verified.OK() {
		t.Fatalf("verify = %+v, err = %v", verified, err)
	}
}

func TestPublishBundleDoesNotExposePartialDestination(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "case.numbat")
	errSentinel := fmt.Errorf("write failed")
	err := publishBundle(out, func(stage string) error {
		if err := os.WriteFile(filepath.Join(stage, "partial.ndjson"), []byte("partial\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return errSentinel
	})
	if err == nil || !strings.Contains(err.Error(), errSentinel.Error()) {
		t.Fatalf("publishBundle error = %v, want %v", err, errSentinel)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("partial destination exists after failure: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(root, ".numbat-case-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staging directories remain after failure: %v", matches)
	}
}

func TestBuildBundleKeepsOnlyCitedOTelEvent(t *testing.T) {
	thinOTel := map[string]any{"artifact_type": "otel"}
	src := writeStream(t,
		event(t, "otel-1", "2026-06-02T10:00:00Z", thinOTel),
		event(t, "otel-2", "2026-06-02T10:00:01Z", thinOTel),
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:02Z", []string{"otel-2"}, thinOTel),
	)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	mustBuild(t, opts)

	el := readLines(t, filepath.Join(opts.Out, "events.ndjson"))
	if len(el) != 1 || !strings.Contains(el[0], "\"event_id\":\"otel-2\"") {
		t.Fatalf("events.ndjson = %v, want only cited otel-2", el)
	}
}

func TestBuildBundleKeepsOnlyCitedHookEvent(t *testing.T) {
	thinHook := map[string]any{"artifact_type": "hook"}
	src := writeStream(t,
		event(t, "hook-1", "2026-06-02T10:00:00Z", thinHook),
		event(t, "hook-2", "2026-06-02T10:00:01Z", thinHook),
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:02Z", []string{"hook-1"}, thinHook),
	)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	mustBuild(t, opts)

	el := readLines(t, filepath.Join(opts.Out, "events.ndjson"))
	if len(el) != 1 || !strings.Contains(el[0], "\"event_id\":\"hook-1\"") {
		t.Fatalf("events.ndjson = %v, want only cited hook-1", el)
	}
}

func TestBuildBundleKeepsOnlyCitedArtifactSibling(t *testing.T) {
	evidence := ref("/a/session.jsonl", 7)
	src := writeStream(t,
		event(t, "artifact-1", "2026-06-02T10:00:00Z", evidence),
		event(t, "artifact-2", "2026-06-02T10:00:01Z", evidence),
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:02Z", []string{"artifact-2"}, evidence),
	)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	mustBuild(t, opts)

	events := readLines(t, filepath.Join(opts.Out, "events.ndjson"))
	if len(events) != 1 || !strings.Contains(events[0], `"event_id":"artifact-2"`) {
		t.Fatalf("events.ndjson = %v, want only the exactly cited artifact event", events)
	}
}

func TestBuildBundleDoesNotGuessUncitedLiveEvents(t *testing.T) {
	thinOTel := map[string]any{"artifact_type": "otel"}
	thinHook := map[string]any{"artifact_type": "hook"}
	src := writeStream(t,
		eventWithSourceType(t, "otel-1", "2026-06-02T10:00:00Z", "otel", thinOTel),
		eventWithSourceType(t, "hook-1", "2026-06-02T10:00:01Z", "hook", thinHook),
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:02Z", nil, thinOTel),
		findingWithCitedEvents(t, "fnd-b", "case-1", "2026-06-02T10:00:03Z", nil, thinHook),
	)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)

	el := readLines(t, filepath.Join(opts.Out, "events.ndjson"))
	if len(el) != 0 {
		t.Fatalf("events.ndjson = %v, want no guessed live events", el)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "no cited_event_ids") {
		t.Fatalf("warnings = %v, want unresolved live-citation warning", res.Warnings)
	}
}

func TestBuildBundleMixedUncitedAndCitedLiveEvents(t *testing.T) {
	thinOTel := map[string]any{"artifact_type": "otel"}
	thinHook := map[string]any{"artifact_type": "hook"}
	uncited := writeStream(t,
		eventWithSourceType(t, "otel-uncited", "2026-06-02T10:00:00Z", "otel", thinOTel),
		findingWithCitedEvents(t, "fnd-uncited", "case-1", "2026-06-02T10:00:01Z", nil, thinOTel),
	)
	current := writeStream(t,
		eventWithSourceType(t, "hook-1", "2026-06-02T10:00:02Z", "hook", thinHook),
		eventWithSourceType(t, "hook-2", "2026-06-02T10:00:03Z", "hook", thinHook),
		findingWithCitedEvents(t, "fnd-new", "case-1", "2026-06-02T10:00:04Z", []string{"hook-1"}, thinHook),
	)
	opts := buildOpts(uncited, current)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)

	el := readLines(t, filepath.Join(opts.Out, "events.ndjson"))
	if len(el) != 1 {
		t.Fatalf("events.ndjson = %v, want only the cited hook event", el)
	}
	if !strings.Contains(el[0], "\"event_id\":\"hook-1\"") {
		t.Fatalf("events.ndjson = %v, want hook-1", el)
	}
	joined := strings.Join(el, "\n")
	if strings.Contains(joined, "\"event_id\":\"hook-2\"") || strings.Contains(joined, "\"event_id\":\"otel-uncited\"") {
		t.Fatalf("events.ndjson = %v, uncited live event leaked into the bundle", el)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "no cited_event_ids") {
		t.Fatalf("warnings = %v, want unresolved live-citation warning", res.Warnings)
	}
}

func TestBuildRejectsConflictingDuplicateFindingContent(t *testing.T) {
	thinOTel := map[string]any{"artifact_type": "otel"}
	first := findingWithCitedEvents(t, "fnd-x", "case-1", "2026-06-02T10:00:02Z", []string{"otel-1"}, thinOTel)
	var changed map[string]any
	if err := json.Unmarshal([]byte(first), &changed); err != nil {
		t.Fatal(err)
	}
	changed["timestamp"] = "2026-06-02T10:00:03Z"
	opts := buildOpts(writeStream(t,
		eventWithSourceType(t, "otel-1", "2026-06-02T10:00:00Z", "otel", thinOTel),
		first,
		jline(t, changed),
	))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	_, err := Build(opts)
	if err == nil || !strings.Contains(err.Error(), `duplicate finding "fnd-x" has conflicting content`) {
		t.Fatalf("Build error = %v, want conflicting-content rejection", err)
	}
	if _, err := os.Lstat(opts.Out); !os.IsNotExist(err) {
		t.Fatalf("failed build left output at %q: %v", opts.Out, err)
	}
}

func TestBuildDeduplicatesFindingAcrossDetectionRuns(t *testing.T) {
	evidence := ref("/a/session.jsonl", 1)
	first := findingWithCitedEvents(t, "fnd-x", "case-1", "2026-06-02T10:00:00Z", []string{"ev-1"}, evidence)
	var second map[string]any
	if err := json.Unmarshal([]byte(first), &second); err != nil {
		t.Fatal(err)
	}
	second["run_id"] = "run-2"
	second["detected_at"] = "2026-06-11T12:00:00Z"
	opts := buildOpts(writeStream(t, event(t, "ev-1", "2026-06-02T10:00:00Z", evidence), first, jline(t, second)))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	if res := mustBuild(t, opts); res.Findings != 1 {
		t.Fatalf("findings = %d, want one deduplicated finding", res.Findings)
	}
}

func TestBuildRejectsDuplicateFindingWithChangedRuleVersion(t *testing.T) {
	evidence := ref("/a/session.jsonl", 1)
	first := findingWithCitedEvents(t, "fnd-x", "case-1", "2026-06-02T10:00:00Z", []string{"ev-1"}, evidence)
	var changed map[string]any
	if err := json.Unmarshal([]byte(first), &changed); err != nil {
		t.Fatal(err)
	}
	changed["rule_version"] = "1.1"
	opts := buildOpts(writeStream(t, first, jline(t, changed)))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	_, err := Build(opts)
	if err == nil || !strings.Contains(err.Error(), `duplicate finding "fnd-x" has conflicting content`) {
		t.Fatalf("Build error = %v, want changed-rule-version rejection", err)
	}
}

func TestBuildRejectsConflictingDuplicateEvent(t *testing.T) {
	evidence := ref("/a/session.jsonl", 1)
	src := writeStream(t,
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:02Z", []string{"ev-1"}, evidence),
		event(t, "ev-1", "2026-06-02T10:00:00Z", evidence),
		event(t, "ev-1", "2026-06-02T10:00:01Z", evidence),
	)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	_, err := Build(opts)
	if err == nil || !strings.Contains(err.Error(), `duplicate event "ev-1" has conflicting content`) {
		t.Fatalf("Build error = %v, want conflicting-event rejection", err)
	}
}

func TestBuildWarnsWhenCitedEventsAreMissing(t *testing.T) {
	evidence := ref("/a/session.jsonl", 1)
	opts := buildOpts(writeStream(t,
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z", []string{"missing-1", "missing-2"}, evidence),
	))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "2 cited event(s) were not found") {
		t.Fatalf("warnings = %v, want missing-cited-events warning", res.Warnings)
	}
}

func TestBuildDeterministic(t *testing.T) {
	src := sampleStream(t, "/a/t.jsonl")
	build := func(out string) {
		opts := buildOpts(src)
		opts.Out = out
		mustBuild(t, opts)
	}
	a := filepath.Join(t.TempDir(), "a.numbat")
	b := filepath.Join(t.TempDir(), "b.numbat")
	build(a)
	build(b)
	for _, name := range []string{"manifest.json", "findings.ndjson", "events.ndjson"} {
		ab, _ := os.ReadFile(filepath.Join(a, name))
		bb, _ := os.ReadFile(filepath.Join(b, name))
		if string(ab) != string(bb) {
			t.Fatalf("%s differs across identical builds", name)
		}
	}
}

func TestSortRecordsOrdersRFC3339OffsetsByInstant(t *testing.T) {
	recs := []record{
		{timestamp: "2026-06-02T10:00:00-05:00", id: "later"},
		{timestamp: "2026-06-02T14:00:00Z", id: "earlier"},
	}
	sortRecords(recs)
	if recs[0].id != "earlier" || recs[1].id != "later" {
		t.Fatalf("sortRecords order = %s, %s; want absolute-time order", recs[0].id, recs[1].id)
	}
}

func TestBuildRefusesExistingOut(t *testing.T) {
	opts := buildOpts(sampleStream(t, "/a/t.jsonl"))
	opts.Out = t.TempDir() // exists
	if _, err := Build(opts); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("want overwrite refusal, got %v", err)
	}
}

func TestPublishBundleDoesNotReplaceRacingDestination(t *testing.T) {
	out := filepath.Join(t.TempDir(), "case.numbat")
	err := publishBundle(out, func(stage string) error {
		if err := os.WriteFile(filepath.Join(stage, "staged"), []byte("new"), 0o600); err != nil {
			return err
		}
		return os.Mkdir(out, 0o700)
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("publish error = %v, want overwrite refusal", err)
	}
	entries, readErr := os.ReadDir(out)
	if readErr != nil {
		t.Fatalf("read racing destination: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("racing destination was replaced: %v", entries)
	}
}

func TestBuildValidation(t *testing.T) {
	src := sampleStream(t, "/a/t.jsonl")
	out := filepath.Join(t.TempDir(), "case.numbat")

	for _, tc := range []struct {
		name string
		mut  func(*Options)
		want string
	}{
		{"empty case id", func(o *Options) { o.CaseID = "" }, "empty case id"},
		{"blank case id", func(o *Options) { o.CaseID = " \t" }, "empty case id"},
		{"no sources", func(o *Options) { o.Sources = nil }, "no source"},
		{"invalid evidence mode", func(o *Options) { o.Evidence = EvidenceMode(99) }, "invalid evidence mode"},
		{"unknown case id", func(o *Options) { o.CaseID = "case-x" }, "no findings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := buildOpts(src)
			opts.Out = out
			tc.mut(&opts)
			if _, err := Build(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatal("failed build must not leave an output directory")
			}
		})
	}

	t.Run("missing source", func(t *testing.T) {
		opts := buildOpts(src)
		opts.Out = filepath.Join(t.TempDir(), "case.numbat")
		opts.Sources = []string{filepath.Join(t.TempDir(), "nope")}
		if _, err := Build(opts); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Build error = %v, want missing-file classification", err)
		}
		if _, err := os.Lstat(opts.Out); !os.IsNotExist(err) {
			t.Fatal("failed build must not leave an output directory")
		}
	})
}

func TestBuildRejectsSymlinkSource(t *testing.T) {
	target := sampleStream(t, "/a/t.jsonl")
	link := filepath.Join(t.TempDir(), "records.ndjson")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	opts := buildOpts(link)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	_, err := Build(opts)
	if err == nil || !strings.Contains(err.Error(), "symlink") || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("Build error = %v, want symlink rejection", err)
	}
}

func TestBuildSkipsIncompatibleRecords(t *testing.T) {
	evidence := ref("/a/t.jsonl", 1)
	badFinding := map[string]any{}
	if err := json.Unmarshal([]byte(finding(t, "fnd-old", "case-1", "2026-06-02T10:00:00Z", evidence)), &badFinding); err != nil {
		t.Fatal(err)
	}
	badFinding["schema_version"] = "9.9.9"
	opts := buildOpts(writeStream(t, jline(t, badFinding)))
	opts.Out = filepath.Join(t.TempDir(), "old-schema.numbat")
	res, err := Build(opts)
	if err == nil || !strings.Contains(err.Error(), "no findings") {
		t.Fatalf("Build error = %v, want no-findings error", err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "unsupported schema_version") {
		t.Fatalf("warnings = %v", res.Warnings)
	}

	wrongSchemaEvent := map[string]any{}
	if err := json.Unmarshal([]byte(event(t, "ev-old", "2026-06-02T10:00:01Z", evidence)), &wrongSchemaEvent); err != nil {
		t.Fatal(err)
	}
	wrongSchemaEvent["schema_version"] = "9.9.9"
	wrongCaseEvent := map[string]any{}
	if err := json.Unmarshal([]byte(event(t, "ev-other", "2026-06-02T10:00:02Z", evidence)), &wrongCaseEvent); err != nil {
		t.Fatal(err)
	}
	wrongCaseEvent["case_id"] = "case-2"
	src := writeStream(t,
		findingWithCitedEvents(t, "fnd-a", "case-1", "2026-06-02T10:00:03Z", []string{"ev-old", "ev-other"}, evidence),
		jline(t, wrongSchemaEvent),
		jline(t, wrongCaseEvent),
	)
	opts = buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "incompatible-events.numbat")
	res = mustBuild(t, opts)
	if res.Events != 0 {
		t.Fatalf("events = %d, want incompatible events skipped", res.Events)
	}
	warnings := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"unsupported schema_version", `belongs to case_id "case-2"`} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings = %v, want %q", res.Warnings, want)
		}
	}
	if verified, err := Verify(opts.Out); err != nil || !verified.OK() {
		t.Fatalf("bundle must remain self-consistent: %+v, %v", verified, err)
	}
}

func TestBuildMalformedLineWarnsAndContinues(t *testing.T) {
	evidence := ref("/a/t.jsonl", 1)
	src := writeStream(t,
		"not-json",
		finding(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z", evidence),
		event(t, "event-for-fnd-a", "2026-06-02T09:59:59Z", evidence),
	)
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)
	if res.Findings != 1 {
		t.Fatalf("findings = %d, want 1", res.Findings)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "not a record") {
		t.Fatalf("warnings = %v, want one malformed-line warning", res.Warnings)
	}
}

func TestBuildMalformedLineWarningsAreSummarizedPerSource(t *testing.T) {
	evidence := ref("/a/t.jsonl", 1)
	lines := make([]string, maxMalformedWarningsPerSource+5)
	for i := range lines {
		lines[i] = "not-json"
	}
	lines = append(lines,
		finding(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z", evidence),
		event(t, "event-for-fnd-a", "2026-06-02T09:59:59Z", evidence),
	)
	opts := buildOpts(writeStream(t, lines...))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	res := mustBuild(t, opts)
	if len(res.Warnings) != maxMalformedWarningsPerSource+1 {
		t.Fatalf("warnings = %v", res.Warnings)
	}
	if got := res.Warnings[len(res.Warnings)-1]; !strings.Contains(got, "5 additional malformed records suppressed") {
		t.Fatalf("summary warning = %q", got)
	}
}

func TestResultWarningsAreBounded(t *testing.T) {
	var res Result
	for i := 0; i < maxResultWarnings+100; i++ {
		res.warn(fmt.Sprintf("warning %d", i))
	}
	if len(res.Warnings) != maxGeneralResultWarnings {
		t.Fatalf("warnings = %d, want cap %d", len(res.Warnings), maxGeneralResultWarnings)
	}
	if got := res.Warnings[len(res.Warnings)-1]; got != "additional warnings suppressed" {
		t.Fatalf("last warning = %q", got)
	}
	res.warnEvidence("evidence omitted")
	if got := res.Warnings[len(res.Warnings)-1]; got != "evidence omitted" {
		t.Fatalf("evidence warning was suppressed: %v", res.Warnings)
	}
}

func TestBuildSkipsRecordsWithEmptyIDs(t *testing.T) {
	emptyFinding := finding(t, "", "case-1", "2026-06-02T10:00:00Z", ref("/a/t.jsonl", 1))
	opts := buildOpts(writeStream(t, emptyFinding))
	opts.Out = filepath.Join(t.TempDir(), "empty-finding.numbat")
	res, err := Build(opts)
	if err == nil || !strings.Contains(err.Error(), "no findings") {
		t.Fatalf("Build error = %v, want no-findings error", err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "empty finding_id") {
		t.Fatalf("warnings = %v", res.Warnings)
	}

	r := ref("/a/t.jsonl", 1)
	src := writeStream(t,
		finding(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z", r),
		event(t, "", "2026-06-02T10:00:01Z", r),
	)
	opts = buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "empty-event.numbat")
	res = mustBuild(t, opts)
	if res.Events != 0 {
		t.Fatalf("result = %+v, want malformed uncited event excluded", res)
	}
}

func TestVerifyRejectsRecordIdentityEvenWithMatchingDigest(t *testing.T) {
	opts := buildOpts(sampleStream(t, "/a/t.jsonl"))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	mustBuild(t, opts)

	bad := []byte(`{"record_type":"finding","schema_version":"0.3.0","finding_id":"fnd-x","case_id":"other"}` + "\n")
	if err := os.WriteFile(filepath.Join(opts.Out, "findings.ndjson"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(opts.Out, manifestName)
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	for i := range m.Files {
		if m.Files[i].Path == "findings.ndjson" {
			m.Files[i].SHA256 = sha256StringHex(string(bad))
			m.Files[i].Records = 1
		}
	}
	manifestRaw, _ = json.Marshal(m)
	if err := os.WriteFile(manifestPath, manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Verify(opts.Out)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() || !strings.Contains(strings.Join(v.Problems, "\n"), "invalid finding identity") {
		t.Fatalf("problems = %v", v.Problems)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	opts := buildOpts(sampleStream(t, "/a/t.jsonl"))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	mustBuild(t, opts)

	check := func(wantProblem string) {
		t.Helper()
		v, err := Verify(opts.Out)
		if err != nil {
			t.Fatal(err)
		}
		if v.OK() {
			t.Fatalf("tampered bundle verified clean (want %q)", wantProblem)
		}
		joined := strings.Join(v.Problems, "\n")
		if !strings.Contains(joined, wantProblem) {
			t.Fatalf("problems = %v, want one containing %q", v.Problems, wantProblem)
		}
	}

	// A record edited in place: digest and count diverge.
	fpath := filepath.Join(opts.Out, "findings.ndjson")
	orig, _ := os.ReadFile(fpath)
	if err := os.WriteFile(fpath, append(orig, []byte("{\"record_type\":\"finding\"}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	check("records, manifest says")
	check("sha256")
	if err := os.WriteFile(fpath, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// A file the manifest does not vouch for.
	extra := filepath.Join(opts.Out, "extra.txt")
	if err := os.WriteFile(extra, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("not listed in manifest")
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}

	// A symlink smuggled into the bundle.
	link := filepath.Join(opts.Out, "link.ndjson")
	if err := os.Symlink(fpath, link); err != nil {
		t.Fatal(err)
	}
	check("symlink not allowed")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	// A listed file gone missing.
	if err := os.Remove(filepath.Join(opts.Out, "events.ndjson")); err != nil {
		t.Fatal(err)
	}
	check("missing")
}

func TestVerifyMissingBundleErrors(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want error for a directory with no manifest")
	}
}

// evidenceStream builds a stream whose finding cites a real artifact file
// with the given recorded sha256.
func evidenceStream(t *testing.T, artifact, recordedSHA string) string {
	t.Helper()
	r := ref(artifact, 1)
	if recordedSHA != "" {
		r["sha256"] = recordedSHA
	}
	return writeStream(t,
		finding(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z", r),
		event(t, "event-for-fnd-a", "2026-06-02T09:59:59Z", r),
	)
}

func TestEvidenceNotCopiedByDefault(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(artifact, []byte("secret line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := buildOpts(evidenceStream(t, artifact, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	mustBuild(t, opts)
	if _, err := os.Lstat(filepath.Join(opts.Out, "evidence")); !os.IsNotExist(err) {
		t.Fatal("default bundle must not contain an evidence directory")
	}
}

func TestEvidenceRawCopySkipsLiveEvidence(t *testing.T) {
	liveRef := map[string]any{"artifact_type": "hook", "local_path": t.TempDir()}
	opts := buildOpts(writeStream(t,
		findingWithCitedEvents(t, "fnd-live", "case-1", "2026-06-02T10:00:00Z", nil, liveRef),
	))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 0 || !strings.Contains(strings.Join(res.Warnings, "\n"), "no cited_event_ids") {
		t.Fatalf("result = %+v, want no copy and an unresolved live-citation warning", res)
	}
	if _, err := os.Lstat(filepath.Join(opts.Out, "evidence")); !os.IsNotExist(err) {
		t.Fatal("live evidence refs must not create an evidence directory")
	}
}

func TestEvidenceRawCopy(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "session.jsonl")
	content := "line one\nline two\n"
	if err := os.WriteFile(artifact, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := buildOpts(evidenceStream(t, artifact, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 1 || len(res.Warnings) != 0 {
		t.Fatalf("result = %+v", res)
	}

	var m Manifest
	b, _ := os.ReadFile(filepath.Join(opts.Out, "manifest.json"))
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var ev *ManifestFile
	for i := range m.Files {
		if strings.HasPrefix(m.Files[i].Path, "evidence/") {
			ev = &m.Files[i]
		}
	}
	if m.EvidenceMode != "raw" {
		t.Fatalf("evidence_mode = %q, want raw", m.EvidenceMode)
	}
	if ev == nil || ev.SourcePath != artifact || !strings.HasSuffix(ev.Path, "-session.jsonl") {
		t.Fatalf("evidence manifest entry = %+v", ev)
	}
	if ev.SourceSHA256 != sha256StringHex(content) || ev.SHA256 != ev.SourceSHA256 {
		t.Fatalf("raw evidence hashes = stored %q source %q", ev.SHA256, ev.SourceSHA256)
	}
	copied, err := os.ReadFile(filepath.Join(opts.Out, filepath.FromSlash(ev.Path)))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != content {
		t.Fatalf("raw copy = %q, want verbatim source", copied)
	}
	if v, err := Verify(opts.Out); err != nil || !v.OK() {
		t.Fatalf("bundle with evidence must verify: %+v, %v", v, err)
	}
}

func TestEvidenceCopyWarnsOnHashDrift(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(artifact, []byte(`{"text":"changed since the finding"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []EvidenceMode{EvidenceRaw, EvidenceRedacted} {
		opts := buildOpts(evidenceStream(t, artifact, strings.Repeat("a", 64)))
		opts.Out = filepath.Join(t.TempDir(), "case.numbat")
		opts.Evidence = mode
		res := mustBuild(t, opts)
		if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "changed since the finding") {
			t.Fatalf("mode %d warnings = %v, want a hash-drift warning", mode, res.Warnings)
		}
	}
}

func TestEvidenceRawCopyWarnsOnConflictingRecordedDigests(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "session.jsonl")
	content := "current content\n"
	if err := os.WriteFile(artifact, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	currentSHA := sha256StringHex(content)
	otherSHA := strings.Repeat("0", 64)

	refCurrent := ref(artifact, 1)
	refCurrent["sha256"] = currentSHA
	refOther := ref(artifact, 1)
	refOther["sha256"] = otherSHA

	opts := buildOpts(writeStream(t,
		finding(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z", refCurrent),
		finding(t, "fnd-b", "case-1", "2026-06-02T10:00:01Z", refOther),
		event(t, "event-for-fnd-a", "2026-06-02T09:59:58Z", refCurrent),
		event(t, "event-for-fnd-b", "2026-06-02T09:59:59Z", refOther),
	))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 1 {
		t.Fatalf("evidence files = %d, want 1", res.EvidenceFiles)
	}
	want := fmt.Sprintf("evidence %q: content changed since the finding (recorded sha256s [%s, %s], source at copy time %s)", artifact, otherSHA, currentSHA, currentSHA)
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Fatalf("warnings = %v, want %q", res.Warnings, want)
	}
}

func TestEvidenceMissingFileWarnsAndContinues(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone.jsonl")
	opts := buildOpts(evidenceStream(t, missing, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 0 || len(res.Warnings) != 1 {
		t.Fatalf("result = %+v, want zero copies and one warning", res)
	}
	if v, err := Verify(opts.Out); err != nil || !v.OK() {
		t.Fatalf("bundle must still verify: %+v, %v", v, err)
	}
}

func TestEvidenceCopyRejectsNonRegularSources(t *testing.T) {
	dir := t.TempDir()
	opts := buildOpts(evidenceStream(t, dir, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "not a regular file") {
		t.Fatalf("result = %+v, want one non-regular evidence warning", res)
	}
	if v, err := Verify(opts.Out); err != nil || !v.OK() {
		t.Fatalf("bundle must still verify: %+v, %v", v, err)
	}
}

func TestEvidenceCopyRejectsSymlinkSources(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	real := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(real, []byte("content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "session-link.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	opts := buildOpts(evidenceStream(t, link, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "symlink not allowed") {
		t.Fatalf("result = %+v, want one symlink evidence warning", res)
	}
	if v, err := Verify(opts.Out); err != nil || !v.OK() {
		t.Fatalf("bundle must still verify: %+v, %v", v, err)
	}
}

func TestEvidenceRedactedCopyMasksSecrets(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "session.log")
	secret := "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	source := "before\n" + secret + "\nafter\n"
	if err := os.WriteFile(artifact, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := buildOpts(evidenceStream(t, artifact, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRedacted
	mustBuild(t, opts)

	matches, err := filepath.Glob(filepath.Join(opts.Out, "evidence", "*-session.log"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("evidence copies = %v (%v)", matches, err)
	}
	copied, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(copied), "ghp_") {
		t.Fatalf("redacted copy leaked the token: %q", copied)
	}
	if !strings.Contains(string(copied), "before\n") || !strings.Contains(string(copied), "after\n") {
		t.Fatalf("redacted copy lost benign lines: %q", copied)
	}
	var m Manifest
	manifest, err := os.ReadFile(filepath.Join(opts.Out, manifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if m.EvidenceMode != "redacted" {
		t.Fatalf("evidence_mode = %q, want redacted", m.EvidenceMode)
	}
	var evidence ManifestFile
	for _, mf := range m.Files {
		if strings.HasPrefix(mf.Path, "evidence/") {
			evidence = mf
		}
	}
	if evidence.SourceSHA256 != sha256StringHex(source) || evidence.SHA256 == evidence.SourceSHA256 {
		t.Fatalf("redacted evidence hashes = stored %q source %q", evidence.SHA256, evidence.SourceSHA256)
	}
	if v, err := Verify(opts.Out); err != nil || !v.OK() {
		t.Fatalf("redacted bundle must verify: %+v, %v", v, err)
	}
}

func TestEvidenceRedactedCopyPreservesLineEndings(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "session.log")
	body := "one\r\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\r\ntwo"
	if err := os.WriteFile(artifact, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := buildOpts(evidenceStream(t, artifact, ""))
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRedacted
	mustBuild(t, opts)

	matches, err := filepath.Glob(filepath.Join(opts.Out, "evidence", "*-session.log"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("evidence copies = %v (%v)", matches, err)
	}
	copied, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	want := "one\r\nGITHUB_TOKEN=[redacted]\r\ntwo"
	if string(copied) != want {
		t.Fatalf("redacted copy = %q, want %q", copied, want)
	}
}

func TestEvidenceRedactedStructuredFilesStayValid(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		body string
	}{
		{
			name: "jsonl",
			ext:  ".jsonl",
			body: `{"type":"token_count","total_token_usage":{"input_tokens":42}}` + "\r\n" +
				`{"api_key":"plain-secret","text":"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`,
		},
		{
			name: "retained jsonl archive",
			ext:  ".jsonl.deleted.2026-07-23T10-11-12Z",
			body: `{"type":"message","api_key":"plain-secret"}` + "\n",
		},
		{
			name: "json",
			ext:  ".json",
			body: "{\n  \"api_key\": \"plain-secret\",\n  \"count\": 7\n}\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := filepath.Join(t.TempDir(), "session"+tc.ext)
			if err := os.WriteFile(artifact, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := buildOpts(evidenceStream(t, artifact, sha256StringHex(tc.body)))
			opts.Out = filepath.Join(t.TempDir(), "case.numbat")
			opts.Evidence = EvidenceRedacted
			res := mustBuild(t, opts)
			if res.EvidenceFiles != 1 || len(res.Warnings) != 0 {
				t.Fatalf("result = %+v", res)
			}

			matches, err := filepath.Glob(filepath.Join(opts.Out, "evidence", "*-session"+tc.ext))
			if err != nil || len(matches) != 1 {
				t.Fatalf("evidence copies = %v (%v)", matches, err)
			}
			copied, err := os.ReadFile(matches[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(copied), "plain-secret") || strings.Contains(string(copied), "ghp_") {
				t.Fatalf("redacted copy leaked a secret: %s", copied)
			}
			if tc.ext == ".json" {
				if !json.Valid(copied) {
					t.Fatalf("redacted JSON is invalid: %s", copied)
				}
			} else {
				for _, line := range strings.Split(string(copied), "\r\n") {
					if !json.Valid([]byte(line)) {
						t.Fatalf("redacted JSONL line is invalid: %s", line)
					}
				}
			}

			if v, err := Verify(opts.Out); err != nil || !v.OK() {
				t.Fatalf("bundle must verify: %+v, %v", v, err)
			}
		})
	}
}

func TestEvidenceRedactedRejectsUnsafeStructuredInput(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		body string
		want string
	}{
		{"malformed JSONL", ".jsonl", `{"token":`, "cannot safely redact JSON"},
		{"credential in JSON key", ".json", `{"ghp_abcdefghijklmnopqrstuvwxyz0123456789":"value"}`, "object key"},
		{"compressed JSONL", ".jsonl.zst", "compressed", "does not support compressed input"},
		{"compressed retained archive", ".jsonl.deleted.2026-07-23T10-11-12Z.gz", "compressed", "does not support compressed input"},
		{"binary input", ".bin", "\x00\x01\x02\x03", "only supports UTF-8 plain text or JSON"},
		{"late binary input", ".log", strings.Repeat("a", 600) + "\x00secret", "only supports UTF-8 plain text or JSON"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := filepath.Join(t.TempDir(), "session"+tc.ext)
			if err := os.WriteFile(artifact, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := buildOpts(evidenceStream(t, artifact, ""))
			opts.Out = filepath.Join(t.TempDir(), "case.numbat")
			opts.Evidence = EvidenceRedacted
			res := mustBuild(t, opts)
			if res.EvidenceFiles != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], tc.want) {
				t.Fatalf("result = %+v", res)
			}
			if _, err := os.Lstat(filepath.Join(opts.Out, "evidence")); !os.IsNotExist(err) {
				t.Fatal("failed structured copy left an evidence directory")
			}
			if v, err := Verify(opts.Out); err != nil || !v.OK() {
				t.Fatalf("bundle must verify: %+v, %v", v, err)
			}
		})
	}
}

func TestEvidenceBasenameCollisionAvoided(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	for _, d := range []string{dirA, dirB} {
		if err := os.WriteFile(filepath.Join(d, "session.jsonl"), []byte(d+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := writeStream(t, finding(t, "fnd-a", "case-1", "2026-06-02T10:00:00Z",
		ref(filepath.Join(dirA, "session.jsonl"), 1),
		ref(filepath.Join(dirB, "session.jsonl"), 1),
	))
	opts := buildOpts(src)
	opts.Out = filepath.Join(t.TempDir(), "case.numbat")
	opts.Evidence = EvidenceRaw
	res := mustBuild(t, opts)
	if res.EvidenceFiles != 2 {
		t.Fatalf("evidence files = %d, want both same-basename files", res.EvidenceFiles)
	}
}

func TestEvidenceCopyNameSanitizesPortableBasename(t *testing.T) {
	got := evidenceCopyName(filepath.Join(t.TempDir(), " weird\nname☃.jsonl "))
	if strings.ContainsAny(got, " \n\t") || strings.Contains(got, "☃") {
		t.Fatalf("evidence copy name = %q, want portable ASCII without whitespace/control chars", got)
	}
	if !strings.HasSuffix(got, "-weird_name_.jsonl") {
		t.Fatalf("evidence copy name = %q, want sanitized basename suffix", got)
	}
}

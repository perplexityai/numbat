package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// recordTypes returns the record_type of every NDJSON line on stdout, in order.
func recordTypes(t *testing.T, out string) []string {
	t.Helper()
	var types []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var rt struct {
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal([]byte(line), &rt); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		types = append(types, rt.RecordType)
	}
	return types
}

func countType(types []string, want string) int {
	n := 0
	for _, ty := range types {
		if ty == want {
			n++
		}
	}
	return n
}

func decodeEventRecords(t *testing.T, out string) []model.Event {
	t.Helper()
	var events []model.Event
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var envelope struct {
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.RecordType != "event" {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	return events
}

// scanSummary is the subset of the terminal scan_summary record the tests assert
// on. decodeSummary finds the single scan_summary line on stdout and decodes it.
type scanSummary struct {
	RecordType        string `json:"record_type"`
	Status            string `json:"status"`
	ArtifactsScanned  int    `json:"artifacts_scanned"`
	EventsEmitted     int    `json:"events_emitted"`
	FindingsEmitted   int    `json:"findings_emitted"`
	IndicatorsEmitted int    `json:"indicators_emitted"`
	Diagnostics       int    `json:"diagnostics"`
}

func decodeSummary(t *testing.T, out string) scanSummary {
	t.Helper()
	var found scanSummary
	foundSummary := false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var s scanSummary
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		if s.RecordType == "scan_summary" {
			if foundSummary {
				t.Fatalf("more than one scan_summary on stdout:\n%s", out)
			}
			found = s
			foundSummary = true
		}
	}
	if !foundSummary {
		t.Fatalf("no scan_summary on stdout:\n%s", out)
	}
	return found
}

// A transcript whose assistant turn thinks, fetches a URL, calls an MCP tool,
// reads .env (fires the secrets rule) and cats it. Exercises events, findings,
// indicators, and optional reasoning in one fixture.
const emitTranscript = `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-06-02T10:00:00Z","cwd":"/home/dev/proj","message":{"role":"user","content":"read the env"}}
{"type":"assistant","uuid":"a1","sessionId":"s1","timestamp":"2026-06-02T10:00:01Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"thinking","thinking":"I will read the env file"},{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/home/dev/proj/.env"}},{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"cat .env"}},{"type":"tool_use","id":"t3","name":"WebFetch","input":{"url":"https://evil.example/x","prompt":"grab"}},{"type":"tool_use","id":"t4","name":"mcp__db__query","input":{"q":"SELECT 1"}}]}}`

// The default (no --emit) emits only findings plus the always-present terminal
// scan_summary.
func TestScanEmitDefaultFindingsOnly(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	types := recordTypes(t, out)
	if countType(types, "event") != 0 || countType(types, "indicator") != 0 {
		t.Errorf("default scan leaked events/indicators: %v", types)
	}
	if countType(types, "finding") == 0 {
		t.Errorf("default scan emitted no findings: %v", types)
	}
	if countType(types, "scan_summary") != 1 {
		t.Errorf("want exactly one scan_summary, got types %v", types)
	}
}

// --emit events emits the normalized event stream and no findings; the terminal
// summary is still present.
func TestScanEmitEvents(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	types := recordTypes(t, out)
	if countType(types, "finding") != 0 {
		t.Errorf("--emit events leaked findings: %v", types)
	}
	if countType(types, "event") == 0 {
		t.Errorf("--emit events emitted no events: %v", types)
	}
	if countType(types, "scan_summary") != 1 {
		t.Errorf("want one scan_summary: %v", types)
	}
}

// --emit indicators emits the deduplicated indicator projection and no findings.
func TestScanEmitIndicators(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "indicators")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	types := recordTypes(t, out)
	if countType(types, "finding") != 0 || countType(types, "event") != 0 {
		t.Errorf("--emit indicators leaked other records: %v", types)
	}
	if countType(types, "indicator") == 0 {
		t.Errorf("--emit indicators emitted no indicators: %v", types)
	}
}

// Repeating --emit is the low-volume continuous mode: no per-event stream, but
// findings and deduplicated indicators are both available for SIEM enrichment
// and alert pivots.
func TestScanEmitFindingsAndIndicators(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "findings", "--emit", "indicators")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	types := recordTypes(t, out)
	if countType(types, "event") != 0 {
		t.Errorf("repeated --emit leaked events: %v", types)
	}
	for _, want := range []string{"finding", "indicator", "scan_summary"} {
		if countType(types, want) == 0 {
			t.Errorf("repeated --emit missing %s record: %v", want, types)
		}
	}
	foundPivot := false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("stdout line not JSON: %v\n%s", err, line)
		}
		if rec["record_type"] != "indicator" {
			continue
		}
		if strings.Contains(line, `/home/dev/proj`) {
			t.Errorf("indicator stream leaked raw project path:\n%s", line)
		}
		hash, _ := rec["sample_project_path_hash"].(string)
		if rec["sample_session_id"] == "s1" && strings.HasPrefix(hash, "sha256:") {
			foundPivot = true
		}
	}
	if !foundPivot {
		t.Errorf("indicator stream missing session/project pivot:\n%s", out)
	}
}

// --emit all emits every record kind.
func TestScanEmitAll(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "all")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	types := recordTypes(t, out)
	for _, want := range []string{"event", "finding", "indicator", "scan_summary"} {
		if countType(types, want) == 0 {
			t.Errorf("--emit all missing %s record: %v", want, types)
		}
	}
}

// An invalid --emit value is a usage error (exit 2), so a typo fails loudly
// rather than silently emitting the default.
func TestScanEmitInvalidValue(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	_, errb, code := runCLI("scan", "--path", p, "--emit", "bogus")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "invalid --emit") {
		t.Errorf("stderr missing emit error: %q", errb)
	}
}

func TestParseEmitModes(t *testing.T) {
	tests := []struct {
		in   []string
		want emitSelection
	}{
		{nil, emitSelection{findings: true}},
		{[]string{emitFindings}, emitSelection{findings: true}},
		{[]string{emitEvents}, emitSelection{events: true}},
		{[]string{emitIndicators}, emitSelection{indicators: true}},
		{[]string{emitFindings, emitIndicators}, emitSelection{findings: true, indicators: true}},
		{[]string{emitAll}, emitSelection{events: true, findings: true, indicators: true}},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.in, "+"), func(t *testing.T) {
			got, err := parseEmit(tc.in)
			if err != nil {
				t.Fatalf("parseEmit(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseEmit(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseEmitRejectsAliases(t *testing.T) {
	for _, in := range [][]string{
		{"indicators,findings"},
		{"findings+indicators"},
		{"indicators+findings"},
		{"findings", "findings"},
		{"all", "events"},
	} {
		t.Run(strings.Join(in, "+"), func(t *testing.T) {
			if _, err := parseEmit(in); err == nil {
				t.Fatalf("parseEmit(%q) succeeded, want error", in)
			}
		})
	}
}

// Reasoning is omitted unless explicitly requested.
func TestScanOmitsReasoningByDefault(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, `"event_type":"message.reasoning"`) {
		t.Errorf("default scan leaked reasoning:\n%s", out)
	}
}

func TestScanIncludeReasoning(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events", "--include-reasoning")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"event_type":"message.reasoning"`) {
		t.Errorf("--include-reasoning did not surface reasoning:\n%s", out)
	}
}

func TestScanDeprecatedFullProfileIncludesReasoningOnly(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events", "--profile", "full")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, ev := range decodeEventRecords(t, out) {
		if ev.EventType != model.EventMessageReasoning {
			continue
		}
		if ev.Content != "" {
			t.Fatalf("deprecated --profile full emitted full content: %q", ev.Content)
		}
		return
	}
	t.Fatal("deprecated --profile full did not include reasoning")
}

func TestScanDeprecatedEvidenceProfileOmitsReasoning(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events", "--profile", "evidence")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, `"event_type":"message.reasoning"`) {
		t.Fatalf("deprecated --profile evidence included reasoning:\n%s", out)
	}
}

func TestScanRejectsInvalidDeprecatedProfile(t *testing.T) {
	_, errb, code := runCLI("scan", "--profile", "everything")
	if code != 2 || !strings.Contains(errb, `invalid --profile "everything": want evidence|full`) {
		t.Fatalf("exit=%d stderr=%q", code, errb)
	}
}

func TestScanFullContentIsExplicitBoundedAndRedacted(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	raw := strings.Repeat("ordinary context ", 20) + secret + "\nfinal line"
	body := `{"type":"user","uuid":"u1","sessionId":"s1","message":{"role":"user","content":` + strconv.Quote(raw) + `}}`
	p := writeTranscript(t, body)

	previewOut, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("preview exit = %d", code)
	}
	preview := decodeEventRecords(t, previewOut)
	if len(preview) == 0 || preview[1].EventType != model.EventPromptUser {
		t.Fatalf("preview events = %+v", preview)
	}
	if preview[1].Content != "" || !preview[1].ContentPreviewTruncated || strings.Contains(previewOut, secret) {
		t.Fatalf("default projection exposed or misreported content:\n%s", previewOut)
	}

	fullOut, _, code := runCLI("scan", "--path", p, "--emit", "events", "--content", "full")
	if code != 0 {
		t.Fatalf("full exit = %d", code)
	}
	full := decodeEventRecords(t, fullOut)
	if len(full) == 0 || full[1].EventType != model.EventPromptUser {
		t.Fatalf("full events = %+v", full)
	}
	got := full[1]
	if got.Content == "" || strings.Contains(got.Content, secret) || !strings.Contains(got.Content, "[redacted]") {
		t.Fatalf("full content omitted or unredacted: %q", got.Content)
	}
	if got.ContentBytes != len(raw) || got.ContentTruncated {
		t.Fatalf("content metadata = %d/%v, want %d/false", got.ContentBytes, got.ContentTruncated, len(raw))
	}
}

func TestScanFullContentRequiresEvents(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	_, errb, code := runCLI("scan", "--path", p, "--content", "full")
	if code != 2 || !strings.Contains(errb, "--content full requires --emit events or --emit all") {
		t.Fatalf("exit=%d stderr=%q", code, errb)
	}
}

func TestScanReasoningCanEmitFullContent(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events", "--include-reasoning", "--content", "full")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, ev := range decodeEventRecords(t, out) {
		if ev.EventType == model.EventMessageReasoning {
			if ev.Content != "I will read the env file" {
				t.Fatalf("reasoning content = %q", ev.Content)
			}
			return
		}
	}
	t.Fatal("reasoning event not emitted")
}

// --emit events surfaces the typed fields the new wiring populates: a WebFetch
// promotes its url onto a network.indicator, an MCP tool splits into
// mcp_server/mcp_tool, and tool calls carry their tool_call_id.
func TestScanEmitEventsCarriesTypedFields(t *testing.T) {
	p := writeTranscript(t, emitTranscript)
	out, _, code := runCLI("scan", "--path", p, "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"url":"https://evil.example/x"`) {
		t.Errorf("WebFetch url not promoted onto an event:\n%s", out)
	}
	if !strings.Contains(out, `"mcp_server":"db"`) || !strings.Contains(out, `"mcp_tool":"query"`) {
		t.Errorf("MCP name not split into server/tool:\n%s", out)
	}
	if !strings.Contains(out, `"tool_call_id":"t1"`) {
		t.Errorf("tool_call_id not stamped on the tool call:\n%s", out)
	}
	// The synthetic session lifecycle bounds the stream.
	if !strings.Contains(out, `"event_type":"session.start"`) || !strings.Contains(out, `"event_type":"session.end"`) {
		t.Errorf("session lifecycle events missing:\n%s", out)
	}
}

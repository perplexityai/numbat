package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

type closedTimelineWriter struct{}

func (closedTimelineWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// a two-session transcript: one user prompt, an assistant turn that reads .env
// and runs a build, and the build's result — enough to exercise the prompt ->
// tools -> command -> outcome reconstruction.
const timelineTranscript = `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-06-02T10:00:00Z","cwd":"/home/dev/proj","message":{"role":"user","content":"read the env then build"}}
{"type":"assistant","uuid":"a1","sessionId":"s1","timestamp":"2026-06-02T10:00:01Z","cwd":"/home/dev/proj","message":{"role":"assistant","content":[{"type":"text","text":"On it."},{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/home/dev/proj/.env"}},{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"make build"}}]}}
{"type":"user","uuid":"u2","sessionId":"s1","timestamp":"2026-06-02T10:00:02Z","cwd":"/home/dev/proj","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","content":"ok"}]},"toolUseResult":{"stdout":"ok","exit_code":0}}`

// The text format renders a session header and one ordered, evidence-anchored
// line per event — a smoke test that the human view is produced end to end.
func TestTimelineTextSmoke(t *testing.T) {
	p := writeTranscript(t, timelineTranscript)
	out, errb, code := runCLI("timeline", "--path", p)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb)
	}
	for _, want := range []string{
		"session s1 [claude-code]",
		"project: /home/dev/proj",
		"prompt.user",
		"file.read",
		"/home/dev/proj/.env",
		"command.exec",
		"make build",
		"command.result",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	// Steps are anchored by an evidence ref back to the artifact.
	if !strings.Contains(out, p+":") {
		t.Errorf("output missing evidence ref to %s:\n%s", p, out)
	}
	// Order: the prompt precedes the command, which precedes the result.
	if !(strings.Index(out, "prompt.user") < strings.Index(out, "command.exec") &&
		strings.Index(out, "command.exec") < strings.Index(out, "command.result")) {
		t.Errorf("events not in chronological order:\n%s", out)
	}
}

func TestRenderTimelineTextEscapesControlsAndReportsWriteErrors(t *testing.T) {
	sessions := []timelineSession{{
		SourceAgent: "claude-code",
		SessionID:   "s\x1b",
		Events: []model.Event{{
			Timestamp: "2026-06-02T10:00:00Z",
			EventType: model.EventCommandExec,
			Actor:     model.ActorAssistant,
			Command:   "printf '\x1b[31mred'\nnext",
			Evidence:  model.Evidence{LocalPath: "/tmp/evidence\x1b.jsonl"},
		}},
	}}
	var out bytes.Buffer
	if err := renderTimelineText(sessions, &out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') || !strings.Contains(out.String(), `\u001b[31mred'\nnext`) {
		t.Fatalf("unsafe or missing control escaping: %q", out.String())
	}
	if err := renderTimelineText(sessions, closedTimelineWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("render error = %v, want closed pipe", err)
	}
}

// The json format is one document carrying schema_version and the grouped
// sessions, deterministic across runs.
func TestTimelineJSONShapeAndDeterminism(t *testing.T) {
	p := writeTranscript(t, timelineTranscript)
	out, errb, code := runCLI("timeline", "--path", p, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb)
	}
	var report struct {
		SchemaVersion string `json:"schema_version"`
		Sessions      []struct {
			SourceAgent string `json:"source_agent"`
			SessionID   string `json:"session_id"`
			ProjectPath string `json:"project_path"`
			Start       string `json:"start"`
			End         string `json:"end"`
			Events      []struct {
				EventType string `json:"event_type"`
			} `json:"events"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("json output not a single document: %v\n%s", err, out)
	}
	if report.SchemaVersion != "0.3.0" {
		t.Errorf("schema_version = %q, want 0.3.0", report.SchemaVersion)
	}
	if len(report.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(report.Sessions))
	}
	s := report.Sessions[0]
	if s.SessionID != "s1" || s.SourceAgent != "claude-code" || s.ProjectPath != "/home/dev/proj" {
		t.Errorf("session identity wrong: %+v", s)
	}
	if s.Start != "2026-06-02T10:00:00Z" || s.End != "2026-06-02T10:00:02Z" {
		t.Errorf("span = %s..%s", s.Start, s.End)
	}
	// Re-running over the same artifact is byte-identical.
	out2, _, _ := runCLI("timeline", "--path", p, "--format", "json")
	if out != out2 {
		t.Errorf("json output not deterministic across runs")
	}
}

func TestTimelineOpenCodeKeepsSessionAndToolTimes(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, ".local", "share", "opencode", "storage", "part", "m1", "p1.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"p1","sessionID":"open-1","messageID":"m1","type":"tool","callID":"c1","tool":"bash","state":{"status":"completed","input":{"command":"echo ok"},"output":"ok","time":{"start":1700000000000,"end":1700000000123}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errb, code := runCLI("timeline", "--path", p, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb)
	}
	var report timelineReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(report.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(report.Sessions))
	}
	s := report.Sessions[0]
	if s.SourceAgent != model.AgentOpenCode || s.SessionID != "open-1" || s.Start != "2023-11-14T22:13:20Z" || s.End != "2023-11-14T22:13:20.123Z" {
		t.Errorf("OpenCode timeline context not preserved: %+v", s)
	}
}

func TestTimelineDeduplicatesRepeatedAndOverlappingPaths(t *testing.T) {
	p := writeTranscript(t, timelineTranscript)
	want, errb, code := runCLI("timeline", "--path", p, "--format", "json")
	if code != 0 {
		t.Fatalf("single-path exit = %d, stderr=%s", code, errb)
	}
	got, errb, code := runCLI("timeline", "--path", filepath.Dir(p), "--path", p, "--path", p, "--format", "json")
	if code != 0 {
		t.Fatalf("overlapping-path exit = %d, stderr=%s", code, errb)
	}
	if got != want {
		t.Fatalf("overlapping roots duplicated timeline events:\n%s", got)
	}
}

// A directory of two single-session transcripts renders both, ordered by start
// time, independent of filesystem walk order.
func TestTimelineDirectoryTwoSessions(t *testing.T) {
	root := t.TempDir()
	early := `{"type":"user","uuid":"e","sessionId":"early","timestamp":"2026-06-02T08:00:00Z","cwd":"/p","message":{"role":"user","content":"first"}}`
	late := `{"type":"user","uuid":"l","sessionId":"late","timestamp":"2026-06-02T12:00:00Z","cwd":"/p","message":{"role":"user","content":"second"}}`
	if err := os.WriteFile(filepath.Join(root, "z-late.jsonl"), []byte(late), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a-early.jsonl"), []byte(early), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("timeline", "--path", root, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb)
	}
	var report struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(report.Sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(report.Sessions))
	}
	// "early" (08:00) sorts before "late" (12:00) despite the file names.
	if report.Sessions[0].SessionID != "early" || report.Sessions[1].SessionID != "late" {
		t.Errorf("session order = [%s, %s], want [early, late]", report.Sessions[0].SessionID, report.Sessions[1].SessionID)
	}
}

func TestTimelineAcceptsRepeatedPath(t *testing.T) {
	root := t.TempDir()
	one := filepath.Join(root, "one.jsonl")
	two := filepath.Join(root, "two.jsonl")
	if err := os.WriteFile(one, []byte(`{"type":"user","uuid":"u1","sessionId":"one","timestamp":"2026-06-02T08:00:00Z","cwd":"/p","message":{"role":"user","content":"one"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte(`{"type":"user","uuid":"u2","sessionId":"two","timestamp":"2026-06-02T09:00:00Z","cwd":"/p","message":{"role":"user","content":"two"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("timeline", "--path", two, "--path", one, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errb)
	}
	var report struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(report.Sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(report.Sessions))
	}
	if report.Sessions[0].SessionID != "one" || report.Sessions[1].SessionID != "two" {
		t.Errorf("session order = [%s, %s], want [one, two]", report.Sessions[0].SessionID, report.Sessions[1].SessionID)
	}
}

func TestTimelineRejectsBadFormat(t *testing.T) {
	p := writeTranscript(t, timelineTranscript)
	_, errb, code := runCLI("timeline", "--path", p, "--format", "yaml")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "invalid --format") {
		t.Errorf("stderr = %q, want invalid --format", errb)
	}
}

func TestTimelineRejectsPositionalArgs(t *testing.T) {
	_, errb, code := runCLI("timeline", "extra")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "unexpected argument") {
		t.Errorf("stderr = %q, want unexpected argument", errb)
	}
}

func TestTimelineMissingPathExitsOne(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	_, errb, code := runCLI("timeline", "--path", missing)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "no agent artifacts") {
		t.Errorf("stderr = %q", errb)
	}
}

func TestTimelineDiscoveredButUnparsedArtifactExitsOne(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, ".codex", "sessions", "2026", "06", "19", "rollout-bad.jsonl.zst")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte("not zstd"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, errb, code := runCLI("timeline", "--path", root)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "parse") || !strings.Contains(errb, "no agent artifacts parsed") {
		t.Errorf("stderr = %q, want parse diagnostic and no-parsed message", errb)
	}
	if strings.Contains(errb, "no agent artifacts found to read") {
		t.Errorf("stderr used no-artifacts message for a discovered bad artifact: %q", errb)
	}
}

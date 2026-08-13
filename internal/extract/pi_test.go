package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

const piSessionFixture = `{"type":"session","version":3,"id":"s-pi","timestamp":"2026-07-22T09:00:00.000Z","cwd":"/work/repo"}
{"type":"message","id":"u1","parentId":null,"timestamp":"2026-07-22T09:00:01.000Z","message":{"role":"user","content":"inspect the repo","timestamp":1784710801000}}
{"type":"message","id":"a1","parentId":"u1","timestamp":"2026-07-22T09:00:02.000Z","message":{"role":"assistant","content":[{"type":"text","text":"I will inspect it."},{"type":"thinking","thinking":"private chain"},{"type":"toolCall","id":"call-bash","name":"bash","arguments":{"command":"git status --short"}},{"type":"toolCall","id":"call-read","name":"read","arguments":{"path":"README.md"}},{"type":"toolCall","id":"call-write","name":"edit","arguments":{"path":"main.go","oldText":"a","newText":"b"}},{"type":"toolCall","id":"call-ext","name":"lookup","arguments":{"query":"x"}}],"timestamp":1784710802000}}
{"type":"message","id":"r1","parentId":"a1","timestamp":"2026-07-22T09:00:03.000Z","message":{"role":"toolResult","toolCallId":"call-bash","toolName":"bash","content":[{"type":"text","text":"failed"}],"isError":true,"timestamp":1784710803000}}
{"type":"message","id":"b1","parentId":"r1","timestamp":"2026-07-22T09:00:04.000Z","message":{"role":"bashExecution","command":"pwd","output":"/work/repo\n","exitCode":0,"timestamp":1784710804000}}
`

func TestPiExtractMapsDocumentedSessionRecords(t *testing.T) {
	src := Source{Path: "/home/u/.pi/agent/sessions/--work-repo--/session.jsonl", CaseID: "case-pi"}
	res, err := (PiExtractor{}).Extract(strings.NewReader(piSessionFixture), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
	wantTypes := []model.EventType{
		model.EventSessionStart,
		model.EventPromptUser,
		model.EventMessageAssistant,
		model.EventCommandExec,
		model.EventFileRead,
		model.EventFileWrite,
		model.EventToolCall,
		model.EventCommandResult,
		model.EventCommandExec,
		model.EventCommandResult,
	}
	if len(res.Events) != len(wantTypes) {
		t.Fatalf("events = %d, want %d: %+v", len(res.Events), len(wantTypes), res.Events)
	}
	seenIDs := map[string]bool{}
	for i, ev := range res.Events {
		if ev.EventType != wantTypes[i] {
			t.Errorf("event %d type = %q, want %q", i, ev.EventType, wantTypes[i])
		}
		if ev.SourceAgent != model.AgentPi || ev.SourceType != model.SourceArtifact {
			t.Errorf("event %d source = %q/%q", i, ev.SourceAgent, ev.SourceType)
		}
		if ev.SessionID != "s-pi" || ev.ProjectPath != "/work/repo" || ev.CaseID != "case-pi" {
			t.Errorf("event %d context = session %q project %q case %q", i, ev.SessionID, ev.ProjectPath, ev.CaseID)
		}
		if ev.Evidence.ArtifactType != artifactPiSession || ev.Evidence.LocalPath != src.Path || ev.Evidence.SHA256 == "" {
			t.Errorf("event %d evidence = %+v", i, ev.Evidence)
		}
		if seenIDs[ev.EventID] {
			t.Errorf("duplicate event id %q", ev.EventID)
		}
		seenIDs[ev.EventID] = true
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d invalid: %v\n%+v", i, err, ev)
		}
	}

	if got := res.Events[3]; got.ToolName != "bash" || got.ToolCallID != "call-bash" || got.Command != "git status --short" {
		t.Errorf("bash call = %+v", got)
	}
	if got := res.Events[4]; got.FilePath != "README.md" || got.ToolName != "read" {
		t.Errorf("read call = %+v", got)
	}
	if got := res.Events[5]; got.FilePath != "main.go" || got.ToolName != "edit" {
		t.Errorf("edit call = %+v", got)
	}
	if got := res.Events[6]; got.ToolName != "lookup" || got.ToolCallID != "call-ext" {
		t.Errorf("extension call = %+v", got)
	}
	if got := res.Events[7]; got.ToolCallID != "call-bash" || len(got.Tags) != 1 || got.Tags[0] != model.TagToolError {
		t.Errorf("correlated result = %+v", got)
	}
	if got := res.Events[8]; got.Actor != model.ActorUser || got.Command != "pwd" || got.ToolCallID != "" {
		t.Errorf("user bash execution = %+v", got)
	}
	if got := res.Events[9]; got.ExitCode == nil || *got.ExitCode != 0 || got.ToolCallID != "" {
		t.Errorf("user bash result = %+v", got)
	}
}

func TestPiExtractFullProfileIncludesReasoning(t *testing.T) {
	res, err := (PiExtractor{}).Extract(strings.NewReader(piSessionFixture), Source{
		Path:             "/home/u/.pi/agent/sessions/s.jsonl",
		IncludeReasoning: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var reasoning []model.Event
	for _, ev := range res.Events {
		if ev.EventType == model.EventMessageReasoning {
			reasoning = append(reasoning, ev)
		}
	}
	if len(reasoning) != 1 || reasoning[0].ContentPreview != "private chain" {
		t.Fatalf("reasoning = %+v", reasoning)
	}
}

func TestPiExtractPreservesAllBranchesInArtifactOrder(t *testing.T) {
	fixture := `{"type":"session","version":3,"id":"s","timestamp":"2026-07-22T09:00:00Z","cwd":"/p"}
{"type":"message","id":"left","parentId":"root","timestamp":"2026-07-22T09:00:01Z","message":{"role":"user","content":"left branch"}}
{"type":"message","id":"right","parentId":"root","timestamp":"2026-07-22T09:00:02Z","message":{"role":"user","content":"right branch"}}
{"type":"branch_summary","id":"summary","parentId":"right","timestamp":"2026-07-22T09:00:03Z","summary":"generated"}
{"type":"compaction","id":"compact","parentId":"right","timestamp":"2026-07-22T09:00:04Z","summary":"generated","firstKeptEntryId":"right"}
`
	res, err := (PiExtractor{}).Extract(strings.NewReader(fixture), Source{Path: "/x/.pi/agent/sessions/s.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
	if len(res.Events) != 3 || res.Events[1].ContentPreview != "left branch" || res.Events[2].ContentPreview != "right branch" {
		t.Fatalf("events = %+v", res.Events)
	}
}

func TestPiExtractToleratesMalformedAndUnknownRows(t *testing.T) {
	fixture := "{bad\n" +
		`{"type":"message","timestamp":"2026-07-22T09:00:01Z","message":{"role":"user","content":{"bad":true}}}` + "\n" +
		`{"type":"mystery"}` + "\n" +
		`{"type":"message","timestamp":"2026-07-22T09:00:02Z","message":{"role":"mystery"}}` + "\n"
	res, err := (PiExtractor{}).Extract(strings.NewReader(fixture), Source{Path: "/x/.pi/agent/sessions/s.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || len(res.Diagnostics) != 4 {
		t.Fatalf("events = %+v diagnostics = %+v", res.Events, res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "bad") || strings.Contains(d.Msg, "mystery") {
			t.Errorf("diagnostic leaks artifact content: %+v", d)
		}
	}
}

func TestPiExtractDeterministicIDsAndEpochFallback(t *testing.T) {
	fixture := `{"type":"session","version":1,"id":"old","cwd":"/old"}
{"type":"message","id":"u","message":{"role":"user","content":"hello","timestamp":1784710801000}}
`
	src := Source{Path: "/x/.pi/agent/sessions/old.jsonl"}
	a, err := (PiExtractor{}).Extract(strings.NewReader(fixture), src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (PiExtractor{}).Extract(strings.NewReader(fixture), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Events) != 2 || len(b.Events) != 2 || a.Events[1].EventID != b.Events[1].EventID {
		t.Fatalf("events a=%+v b=%+v", a.Events, b.Events)
	}
	if a.Events[1].Timestamp != "2026-07-22T09:00:01Z" {
		t.Fatalf("timestamp = %q", a.Events[1].Timestamp)
	}
}

func TestPiExtractRejectsOversizeArtifact(t *testing.T) {
	_, err := (PiExtractor{maxBytes: 8}).Extract(strings.NewReader(strings.Repeat("x", 9)), Source{Path: "/x/s.jsonl"})
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("error = %v", err)
	}
}

func TestPiEventIDsSeparateSubEvents(t *testing.T) {
	path := "/x/session.jsonl"
	if piEventID(path, 2, 0) == piEventID(path, 2, 1) {
		t.Fatal("sub-events share an id")
	}
	if got := piEventID(path, 2, 0); !strings.HasPrefix(got, "pi-") || len(got) != len("pi-")+16 {
		t.Fatalf("event id = %q", got)
	}
}

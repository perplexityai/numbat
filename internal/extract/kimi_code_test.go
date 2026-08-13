package extract

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// The record and nested key shapes in this fixture were checked against a
// public Kimi Code session artifact, not inferred from the documented path:
// https://huggingface.co/datasets/nacloos/machine-playing-paper
const kimiWireFixture = `{"type":"metadata","protocol_version":"1.5","created_at":1784710800000}
{"type":"config.update","cwd":"/work/repo","profileName":"agent","time":1784710800001}
{"type":"tools.set_active_tools","names":["Read","Write","Bash"],"time":1784710800002}
{"type":"permission.set_mode","mode":"manual","time":1784710800003}
{"type":"turn.prompt","input":[{"type":"text","text":"inspect the repo"}],"origin":{"kind":"user"},"time":1784710801000}
{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"inspect the repo"}],"toolCalls":[]},"time":1784710801001}
{"type":"context.append_loop_event","event":{"type":"step.begin","uuid":"s1","turnId":"t1","step":0},"time":1784710801100}
{"type":"context.append_loop_event","event":{"type":"content.part","stepUuid":"s1","part":{"type":"text","text":"I will inspect it."}},"time":1784710801200}
{"type":"context.append_loop_event","event":{"type":"content.part","stepUuid":"s1","part":{"type":"think","think":"private chain"}},"time":1784710801250}
{"type":"context.append_loop_event","event":{"type":"tool.call","stepUuid":"s1","toolCallId":"call-bash","name":"Bash","args":{"command":"git status --short"}},"time":1784710801300}
{"type":"context.append_loop_event","event":{"type":"tool.result","toolCallId":"call-bash","result":{"output":"failed","isError":true}},"time":1784710801400}
{"type":"context.append_loop_event","event":{"type":"tool.call","stepUuid":"s1","toolCallId":"call-read","name":"Read","args":{"path":"README.md"}},"time":1784710801500}
{"type":"context.append_loop_event","event":{"type":"tool.call","stepUuid":"s1","toolCallId":"call-write","name":"Write","args":{"path":"out.txt","content":"x"}},"time":1784710801600}
{"type":"context.append_loop_event","event":{"type":"tool.call","stepUuid":"s1","toolCallId":"call-fetch","name":"FetchURL","args":{"url":"https://example.com/a"}},"time":1784710801700}
{"type":"context.append_loop_event","event":{"type":"tool.call","stepUuid":"s1","toolCallId":"call-ext","name":"PluginLookup","args":{"query":"x"}},"time":1784710801800}
{"type":"context.append_loop_event","event":{"type":"step.end","uuid":"s1","turnId":"t1","step":0},"time":1784710801900}
{"type":"usage.record","model":"kimi-k2","usage":{"output":5},"time":1784710801901}
`

func TestKimiCodeExtractMapsCurrentWireRecords(t *testing.T) {
	src := Source{
		Path:   "/home/u/.kimi-code/sessions/wd_repo_abc/session-1/agents/main/wire.jsonl",
		CaseID: "case-kimi",
	}
	res, err := (KimiCodeExtractor{}).Extract(strings.NewReader(kimiWireFixture), src)
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
		model.EventCommandResult,
		model.EventFileRead,
		model.EventFileWrite,
		model.EventNetworkIndicator,
		model.EventToolCall,
	}
	if len(res.Events) != len(wantTypes) {
		t.Fatalf("events = %d, want %d: %+v", len(res.Events), len(wantTypes), res.Events)
	}
	seenIDs := map[string]bool{}
	for i, ev := range res.Events {
		if ev.EventType != wantTypes[i] {
			t.Errorf("event %d type = %q, want %q", i, ev.EventType, wantTypes[i])
		}
		if ev.SourceAgent != model.AgentKimiCode || ev.SourceType != model.SourceArtifact {
			t.Errorf("event %d source = %q/%q", i, ev.SourceAgent, ev.SourceType)
		}
		if ev.SessionID != "session-1" || ev.ProjectPath != "/work/repo" || ev.SubAgent != "" {
			t.Errorf("event %d context = session %q project %q subagent %q", i, ev.SessionID, ev.ProjectPath, ev.SubAgent)
		}
		if ev.CaseID != "case-kimi" || ev.Evidence.ArtifactType != artifactKimiWire || ev.Evidence.SHA256 == "" {
			t.Errorf("event %d provenance = case %q evidence %+v", i, ev.CaseID, ev.Evidence)
		}
		if seenIDs[ev.EventID] {
			t.Errorf("duplicate event id %q", ev.EventID)
		}
		seenIDs[ev.EventID] = true
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d invalid: %v\n%+v", i, err, ev)
		}
	}

	if got := res.Events[3]; got.ToolName != "Bash" || got.ToolCallID != "call-bash" || got.Command != "git status --short" {
		t.Errorf("bash = %+v", got)
	}
	if got := res.Events[4]; got.ToolName != "Bash" || got.ToolCallID != "call-bash" || len(got.Tags) != 1 || got.Tags[0] != model.TagToolError {
		t.Errorf("bash result = %+v", got)
	}
	if got := res.Events[5]; got.ToolName != "Read" || got.FilePath != "README.md" {
		t.Errorf("read = %+v", got)
	}
	if got := res.Events[6]; got.ToolName != "Write" || got.FilePath != "out.txt" {
		t.Errorf("write = %+v", got)
	}
	if got := res.Events[7]; got.URL != "https://example.com/a" || len(got.Tags) != 1 || got.Tags[0] != model.TagNetwork {
		t.Errorf("fetch = %+v", got)
	}
	if got := res.Events[8]; got.ToolName != "PluginLookup" || got.ToolCallID != "call-ext" {
		t.Errorf("plugin tool = %+v", got)
	}
}

func TestKimiCodeExtractFullProfileIncludesThinking(t *testing.T) {
	res, err := (KimiCodeExtractor{}).Extract(strings.NewReader(kimiWireFixture), Source{
		Path:             "/x/.kimi-code/sessions/w/s/agents/main/wire.jsonl",
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

func TestKimiCodeExtractCarriesSubAgentFromPath(t *testing.T) {
	fixture := `{"type":"metadata","protocol_version":"1.1","created_at":1784710800000}
{"type":"config.update","cwd":"/work/repo","time":1784710800001}
{"type":"turn.prompt","input":[{"type":"text","text":"subtask"}],"origin":{"kind":"user"},"time":1784710801000}
`
	res, err := (KimiCodeExtractor{}).Extract(strings.NewReader(fixture), Source{
		Path: "/x/.kimi-code/sessions/wd/session-2/agents/agent-0/wire.jsonl",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 || res.Events[0].SubAgent != "agent-0" || res.Events[1].SubAgent != "agent-0" {
		t.Fatalf("events = %+v", res.Events)
	}
}

func TestKimiCodeExtractOnlyTreatsUserOriginAsPrompt(t *testing.T) {
	fixture := `{"type":"metadata","protocol_version":"1.1","created_at":1784710800000}
{"type":"turn.prompt","input":[{"type":"text","text":"generated"}],"origin":{"kind":"injection","variant":"task"},"time":1784710801000}
{"type":"turn.prompt","input":[{"type":"text","text":"human"}],"origin":{"kind":"user"},"time":1784710802000}
`
	res, err := (KimiCodeExtractor{}).Extract(strings.NewReader(fixture), Source{Path: "/x/.kimi-code/sessions/w/s/agents/main/wire.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 || res.Events[1].ContentPreview != "human" {
		t.Fatalf("events = %+v", res.Events)
	}
}

func TestKimiCodeExtractToleratesMalformedAndUnknownRecords(t *testing.T) {
	fixture := "{bad\n" +
		`{"protocol_version":"1.1"}` + "\n" +
		`{"type":"metadata"}` + "\n" +
		`{"type":"future.state.operation","secret":"do not leak"}` + "\n"
	res, err := (KimiCodeExtractor{}).Extract(strings.NewReader(fixture), Source{Path: "/x/wire.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 || len(res.Diagnostics) != 3 {
		t.Fatalf("events = %+v diagnostics = %+v", res.Events, res.Diagnostics)
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Msg, "secret") {
			t.Errorf("diagnostic leaks content: %+v", d)
		}
	}
}

func TestKimiCodeExtractRejectsOversizeArtifact(t *testing.T) {
	_, err := (KimiCodeExtractor{maxBytes: 8}).Extract(strings.NewReader(strings.Repeat("x", 9)), Source{Path: "/x/wire.jsonl"})
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("error = %v", err)
	}
}

func TestKimiPathContext(t *testing.T) {
	session, sub := kimiPathContext(`/home/u/.kimi-code/sessions/wd_x/session-3/agents/agent-7/wire.jsonl`)
	if session != "session-3" || sub != "agent-7" {
		t.Fatalf("context = %q/%q", session, sub)
	}
	session, sub = kimiPathContext(`/home/u/.kimi-code/sessions/wd_x/session-3/agents/main/wire.jsonl`)
	if session != "session-3" || sub != "" {
		t.Fatalf("main context = %q/%q", session, sub)
	}
	session, sub = kimiPathContext(`/home/u/.kimi-code/sessions/wd_x/session-4/agents/agent-1/wire.JSONL`)
	if session != "session-4" || sub != "agent-1" {
		t.Fatalf("case-insensitive wire context = %q/%q", session, sub)
	}
}

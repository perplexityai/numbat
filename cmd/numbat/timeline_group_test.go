package main

import (
	"encoding/json"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func ev(agent, session, ts string, et model.EventType, path string) model.Event {
	return model.Event{
		SourceAgent: agent,
		SessionID:   session,
		Timestamp:   ts,
		EventType:   et,
		Evidence:    model.Evidence{LocalPath: path},
	}
}

// Events split into one session per (source_agent, source_type, session_id), and
// the sessions come back in Start order regardless of input order.
func TestGroupSessionsPartitionsBySessionAndOrders(t *testing.T) {
	in := []model.Event{
		ev("claude-code", "s2", "2026-06-02T11:00:00Z", model.EventPromptUser, "/a"),
		ev("claude-code", "s1", "2026-06-02T10:00:00Z", model.EventPromptUser, "/a"),
		ev("codex", "s1", "2026-06-02T09:00:00Z", model.EventPromptUser, "/b"),
	}
	got := groupSessions(in)
	if len(got) != 3 {
		t.Fatalf("got %d sessions, want 3", len(got))
	}
	// codex/s1 (09:00) < claude/s1 (10:00) < claude/s2 (11:00).
	want := []struct{ agent, session string }{
		{"codex", "s1"}, {"claude-code", "s1"}, {"claude-code", "s2"},
	}
	for i, w := range want {
		if got[i].SourceAgent != w.agent || got[i].SessionID != w.session {
			t.Errorf("session %d = %s/%s, want %s/%s", i, got[i].SourceAgent, got[i].SessionID, w.agent, w.session)
		}
	}
	// (claude-code, s1) and (codex, s1) share an id but are different sessions.
	if len(got[0].Events) != 1 || len(got[1].Events) != 1 {
		t.Errorf("same session_id across agents was merged")
	}
}

func TestGroupSessionsPartitionsBySourceType(t *testing.T) {
	artifact := ev("claude-code", "s1", "2026-06-02T10:00:00Z", model.EventPromptUser, "/a")
	artifact.SourceType = model.SourceArtifact
	hook := ev("claude-code", "s1", "2026-06-02T10:00:01Z", model.EventCommandExec, "/a")
	hook.SourceType = model.SourceHook

	got := groupSessions([]model.Event{hook, artifact})
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2 (artifact and hook split)", len(got))
	}
	if got[0].Events[0].SourceType == got[1].Events[0].SourceType {
		t.Fatalf("source types were merged: %+v", got)
	}
}

func TestGroupSessionsKeepsSubagentsDistinct(t *testing.T) {
	parent := ev("codex", "root-1", "2026-08-31T17:04:00Z", model.EventCommandExec, "/parent.jsonl")
	child := func(id, ts string) model.Event {
		ev := ev("codex", id, ts, model.EventCommandExec, "/"+id+".jsonl")
		ev.SessionTreeID = "root-1"
		ev.ParentSessionID = "root-1"
		ev.SubAgent = "default"
		ev.SubAgentID = id
		return ev
	}
	got := groupSessions([]model.Event{
		child("child-2", "2026-08-31T17:04:02Z"),
		parent,
		child("child-1", "2026-08-31T17:04:01Z"),
	})
	if len(got) != 3 {
		t.Fatalf("got %d sessions, want parent plus two children", len(got))
	}
	for _, session := range got {
		if session.SessionID == "root-1" {
			continue
		}
		if session.SessionTreeID != "root-1" || session.ParentSessionID != "root-1" || session.SubAgent != "default" || session.SubAgentID != session.SessionID {
			t.Fatalf("child session context = %+v", session)
		}
	}
}

func TestGroupSessionsUsesChildIDWhenHostSessionIsShared(t *testing.T) {
	child := func(id, ts string) model.Event {
		ev := ev("codex", "shared-tree", ts, model.EventCommandExec, "")
		ev.SourceType = model.SourceHook
		ev.SubAgent = "default"
		ev.SubAgentID = id
		return ev
	}
	got := groupSessions([]model.Event{
		child("child-1", "2026-08-31T17:04:01Z"),
		child("child-2", "2026-08-31T17:04:02Z"),
	})
	if len(got) != 2 || got[0].SubAgentID == got[1].SubAgentID {
		t.Fatalf("shared host session collapsed concurrent children: %+v", got)
	}
}

// Within a session, events sort by timestamp ascending; ties and empty timestamps
// keep their original input (artifact emission) order via the index tiebreaker.
func TestGroupSessionsOrdersWithinSession(t *testing.T) {
	in := []model.Event{
		ev("claude-code", "s1", "2026-06-02T10:00:02Z", model.EventCommandExec, "/a"),
		ev("claude-code", "s1", "2026-06-02T10:00:00Z", model.EventPromptUser, "/a"),
		ev("claude-code", "s1", "2026-06-02T10:00:01Z", model.EventFileRead, "/a"),
		// two with equal timestamps: must keep input order (write before delete)
		ev("claude-code", "s1", "2026-06-02T10:00:03Z", model.EventFileWrite, "/a"),
		ev("claude-code", "s1", "2026-06-02T10:00:03Z", model.EventFileDelete, "/a"),
	}
	got := groupSessions(in)
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1", len(got))
	}
	wantOrder := []model.EventType{
		model.EventPromptUser, model.EventFileRead, model.EventCommandExec,
		model.EventFileWrite, model.EventFileDelete,
	}
	for i, w := range wantOrder {
		if got[0].Events[i].EventType != w {
			t.Errorf("event %d = %s, want %s", i, got[0].Events[i].EventType, w)
		}
	}
	if got[0].Start != "2026-06-02T10:00:00Z" || got[0].End != "2026-06-02T10:00:03Z" {
		t.Errorf("span = %s..%s, want 10:00:00..10:00:03", got[0].Start, got[0].End)
	}
}

func TestGroupSessionsOrdersRFC3339OffsetsChronologically(t *testing.T) {
	laterLexicallyEarly := ev("codex", "s1", "2026-06-02T08:00:00-05:00", model.EventCommandExec, "/a") // 13:00Z
	earlier := ev("codex", "s1", "2026-06-02T12:00:00Z", model.EventPromptUser, "/a")

	got := groupSessions([]model.Event{laterLexicallyEarly, earlier})
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1", len(got))
	}
	if got[0].Events[0].EventType != model.EventPromptUser {
		t.Fatalf("first event = %s, want prompt.user (12:00Z before 08:00-05:00)", got[0].Events[0].EventType)
	}
	if got[0].Start != "2026-06-02T12:00:00Z" || got[0].End != "2026-06-02T08:00:00-05:00" {
		t.Fatalf("span = %s..%s, want chronological offset-aware bounds", got[0].Start, got[0].End)
	}
}

// Events with no session_id are kept together per artifact path, never merged
// across files — two pathless-session files stay two sessions.
func TestGroupSessionsEmptySessionKeyedByArtifact(t *testing.T) {
	in := []model.Event{
		ev("codex", "", "2026-06-02T10:00:00Z", model.EventPromptUser, "/rollout-a.jsonl"),
		ev("codex", "", "2026-06-02T10:00:01Z", model.EventCommandExec, "/rollout-a.jsonl"),
		ev("codex", "", "2026-06-02T10:00:00Z", model.EventPromptUser, "/rollout-b.jsonl"),
	}
	got := groupSessions(in)
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2 (one per artifact)", len(got))
	}
	for _, s := range got {
		if s.SessionID != "" {
			t.Errorf("session id = %q, want empty", s.SessionID)
		}
	}
	// rollout-a contributed two events, rollout-b one — neither was merged.
	counts := map[string]int{}
	for _, s := range got {
		counts[s.Events[0].Evidence.LocalPath] = len(s.Events)
	}
	if counts["/rollout-a.jsonl"] != 2 || counts["/rollout-b.jsonl"] != 1 {
		t.Errorf("artifact event counts = %v, want a:2 b:1", counts)
	}
}

func TestGroupSessionsEmptyLiveSessionUsesEventBoundary(t *testing.T) {
	first := ev("codex", "", "2026-06-02T10:00:00Z", model.EventPromptUser, "")
	first.SourceType = model.SourceHook
	first.EventID = "hook-1"
	second := ev("codex", "", "2026-06-02T10:00:01Z", model.EventCommandExec, "")
	second.SourceType = model.SourceHook
	second.EventID = "hook-2"

	got := groupSessions([]model.Event{first, second})
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2 standalone pathless live events", len(got))
	}
}

// ProjectPath is lifted from the first event in session order that carries one,
// even when the very first event has none.
func TestGroupSessionsLiftsProjectPath(t *testing.T) {
	in := []model.Event{
		ev("claude-code", "s1", "2026-06-02T10:00:00Z", model.EventSessionStart, "/a"),
		func() model.Event {
			e := ev("claude-code", "s1", "2026-06-02T10:00:01Z", model.EventPromptUser, "/a")
			e.ProjectPath = "/home/dev/proj"
			return e
		}(),
	}
	got := groupSessions(in)
	if len(got) != 1 || got[0].ProjectPath != "/home/dev/proj" {
		t.Errorf("project_path = %q, want /home/dev/proj", got[0].ProjectPath)
	}
}

func TestGroupSessionsDoesNotSplitConversationByProjectPath(t *testing.T) {
	history := ev("codex", "s1", "2026-06-02T09:59:59Z", model.EventPromptUser, "/history.jsonl")
	// Codex history rows often carry only the session id. They should merge into
	// the conversation timeline when the rollout is also scanned.
	transcript := ev("codex", "s1", "2026-06-02T10:00:00Z", model.EventCommandExec, "/rollout.jsonl")
	transcript.ProjectPath = "/repo/a"
	laterTurn := ev("codex", "s1", "2026-06-02T10:10:00Z", model.EventFileWrite, "/rollout.jsonl")
	laterTurn.ProjectPath = "/repo/b"

	got := groupSessions([]model.Event{laterTurn, history, transcript})
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want one conversation despite missing/changing project paths", len(got))
	}
	if got[0].ProjectPath != "/repo/a" {
		t.Fatalf("project_path = %q, want first non-empty project in session order", got[0].ProjectPath)
	}
	if len(got[0].Events) != 3 {
		t.Fatalf("events = %d, want 3", len(got[0].Events))
	}
}

// Two same-agent empty-session artifacts with IDENTICAL start timestamps must
// still order deterministically: the partition key (artifact path) is carried
// into the session sort as a total tiebreaker, so neither input order nor scan
// order can change the result. Without the artifact tiebreaker these two groups
// compare equal (same Start, same SourceAgent, same empty SessionID) and fall
// back to input order, breaking byte-identical determinism.
func TestGroupSessionsEmptySessionSameStartDeterministic(t *testing.T) {
	mk := func() []model.Event {
		return []model.Event{
			ev("codex", "", "2026-06-02T10:00:00Z", model.EventPromptUser, "/rollout-a.jsonl"),
			ev("codex", "", "2026-06-02T10:00:00Z", model.EventPromptUser, "/rollout-b.jsonl"),
		}
	}
	forward := mk()
	reversed := []model.Event{mk()[1], mk()[0]}

	a := groupSessions(forward)
	b := groupSessions(reversed)
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("got %d / %d sessions, want 2 / 2", len(a), len(b))
	}
	// Order-independence: artifact path breaks the tie, so a sorts before b in both.
	wantPaths := []string{"/rollout-a.jsonl", "/rollout-b.jsonl"}
	for i, w := range wantPaths {
		if a[i].Events[0].Evidence.LocalPath != w {
			t.Errorf("forward session %d path = %q, want %q", i, a[i].Events[0].Evidence.LocalPath, w)
		}
		if b[i].Events[0].Evidence.LocalPath != w {
			t.Errorf("reversed session %d path = %q, want %q", i, b[i].Events[0].Evidence.LocalPath, w)
		}
	}

	// Byte-identical grouped output across runs and across input orderings.
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(ja) != string(jb) {
		t.Errorf("grouped output differs across input orderings:\n forward=%s\nreversed=%s", ja, jb)
	}
}

// Grouping is deterministic: shuffling the input yields identical session order
// and within-session order.
func TestGroupSessionsDeterministic(t *testing.T) {
	base := []model.Event{
		ev("claude-code", "s1", "2026-06-02T10:00:00Z", model.EventPromptUser, "/a"),
		ev("claude-code", "s1", "2026-06-02T10:00:01Z", model.EventCommandExec, "/a"),
		ev("codex", "s9", "2026-06-02T09:00:00Z", model.EventPromptUser, "/b"),
	}
	shuffled := []model.Event{base[2], base[0], base[1]}
	a := groupSessions(base)
	b := groupSessions(shuffled)
	if len(a) != len(b) {
		t.Fatalf("session counts differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].SourceAgent != b[i].SourceAgent || a[i].SessionID != b[i].SessionID || len(a[i].Events) != len(b[i].Events) {
			t.Errorf("session %d differs between orderings", i)
		}
	}
}

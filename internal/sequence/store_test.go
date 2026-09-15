package sequence

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

// hookChainRule is the hook-shaped test rule: event-count window only,
// because live hook events carry no timestamps and a wall-clock window would
// fail closed.
func hookChainRule(mut func(*rule.SequenceSpec)) rule.Rule {
	return secretThenEgress(func(s *rule.SequenceSpec) {
		s.Within = ""
		s.WithinEvents = 8
		if mut != nil {
			mut(s)
		}
	})
}

// openDB opens the shared state file the way the hook does (the caller owns
// the handle), failing the test on error.
func openDB(t *testing.T, path string) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

// newStore binds a store onto an open handle, failing the test on error.
func newStore(t *testing.T, db *bolt.DB, rules []*rule.SequenceRule, cfg Config) *Store {
	t.Helper()
	st, err := NewStore(db, rules, cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return st
}

// observeOnce opens the database, observes one event, and closes — exactly
// the lifecycle of one hook invocation.
func observeOnce(t *testing.T, path string, rules []*rule.SequenceRule, ev model.Event) []Match {
	t.Helper()
	db := openDB(t, path)
	defer db.Close()
	observation, err := newStore(t, db, rules, DefaultConfig()).Observe(ev)
	if err != nil {
		t.Fatalf("Observe(%s): %v", ev.EventID, err)
	}
	return observation.Findings
}

func TestStoreChainAcrossInvocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))

	if ms := observeOnce(t, path, rules, secretRead("e1", "", nil)); len(ms) != 0 {
		t.Fatalf("first step alone matched: %+v", ms)
	}
	ms := observeOnce(t, path, rules, egress("e2", "", nil))
	if len(ms) != 1 {
		t.Fatalf("matches = %d, want the chain to assemble across store opens", len(ms))
	}
	if len(ms[0].Links) != 2 || ms[0].Links[0].EventID != "e1" || ms[0].Links[1].EventID != "e2" {
		t.Fatalf("links = %+v", ms[0].Links)
	}
}

func TestStorePersistenceContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))
	db := openDB(t, path)
	defer db.Close()
	st := newStore(t, db, rules, DefaultConfig())

	ev := secretRead("e1", "2026-07-24T12:34:56Z", func(e *model.Event) {
		e.Tags = []string{"secret_file_read"}
		e.Confidence = model.ConfidenceMedium
		e.Command = "command-content-canary"
		e.ContentPreview = "preview-content-canary"
		e.Evidence = model.Evidence{
			ArtifactType: "claude_jsonl",
			LocalPath:    "/home/dev/.claude/projects/demo/session.jsonl",
			Line:         42,
			RowID:        7,
			JSONPointer:  "/message/content/0",
			SHA256:       strings.Repeat("a", 64),
		}
	})
	if _, err := st.Observe(ev); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketSequence).Get([]byte(sessionKey(ev)))
		if value == nil {
			return fmt.Errorf("persisted session not found")
		}
		raw = append([]byte(nil), value...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var persisted storedSession
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Entries) != 1 {
		t.Fatalf("persisted entries = %d, want 1", len(persisted.Entries))
	}
	entry := persisted.Entries[0]
	if entry.EventID != ev.EventID || entry.Timestamp != ev.Timestamp || entry.Confidence != ev.Confidence {
		t.Fatalf("persisted identity fields = %+v", entry)
	}
	if entry.Evidence != ev.Evidence {
		t.Fatalf("persisted evidence = %+v, want %+v", entry.Evidence, ev.Evidence)
	}
	if len(entry.Tags) != 1 || entry.Tags[0] != ev.Tags[0] || len(entry.Masks) != 1 || entry.Masks[0] == 0 {
		t.Fatalf("persisted tags or verdict bits = tags:%v masks:%v", entry.Tags, entry.Masks)
	}
	if strings.Contains(string(raw), ev.Command) || strings.Contains(string(raw), ev.ContentPreview) {
		t.Fatalf("persisted projection retained command or content preview: %s", raw)
	}
}

func TestStoreEmissionStatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil)) // max_matches default 1

	observeOnce(t, path, rules, secretRead("e1", "", nil))
	if ms := observeOnce(t, path, rules, egress("e2", "", nil)); len(ms) != 1 {
		t.Fatalf("first trigger = %d matches", len(ms))
	}
	// A later trigger in a fresh process must stay quiet: the emission cap
	// survived the round trip.
	if ms := observeOnce(t, path, rules, egress("e3", "", nil)); len(ms) != 0 {
		t.Fatalf("max_matches must hold across invocations, got %+v", ms)
	}
}

func TestStoreEnforcementSurvivesPersistedFindingCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	enforce := true
	r := hookChainRule(nil)
	r.Severity = model.SeverityCritical
	r.Enforce = &enforce
	rules := compile(t, r)

	db := openDB(t, path)
	st := newStore(t, db, rules, DefaultConfig())
	if _, err := st.Observe(secretRead("e1", "", nil)); err != nil {
		t.Fatal(err)
	}
	first, err := st.Observe(egress("e2", "", nil))
	if err != nil || len(first.Findings) != 1 || len(first.EnforcementRules) != 1 {
		t.Fatalf("first completion = %+v, %v", first, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openDB(t, path)
	defer db.Close()
	second, err := newStore(t, db, rules, DefaultConfig()).Observe(egress("e3", "", nil))
	if err != nil || len(second.Findings) != 0 || len(second.EnforcementRules) != 1 {
		t.Fatalf("persisted completion after max_matches = %+v, %v", second, err)
	}
}

func TestStorePersistsFatalLinkAsNonEnforceable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	enforce := true
	r := hookChainRule(func(spec *rule.SequenceSpec) {
		spec.Steps[0].Expr = `shell_commands.exists(command, command.name == "write-output")`
		spec.Steps[1].Expr = `shell_commands.exists(command, command.name == "finish")`
	})
	r.Severity = model.SeverityCritical
	r.Enforce = &enforce
	rules := compile(t, r)

	db := openDB(t, path)
	st := newStore(t, db, rules, DefaultConfig())
	partial := ev("e1", "", model.EventCommandExec, func(e *model.Event) {
		e.ToolName = "PowerShell"
		e.Command = `Write-Output ready; "unterminated`
	})
	if observation, err := st.Observe(partial); err == nil || len(observation.Findings) != 0 {
		t.Fatalf("partial observation = %+v, %v; want a diagnostic and no finding", observation, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openDB(t, path)
	defer db.Close()
	finish := ev("e2", "", model.EventCommandExec, func(e *model.Event) {
		e.Command = "finish"
	})
	observation, err := newStore(t, db, rules, DefaultConfig()).Observe(finish)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 1 {
		t.Fatalf("findings = %d, want detection retained", len(observation.Findings))
	}
	if len(observation.EnforcementRules) != 0 {
		t.Fatalf("persisted fatal link authorized enforcement: %+v", observation.EnforcementRules)
	}
}

func TestStorePersistsPreviewLinkAsDetectionOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	enforce := true
	r := rule.Rule{
		ID:       "seq.preview",
		Title:    "preview sequence",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  &enforce,
		Sequence: &rule.SequenceSpec{
			WithinEvents: 4,
			Steps: []rule.SequenceStep{
				{Expr: `shell_commands.exists(command, command.name == "stop-process")`},
				{Expr: `shell_commands.exists(command, command.name == "remove-item")`},
			},
		},
	}
	rules := compile(t, r)

	db := openDB(t, path)
	st := newStore(t, db, rules, DefaultConfig())
	first := ev("e1", "", model.EventCommandExec, func(event *model.Event) {
		event.ToolName = "PowerShell"
		event.Command = `Stop-Process -Name * -Force -WhatIf`
	})
	if _, err := st.Observe(first); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openDB(t, path)
	defer db.Close()
	final := ev("e2", "", model.EventCommandExec, func(event *model.Event) {
		event.ToolName = "PowerShell"
		event.Command = `Remove-Item C:\tmp\x -Force`
	})
	observation, err := newStore(t, db, rules, DefaultConfig()).Observe(final)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 1 || len(observation.EnforcementRules) != 0 {
		t.Fatalf("persisted preview chain = %+v, want finding without enforcement", observation)
	}
}

func TestStoreNoChainAcrossSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))

	observeOnce(t, path, rules, secretRead("e1", "", nil))
	other := egress("e2", "", func(e *model.Event) { e.SessionID = "sess-2" })
	if ms := observeOnce(t, path, rules, other); len(ms) != 0 {
		t.Fatalf("cross-session chain must not assemble, got %+v", ms)
	}
}

func TestStoreFingerprintInvalidatesStaleVerdicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))
	observeOnce(t, path, rules, secretRead("e1", "", nil))

	// Same rule id, edited first step: the persisted verdict for e1 was
	// produced by a different predicate and must not seed a chain.
	edited := compile(t, hookChainRule(func(s *rule.SequenceSpec) {
		s.Steps[0].Expr = `event.event_type == "file.read" && event.file_path.contains("id_rsa")`
	}))
	if ms := observeOnce(t, path, edited, egress("e2", "", nil)); len(ms) != 0 {
		t.Fatalf("stale verdicts from another rule set assembled a chain: %+v", ms)
	}
}

func TestStoreProjectionRevisionInvalidatesEnforcementMasks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))
	first := secretRead("e1", "", nil)
	key := sessionKey(first)

	db := openDB(t, path)
	defer db.Close()
	st := newStore(t, db, rules, DefaultConfig())
	raw, err := json.Marshal(storedSession{
		RulesHash: fingerprintForProjection(rules, "sequence-projection-v4"),
		NextSeq:   1,
		Entries: []storedEntry{{
			Seq:              0,
			EventID:          first.EventID,
			Evidence:         first.Evidence,
			Confidence:       first.Confidence,
			Masks:            []uint8{1},
			EnforcementMasks: []uint8{1},
		}},
		Rules: make([]storedRule, len(rules)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSequence).Put([]byte(key), raw)
	}); err != nil {
		t.Fatal(err)
	}

	observation, err := st.Observe(egress("e2", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Findings) != 0 || len(observation.EnforcementRules) != 0 {
		t.Fatalf("stale projection state assembled a chain: %+v", observation)
	}
}

func TestStoreWallClockWindowFailsClosedWithoutTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, secretThenEgress(nil)) // within: 30m

	observeOnce(t, path, rules, secretRead("e1", "", nil))
	if ms := observeOnce(t, path, rules, egress("e2", "", nil)); len(ms) != 0 {
		t.Fatalf("a wall-clock window without timestamps must not match, got %+v", ms)
	}
}

func TestStoreCorruptRecordDiscardedAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))
	observeOnce(t, path, rules, secretRead("e1", "", nil))

	// Corrupt the session record behind the store's back.
	key := sessionKey(secretRead("x", "", nil))
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSequence).Put([]byte(key), []byte("not json"))
	})
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}

	db = openDB(t, path)
	defer db.Close()
	st := newStore(t, db, rules, DefaultConfig())
	observation, obsErr := st.Observe(egress("e2", "", nil))
	if len(observation.Findings) != 0 {
		t.Fatalf("a corrupt window must not match, got %+v", observation.Findings)
	}
	if obsErr == nil || !strings.Contains(obsErr.Error(), "corrupt") {
		t.Fatalf("corrupt state must surface as an error, got %v", obsErr)
	}
	// The window restarted cleanly: a full fresh chain still assembles.
	observation, obsErr = st.Observe(secretRead("e3", "", nil))
	if obsErr != nil || len(observation.Findings) != 0 {
		t.Fatalf("fresh first step: %v %+v", obsErr, observation.Findings)
	}
	observation, obsErr = st.Observe(egress("e4", "", nil))
	if obsErr != nil {
		t.Fatalf("recovery second step: %v", obsErr)
	}
	if len(observation.Findings) != 1 {
		t.Fatalf("recovery chain = %d matches, want 1", len(observation.Findings))
	}
}

func TestStoreCorruptMaskShapeDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))

	ev := secretRead("e1", "", nil)
	key := sessionKey(ev)
	db := openDB(t, path)
	defer db.Close()
	st := newStore(t, db, rules, DefaultConfig())
	raw, err := json.Marshal(storedSession{
		RulesHash: st.rulesHash,
		NextSeq:   1,
		Entries: []storedEntry{{
			Seq:      0,
			EventID:  ev.EventID,
			Evidence: ev.Evidence,
			Masks:    nil,
		}},
		Rules: make([]storedRule, len(rules)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSequence).Put([]byte(key), raw)
	}); err != nil {
		t.Fatal(err)
	}

	observation, obsErr := st.Observe(egress("e2", "", nil))
	if len(observation.Findings) != 0 {
		t.Fatalf("corrupt mask shape must not match, got %+v", observation.Findings)
	}
	if obsErr == nil || !strings.Contains(obsErr.Error(), "corrupt session state discarded") {
		t.Fatalf("corrupt mask shape must surface as an error, got %v", obsErr)
	}
}

func TestStoreEvictsLeastRecentSessionPastCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))
	cfg := Config{MaxEvents: 16, MaxSessions: 2}

	inSession := func(e model.Event, sess string) model.Event {
		e.SessionID = sess
		return e
	}
	for i, sess := range []string{"A", "B", "C"} {
		db := openDB(t, path)
		if _, err := newStore(t, db, rules, cfg).Observe(inSession(secretRead("r", "", nil), sess)); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			// Distinct update times so eviction age is unambiguous.
			time.Sleep(2 * time.Millisecond)
		}
	}
	// A was evicted when C arrived; B and C survive. Check B BEFORE touching
	// A — re-observing the evicted A re-creates its session, which would
	// evict B in turn.
	db := openDB(t, path)
	defer db.Close()
	s := newStore(t, db, rules, cfg)
	observation, err := s.Observe(inSession(egress("c1", "", nil), "B"))
	if err != nil {
		t.Fatalf("observe surviving session B: %v", err)
	}
	if len(observation.Findings) != 1 {
		t.Fatalf("session B should still chain, got %d", len(observation.Findings))
	}
	observation, err = s.Observe(inSession(egress("c2", "", nil), "A"))
	if err != nil {
		t.Fatalf("observe evicted session A: %v", err)
	}
	if len(observation.Findings) != 0 {
		t.Fatalf("evicted session A must have lost its window, got %+v", observation.Findings)
	}
}

func TestStoreEvictOverExcludesJustWroteAndStillHitsCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	rules := compile(t, hookChainRule(nil))
	cfg := Config{MaxEvents: 16, MaxSessions: 2}

	db := openDB(t, path)
	defer db.Close()
	st := newStore(t, db, rules, cfg)

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSequence)
		for _, sess := range []string{"A", "B", "C"} {
			raw, err := json.Marshal(storedSession{
				RulesHash: st.rulesHash,
				UpdatedAt: 12345,
				Rules:     make([]storedRule, len(rules)),
			})
			if err != nil {
				return err
			}
			key := []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s", model.AgentClaudeCode, model.SourceArtifact, sess, model.HashPath("/repo/a")))
			if err := b.Put(key, raw); err != nil {
				return err
			}
		}
		return st.evictOver(b, []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s", model.AgentClaudeCode, model.SourceArtifact, "B", model.HashPath("/repo/a"))))
	})
	if err != nil {
		t.Fatal(err)
	}

	var count int
	keys := map[string]bool{}
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSequence)
		return b.ForEach(func(k, _ []byte) error {
			count++
			keys[string(k)] = true
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != cfg.MaxSessions {
		t.Fatalf("bucket count = %d, want %d", count, cfg.MaxSessions)
	}
	justWrote := fmt.Sprintf("%s\x00%s\x00%s\x00%s", model.AgentClaudeCode, model.SourceArtifact, "B", model.HashPath("/repo/a"))
	if !keys[justWrote] {
		t.Fatalf("justWrote session was evicted; keys=%v", keys)
	}
}

func TestStoreNilObservesNothing(t *testing.T) {
	var nilStore *Store
	observation, err := nilStore.Observe(secretRead("e1", "", nil))
	if err != nil || len(observation.Findings) != 0 || len(observation.EnforcementRules) != 0 {
		t.Fatalf("nil store must observe nothing: %v %+v", err, observation)
	}
}

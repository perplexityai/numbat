package state

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/perplexityai/numbat/internal/decision"
)

func decisionStore(t *testing.T) (*DB, decision.ContextLimits, decision.Subject, time.Time) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, decision.ContextLimits{MaxSessions: 4, MaxCalls: 8, MaxBytes: 32768, IdleTTLMS: 10000},
		decision.Subject{Installation: "fixture", Agent: "claude-code", Session: "session", EventID: "event"},
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestDecisionPrefixAndFreshness(t *testing.T) {
	db, limits, s, now := decisionStore(t)
	observe := func(phase, call string, input, result json.RawMessage) decision.Evidence {
		t.Helper()
		s.CallID = call
		e, err := db.ObserveDecision("config", decision.Observation{
			Subject: s, Phase: phase, NewSession: phase == "start", Action: input, Result: result, Complete: true,
		}, limits, now)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	observe("start", "", nil, nil)
	read := json.RawMessage(`{"tool":"read","arguments":{"key":"x"}}`)
	upload := json.RawMessage(`{"tool":"upload","arguments":{"handle":"h1"}}`)
	observe("pre", "c1", read, nil)
	observe("result", "c1", read, json.RawMessage(`{"handle":"h1","classification":"restricted"}`))
	e := observe("pre", "c2", upload, nil)
	if !e.PrefixComplete || len(e.History) != 1 || e.Concurrent || len(e.Gaps) != 0 {
		t.Fatalf("unexpected prefix: %+v", e)
	}
	r := decision.Request{Subject: e.Subject, Revision: e.Revision}
	revision, err := db.ConfirmDecision("config", r, now, 10*time.Second)
	if err != nil || revision != e.Revision {
		t.Fatalf("freshness = %d, %v", revision, err)
	}
	next := observe("pre", "c3", read, nil)
	if next.PrefixComplete || !next.Concurrent {
		t.Fatal("overlapping action was treated as serial")
	}
	if _, err := db.ConfirmDecision("config", r, now, 10*time.Second); err == nil {
		t.Fatal("old pending identity confirmed")
	}
	observe("result", "c2", upload, json.RawMessage(`{}`))
	observe("result", "c3", read, json.RawMessage(`{}`))
	e = observe("pre", "c4", upload, nil)
	if e.PrefixComplete || !slices.Contains(e.Gaps, "overlapping_or_unresolved_calls") {
		t.Fatal("concurrency gap silently cleared")
	}
}

func TestDecisionPrefixGapsAndRetention(t *testing.T) {
	for _, mode := range []string{"no_start", "resume", "missing_result", "changed_input", "evicted", "expired", "subagent"} {
		t.Run(mode, func(t *testing.T) {
			db, limits, s, now := decisionStore(t)
			if mode != "no_start" {
				_, err := db.ObserveDecision("config", decision.Observation{
					Subject: s, Phase: "start", NewSession: mode != "resume",
				}, limits, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			s.CallID = "c1"
			o := decision.Observation{Subject: s, Phase: "pre", Action: json.RawMessage(`{"tool":"read"}`), Complete: true}
			if _, err := db.ObserveDecision("config", o, limits, now); err != nil {
				t.Fatal(err)
			}
			o.Phase, o.Result = "result", json.RawMessage(`null`)
			if mode == "missing_result" {
				o.Result = nil
			}
			if mode == "changed_input" {
				o.Action = json.RawMessage(`{"tool":"different"}`)
			}
			if _, err := db.ObserveDecision("config", o, limits, now); err != nil {
				t.Fatal(err)
			}
			s.CallID = "c2"
			if mode == "subagent" {
				s.SubAgentID = "child"
			}
			if mode == "evicted" {
				limits.MaxCalls = 1
			}
			if mode == "expired" {
				now = now.Add(11 * time.Second)
			}
			e, err := db.ObserveDecision("config", decision.Observation{
				Subject: s, Phase: "pre", Action: json.RawMessage(`{"tool":"upload"}`), Complete: true,
			}, limits, now)
			if err != nil {
				t.Fatal(err)
			}
			if e.PrefixComplete {
				t.Fatalf("%s produced a complete prefix", mode)
			}
		})
	}
}

func TestDuplicateAdmissionIsNotCachedAndMutationStaysIneligible(t *testing.T) {
	db, limits, s, now := decisionStore(t)
	_, err := db.ObserveDecision("config", decision.Observation{Subject: s, Phase: "start", NewSession: true}, limits, now)
	if err != nil {
		t.Fatal(err)
	}
	s.CallID = "c1"
	o := decision.Observation{Subject: s, Phase: "pre", Action: json.RawMessage(`{"tool":"upload"}`), Complete: true}
	first, err := db.ObserveDecision("config", o, limits, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.ObserveDecision("config", o, limits, now)
	if err != nil || second.Revision == first.Revision || !second.PrefixComplete || len(second.History) != 0 {
		t.Fatalf("duplicate must get fresh revision without cached verdict: %+v %v", second, err)
	}
	o.Action = json.RawMessage(`{"tool":"different"}`)
	changed, err := db.ObserveDecision("config", o, limits, now)
	if err != nil || changed.PrefixComplete {
		t.Fatalf("mutated identity eligible: %+v %v", changed, err)
	}
}

func TestDecisionSessionByteEviction(t *testing.T) {
	original := observedSession{Generation: "fixture", Revision: 1, Started: true}
	for i := range 12 {
		original.Calls = append(original.Calls, observedCall{
			ID: fmt.Sprint(i), Action: json.RawMessage(`{"tool":"read","value":"<>&"}`),
			Result: json.RawMessage(`{ "body": "quoted \" text" }`), Outcome: "result", Complete: true,
		})
	}
	full, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, capBytes := range []int{128, 300, 512, len(full) - 1, len(full), len(full) + 1} {
		t.Run(fmt.Sprint(capBytes), func(t *testing.T) {
			s := original
			encoded, removed, err := encodeDecisionSession(&s, capBytes)
			if err != nil || len(encoded) > capBytes || len(s.Calls)+removed != len(original.Calls) {
				t.Fatalf("size=%d removed=%d err=%v", len(encoded), removed, err)
			}
			if (removed > 0) != slices.Contains(s.Gaps, "history_evicted") {
				t.Fatal("eviction gap does not match retained history")
			}
			if removed > 0 {
				larger := s
				larger.Calls = original.Calls[removed-1:]
				encoded, err := json.Marshal(larger)
				if err != nil || len(encoded) <= capBytes {
					t.Fatal("discarded more history than required")
				}
			}
		})
	}
}

func TestDecisionSessionEvictionAllocationBound(t *testing.T) {
	s := observedSession{Generation: "fixture", Revision: 1, Started: true}
	for i := range 256 {
		s.Calls = append(s.Calls, observedCall{
			ID: fmt.Sprint(i), Action: json.RawMessage(`{"tool":"read"}`),
			Result: json.RawMessage(`{}`), Outcome: "result", Complete: true,
		})
	}
	action, err := json.Marshal(map[string]string{"body": strings.Repeat("x", 512<<10)})
	if err != nil {
		t.Fatal(err)
	}
	s.Calls = append(s.Calls, observedCall{ID: "large", Action: action, Outcome: "pending", Complete: true})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	encoded, removed, err := encodeDecisionSession(&s, 128<<10)
	runtime.ReadMemStats(&after)
	if err != nil || removed != 257 || len(encoded) > 128<<10 {
		t.Fatalf("size=%d removed=%d err=%v", len(encoded), removed, err)
	}
	// Deliberately generous across platforms and race builds. Re-encoding the
	// newest 512 KiB call for every discarded predecessor exceeds this bound.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("eviction allocated %d bytes for a 512 KiB input", allocated)
	}
}

func TestDecisionMaintenanceDoesNotCopyOtherSessionHistory(t *testing.T) {
	db, limits, subject, now := decisionStore(t)
	limits.MaxSessions, limits.MaxBytes = 64, 8<<20
	result, err := json.Marshal(map[string]string{"body": strings.Repeat("x", 128<<10)})
	if err != nil {
		t.Fatal(err)
	}
	session := observedSession{
		Generation: "fixture", Revision: 1, Last: now.UnixMilli(), Started: true,
		Calls: []observedCall{{ID: "call", Action: json.RawMessage(`{}`), Result: result, Outcome: "result", Complete: true}},
	}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(decisionBucket)
		if err != nil {
			return err
		}
		for i := range 32 {
			subject.Session = fmt.Sprint("session", i)
			if err := bucket.Put(contextKey("config", subject), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(decisionBucket)
		if err := expireDecisionSessions(bucket, limits, now); err != nil {
			return err
		}
		return trimDecisionSessions(bucket, contextKey("config", subject), limits)
	})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	// Maintenance needs timestamps and sizes, not copies of 4 MiB of history.
	// Leave generous room for transaction bookkeeping and race builds.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("maintenance copied retained bodies: allocated %d bytes", allocated)
	}
}

func TestDecisionLastSeenReadsHeaderWithOrderingFallback(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      int64
		ok        bool
	}{
		{"header", `{"generation":"g","revision":1,"last":123,"calls":[]}`, 123, true},
		{"reordered", `{"calls":[],"last":123,"generation":"g","revision":1}`, 123, true},
		{"long header", `{"generation":"` + strings.Repeat("g", 300) + `","revision":1,"last":123,"calls":[]}`, 123, true},
		{"header is not body validation", `{"generation":"g","revision":1,"last":123,"calls":[`, 123, true},
		{"invalid timestamp", `{"generation":"g","revision":1,"last":"invalid","calls":[]}`, 0, false},
		{"invalid JSON", `{"generation":`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			last, ok := decisionLastSeen([]byte(tc.raw))
			if last != tc.want || ok != tc.ok {
				t.Fatalf("last=%d ok=%t, want %d %t", last, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestDecisionHeaderCannotReviveInvalidCurrentState(t *testing.T) {
	for _, suffix := range []string{
		`,"calls":[`,
		`,"calls":"invalid"}`,
		`,"last":0,"calls":[]}`,
	} {
		t.Run(suffix, func(t *testing.T) {
			db, limits, subject, now := decisionStore(t)
			raw := []byte(fmt.Sprintf(`{"generation":"g","revision":1,"last":%d,"started":true`, now.UnixMilli()) + suffix)
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				bucket, err := tx.CreateBucketIfNotExists(decisionBucket)
				if err != nil {
					return err
				}
				return bucket.Put(contextKey("config", subject), raw)
			}); err != nil {
				t.Fatal(err)
			}
			subject.CallID = "c1"
			e, err := db.ObserveDecision("config", decision.Observation{
				Subject: subject, Phase: "pre", Action: json.RawMessage(`{}`), Complete: true,
			}, limits, now)
			if err == nil && e.PrefixComplete {
				t.Fatal("header-only maintenance revived invalid or expired current evidence")
			}
			subject.Generation = "g"
			if _, err := db.ConfirmDecision("config", decision.Request{Subject: subject}, now, time.Minute); err == nil {
				t.Fatal("invalid or expired evidence passed confirmation")
			}
		})
	}
}

func TestDecisionMaintenancePreservesCurrentAndEvictsOldest(t *testing.T) {
	for _, bound := range []string{"count", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			db, limits, subject, now := decisionStore(t)
			action, err := json.Marshal(map[string]string{"body": strings.Repeat("x", 1024)})
			if err != nil {
				t.Fatal(err)
			}
			var keys [][]byte
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				bucket, err := tx.CreateBucketIfNotExists(decisionBucket)
				if err != nil {
					return err
				}
				for i := range 3 {
					subject.Session = fmt.Sprint("session", i)
					key := contextKey("config", subject)
					keys = append(keys, slices.Clone(key))
					raw, err := json.Marshal(observedSession{
						Generation: "fixture", Revision: 1, Last: now.Add(time.Duration(i) * time.Second).UnixMilli(),
						Started: true, Calls: []observedCall{{ID: "call", Action: action, Outcome: "pending", Complete: true}},
					})
					if err != nil {
						return err
					}
					if bound == "bytes" {
						limits.MaxBytes = 2 * len(raw)
					}
					if err := bucket.Put(key, raw); err != nil {
						return err
					}
				}
				if bound == "count" {
					limits.MaxSessions = 2
				}
				if err := trimDecisionSessions(bucket, keys[0], limits); err != nil {
					return err
				}
				if bucket.Get(keys[0]) == nil || bucket.Get(keys[1]) != nil || bucket.Get(keys[2]) == nil {
					t.Fatal("retention did not preserve current and newest sessions")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDecisionLongSessionCountBoundary(t *testing.T) {
	for _, maxCalls := range []int{64, 2000} {
		t.Run(fmt.Sprint(maxCalls), func(t *testing.T) {
			db, limits, subject, now := decisionStore(t)
			limits.MaxCalls, limits.MaxBytes = maxCalls, 32<<20
			// Start from a valid persisted prefix just below the boundary.
			// Replaying every prior write adds quadratic work without testing
			// a different transition.
			prefix := observedSession{Generation: "fixture", Revision: uint64(2*maxCalls - 1), Last: now.UnixMilli(), Started: true}
			for i := 1; i < maxCalls; i++ {
				prefix.Calls = append(prefix.Calls, observedCall{
					ID: fmt.Sprint("call", i), Action: json.RawMessage(`{"tool":"read"}`),
					Result: json.RawMessage(`{}`), Outcome: "result", Complete: true,
				})
			}
			raw, err := json.Marshal(prefix)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				bucket, err := tx.CreateBucketIfNotExists(decisionBucket)
				if err != nil {
					return err
				}
				return bucket.Put(contextKey("config", subject), raw)
			}); err != nil {
				t.Fatal(err)
			}
			for i := maxCalls; i <= maxCalls+2; i++ {
				subject.CallID = fmt.Sprint("call", i)
				o := decision.Observation{
					Subject: subject, Phase: "pre", Action: json.RawMessage(`{"tool":"read"}`), Complete: true,
				}
				e, err := db.ObserveDecision("config", o, limits, now)
				if err != nil {
					t.Fatal(err)
				}
				if e.PrefixComplete != (i <= limits.MaxCalls) || len(e.History) != min(i-1, limits.MaxCalls-1) {
					t.Fatalf("call %d: history=%d complete=%t gaps=%v", i, len(e.History), e.PrefixComplete, e.Gaps)
				}
				if i > limits.MaxCalls && !slices.Contains(e.Gaps, "history_evicted") {
					t.Fatalf("call %d silently regained its prefix", i)
				}
				var oldest observedCall
				if err := json.Unmarshal(e.History[0], &oldest); err != nil || oldest.ID != fmt.Sprint("call", i-maxCalls+1) {
					t.Fatalf("wrong retained suffix: oldest=%q err=%v", oldest.ID, err)
				}
				o.Phase, o.Result = "result", json.RawMessage(`{}`)
				if _, err := db.ObserveDecision("config", o, limits, now); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDecisionLargeHistoryStillBoundsBytes(t *testing.T) {
	s := observedSession{Generation: "fixture", Revision: 1, Started: true}
	result, err := json.Marshal(map[string]string{"body": strings.Repeat("x", 600)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2000 {
		s.Calls = append(s.Calls, observedCall{
			ID: fmt.Sprint("call", i), Action: json.RawMessage(`{}`),
			Result: result, Outcome: "result", Complete: true,
		})
	}
	encoded, removed, err := encodeDecisionSession(&s, 1<<20)
	if err != nil || len(encoded) > 1<<20 || removed == 0 || !slices.Contains(s.Gaps, "history_evicted") {
		t.Fatalf("bytes=%d removed=%d gaps=%v error=%v", len(encoded), removed, s.Gaps, err)
	}
}

func TestDecisionDenyReceiptAndFollowingCall(t *testing.T) {
	for _, next := range []string{"new", "repeat", "host_denial", "unexpected_result", "unexpected_failure"} {
		t.Run(next, func(t *testing.T) {
			db, limits, subject, now := decisionStore(t)
			_, err := db.ObserveDecision("config", decision.Observation{
				Subject: subject, Phase: "start", NewSession: true,
			}, limits, now)
			if err != nil {
				t.Fatal(err)
			}
			subject.CallID = "c1"
			o := decision.Observation{
				Subject: subject, Phase: "pre", Action: json.RawMessage(`{"tool":"upload"}`), Complete: true,
			}
			e, err := db.ObserveDecision("config", o, limits, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.RecordDecisionDeny("config", e, limits, now); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ConfirmDecision("config", decision.Request{Subject: e.Subject}, now, time.Second); err == nil {
				t.Fatal("completed deny request still confirmed as a pending admission")
			}
			switch next {
			case "unexpected_result":
				o.Phase, o.Result = "result", json.RawMessage(`{}`)
			case "unexpected_failure":
				o.Phase, o.Result = "failed", json.RawMessage(`{"error":"fixture"}`)
			case "host_denial":
				o.Phase = "denied"
			case "new":
				o.Subject.CallID = "c2"
			}
			after, err := db.ObserveDecision("config", o, limits, now)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(next, "unexpected_") {
				if after.PrefixComplete || !slices.Contains(after.Gaps, "outcome_after_deny_request") {
					t.Fatal("unexpected execution after a deny request did not qualify the prefix")
				}
				return
			}
			if !after.PrefixComplete || after.Concurrent || after.Revision <= e.Revision {
				t.Fatalf("following proposal lost fresh serial prefix: %+v", after)
			}
			if next == "new" && (len(after.History) != 1 ||
				!strings.Contains(string(after.History[0]), `"outcome":"deny_requested"`) ||
				strings.Contains(string(after.History[0]), `"result":`)) {
				t.Fatalf("deny request was not retained without an invented result: %s", after.History)
			}
			if next == "repeat" && len(after.History) != 0 {
				t.Fatal("same proposal was duplicated in history")
			}
		})
	}
}

func TestDecisionDenyReceiptRejectsChangedState(t *testing.T) {
	for _, change := range []string{"namespace", "generation", "revision", "action", "call", "expired"} {
		t.Run(change, func(t *testing.T) {
			db, limits, subject, now := decisionStore(t)
			subject.CallID = "c1"
			e, err := db.ObserveDecision("config", decision.Observation{
				Subject: subject, Phase: "pre", Action: json.RawMessage(`{"tool":"upload"}`), Complete: true,
			}, limits, now)
			if err != nil {
				t.Fatal(err)
			}
			namespace := "config"
			switch change {
			case "namespace":
				namespace = "other"
			case "generation":
				e.Subject.Generation = "other"
			case "revision":
				e.Revision++
			case "action":
				e.Current = json.RawMessage(`{"tool":"other"}`)
			case "call":
				e.Subject.CallID = "other"
			case "expired":
				now = now.Add(11 * time.Second)
			}
			if err := db.RecordDecisionDeny(namespace, e, limits, now); err == nil {
				t.Fatal("changed or expired receipt was accepted")
			}
		})
	}
}

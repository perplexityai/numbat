package state

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/perplexityai/numbat/internal/decision"
)

var decisionBucket = []byte("decision-context-v1")

type observedCall struct {
	ID       string          `json:"call_id"`
	Action   json.RawMessage `json:"action"`
	Result   json.RawMessage `json:"result,omitempty"`
	Outcome  string          `json:"outcome"`
	Complete bool            `json:"complete"`
}

type observedSession struct {
	Generation string         `json:"generation"`
	Revision   uint64         `json:"revision"`
	Last       int64          `json:"last"`
	Started    bool           `json:"started"`
	Closed     bool           `json:"closed"`
	Gaps       []string       `json:"gaps,omitempty"`
	Calls      []observedCall `json:"calls,omitempty"`
}

func contextKey(namespace string, s decision.Subject) []byte {
	// Call and event identities change on every callback; they do not identify
	// the session. Subagent identity is distinct even when a host reuses a
	// parent session_id.
	data, _ := json.Marshal([]string{namespace, s.Installation, s.Agent, s.SessionTree, s.Session, s.SubAgentID})
	sum := sha256.Sum256(data)
	return sum[:]
}

func (s *observedSession) gap(reason string) {
	if !slices.Contains(s.Gaps, reason) {
		s.Gaps = append(s.Gaps, reason)
	}
}

// ObserveDecision updates and snapshots the configured inference projection
// while the caller owns the DB. The caller must close it before provider I/O.
func (db *DB) ObserveDecision(namespace string, o decision.Observation, limits decision.ContextLimits, now time.Time) (decision.Evidence, error) {
	var evidence decision.Evidence
	if limits.Validate() != nil || namespace == "" || o.Subject.Installation == "" ||
		o.Subject.Agent == "" || o.Subject.Session == "" {
		return evidence, errors.New("decision context identity or limits invalid")
	}
	key := contextKey(namespace, o.Subject)
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(decisionBucket)
		if err != nil {
			return err
		}
		// Retention runs before lookup so an expired prefix cannot become fresh
		// merely by receiving another callback.
		if err := expireDecisionSessions(b, limits, now); err != nil {
			return err
		}
		var s observedSession
		raw := b.Get(key)
		exists := raw != nil
		if exists {
			if len(raw) > 2<<20 || json.Unmarshal(raw, &s) != nil ||
				now.UnixMilli()-s.Last >= int64(limits.IdleTTLMS) {
				return errors.New("decision context unreadable or expired")
			}
		} else {
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			s.Generation = hex.EncodeToString(nonce)
		}
		s.Revision++
		s.Last = now.UnixMilli()
		if o.HistoryGap {
			s.gap("capture_gap")
		}
		current := -1
		switch o.Phase {
		case "start":
			if !exists && o.NewSession {
				s.Started = true
			} else if o.NewSession {
				s.gap("repeated_session_start")
			}
		case "end":
			s.Closed = true
			s.gap("session_ended")
		case "gap":
			s.gap("capture_gap")
		case "pre", "result", "failed", "denied":
			if o.Subject.CallID == "" || !json.Valid(o.Action) {
				s.gap("missing_call_identity_or_input")
				break
			}
			for i := range s.Calls {
				if s.Calls[i].ID == o.Subject.CallID {
					current = i
					break
				}
			}
			if current >= 0 && string(s.Calls[current].Action) != string(o.Action) {
				s.gap("changed_call_input")
			}
			if o.Phase == "pre" {
				if current < 0 {
					for _, call := range s.Calls {
						if call.Outcome == "pending" {
							s.gap("overlapping_or_unresolved_calls")
						}
					}
					s.Calls = append(s.Calls, observedCall{
						ID: o.Subject.CallID, Action: slices.Clone(o.Action),
						Outcome: "pending", Complete: o.Complete,
					})
					current = len(s.Calls) - 1
				} else if current != len(s.Calls)-1 ||
					(s.Calls[current].Outcome != "pending" && s.Calls[current].Outcome != "deny_requested") {
					s.gap("reused_call_identity")
				} else {
					// A repeated proposal requires another assessment. A previous
					// deny request is never a cached verdict for this invocation.
					s.Calls[current].Outcome = "pending"
				}
			} else if current < 0 {
				s.gap("unpaired_call_outcome")
			} else {
				call := &s.Calls[current]
				if call.Outcome == "deny_requested" && o.Phase != "denied" {
					s.gap("outcome_after_deny_request")
				}
				if call.Outcome != "pending" && call.Outcome != "deny_requested" &&
					(call.Outcome != o.Phase || string(call.Result) != string(o.Result)) {
					s.gap("conflicting_call_outcome")
				}
				call.Outcome = o.Phase
				call.Result = slices.Clone(o.Result)
				call.Complete = call.Complete && o.Complete
				if (o.Phase == "result" || o.Phase == "failed") && !json.Valid(o.Result) {
					call.Complete = false
				}
			}
			if !o.Complete {
				s.gap("incomplete_observation")
			}
		default:
			return errors.New("unknown decision observation phase")
		}
		for len(s.Calls) > limits.MaxCalls {
			s.Calls = s.Calls[1:]
			current--
			s.gap("history_evicted")
		}
		// Bound a session value as well as aggregate storage. A discarded prefix
		// remains ineligible for the rest of this generation.
		capBytes := min(limits.MaxBytes, 1<<20)
		encoded, removed, err := encodeDecisionSession(&s, capBytes)
		if err != nil {
			return err
		}
		current -= removed
		if err := b.Put(key, encoded); err != nil {
			return err
		}
		if err := trimDecisionSessions(b, key, limits); err != nil {
			return err
		}
		evidence = decision.Evidence{
			Subject: o.Subject, Revision: s.Revision, Current: slices.Clone(o.Action),
			CurrentComplete: o.Complete, PrefixComplete: s.Started && !s.Closed && len(s.Gaps) == 0,
			Gaps: slices.Clone(s.Gaps),
		}
		evidence.Subject.Generation = s.Generation
		if !s.Started {
			evidence.Gaps = append(evidence.Gaps, "session_start_unobserved")
		}
		for i, call := range s.Calls {
			if i == current && o.Phase == "pre" {
				continue
			}
			if !call.Complete || call.Outcome == "pending" {
				evidence.PrefixComplete = false
				if call.Outcome == "pending" {
					evidence.Concurrent = true
				}
			}
			record, err := json.Marshal(call)
			if err != nil {
				return err
			}
			evidence.History = append(evidence.History, record)
		}
		return nil
	})
	return evidence, err
}

// RecordDecisionDeny closes an exactly matching proposal after the caller
// successfully writes a native deny response. This local observation never
// asserts that the host prevented execution; that outcome remains unobserved.
func (db *DB) RecordDecisionDeny(namespace string, expected decision.Evidence, limits decision.ContextLimits, now time.Time) error {
	if namespace == "" || expected.Subject.Generation == "" || expected.Subject.CallID == "" ||
		expected.Revision == 0 || limits.Validate() != nil {
		return errors.New("decision deny receipt identity or limits invalid")
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(decisionBucket)
		if b == nil {
			return errors.New("decision context absent")
		}
		key := contextKey(namespace, expected.Subject)
		raw := b.Get(key)
		var s observedSession
		if len(raw) == 0 || len(raw) > 2<<20 || json.Unmarshal(raw, &s) != nil ||
			s.Generation != expected.Subject.Generation || s.Revision != expected.Revision ||
			now.UnixMilli()-s.Last >= int64(limits.IdleTTLMS) || s.Closed || len(s.Calls) == 0 {
			return errors.New("decision context expired or changed")
		}
		last := &s.Calls[len(s.Calls)-1]
		if last.ID != expected.Subject.CallID || last.Outcome != "pending" ||
			string(last.Action) != string(expected.Current) {
			return errors.New("decision pending call changed")
		}
		last.Outcome = "deny_requested"
		s.Revision++
		s.Last = now.UnixMilli()
		encoded, _, err := encodeDecisionSession(&s, min(limits.MaxBytes, 1<<20))
		if err != nil {
			return err
		}
		if err := b.Put(key, encoded); err != nil {
			return err
		}
		return trimDecisionSessions(b, key, limits)
	})
}

// encodeDecisionSession drops the oldest calls without repeatedly encoding a
// potentially large newest call. The ordinary, within-budget path encodes once;
// eviction does bounded linear work over the encoded calls.
func encodeDecisionSession(s *observedSession, capBytes int) ([]byte, int, error) {
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, 0, err
	}
	if len(encoded) <= capBytes {
		return encoded, 0, nil
	}
	s.gap("history_evicted")
	sizes := make([]int, len(s.Calls))
	total := 0
	for i, call := range s.Calls {
		data, err := json.Marshal(call)
		if err != nil {
			return nil, 0, err
		}
		sizes[i] = len(data)
		total += len(data)
	}
	metadata := *s
	metadata.Calls = nil
	header, err := json.Marshal(metadata)
	if err != nil {
		return nil, 0, err
	}
	removed := 0
	for len(s.Calls) > 0 && len(header)+len(`,"calls":[]`)+total+len(s.Calls)-1 > capBytes {
		total -= sizes[removed]
		s.Calls = s.Calls[1:]
		removed++
	}
	encoded, err = json.Marshal(s)
	if err != nil || len(encoded) > capBytes {
		return nil, removed, errors.New("decision context exceeds capacity")
	}
	return encoded, removed, nil
}

// ConfirmDecision verifies the exact current admission after provider I/O.
// It never refreshes TTL or writes state as a side effect of verification.
func (db *DB) ConfirmDecision(namespace string, r decision.Request, now time.Time, ttl time.Duration) (uint64, error) {
	var revision uint64
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(decisionBucket)
		if b == nil {
			return errors.New("decision context absent")
		}
		raw := b.Get(contextKey(namespace, r.Subject))
		var s observedSession
		if len(raw) == 0 || len(raw) > 2<<20 || json.Unmarshal(raw, &s) != nil ||
			s.Generation != r.Subject.Generation || now.UnixMilli()-s.Last >= ttl.Milliseconds() || s.Closed {
			return errors.New("decision context expired or changed")
		}
		if len(s.Calls) == 0 || s.Calls[len(s.Calls)-1].ID != r.Subject.CallID {
			return errors.New("decision pending call changed")
		}
		last := s.Calls[len(s.Calls)-1]
		if last.Outcome != "pending" {
			return errors.New("decision call no longer pending")
		}
		revision = s.Revision
		return nil
	})
	return revision, err
}

func expireDecisionSessions(b *bolt.Bucket, limits decision.ContextLimits, now time.Time) error {
	c := b.Cursor()
	for key, raw := c.First(); key != nil; key, raw = c.Next() {
		last, ok := decisionLastSeen(raw)
		if !ok || now.UnixMilli()-last >= int64(limits.IdleTTLMS) {
			if err := c.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Retention needs only the timestamp, not validation of unrelated tool bodies.
// The store writes generation/revision/last before calls; bound the fast read
// and fall back for other field ordering. Current records are decoded in full.
func decisionLastSeen(raw []byte) (int64, bool) {
	if len(raw) > 2<<20 {
		return 0, false
	}
	d := json.NewDecoder(bytes.NewReader(raw[:min(len(raw), 256)]))
	if token, _ := d.Token(); token == json.Delim('{') {
		for range 3 {
			key, err := d.Token()
			if err != nil || key == "calls" {
				break
			}
			var value json.RawMessage
			if d.Decode(&value) != nil {
				break
			}
			if key == "last" {
				var last int64
				if json.Unmarshal(value, &last) == nil {
					return last, true
				}
				break
			}
		}
	}
	var metadata struct {
		Last int64 `json:"last"`
	}
	ok := json.Unmarshal(raw, &metadata) == nil
	return metadata.Last, ok
}

func trimDecisionSessions(b *bolt.Bucket, keep []byte, limits decision.ContextLimits) error {
	total, count := 0, 0
	if err := b.ForEach(func(_, raw []byte) error {
		total += len(raw)
		count++
		return nil
	}); err != nil {
		return err
	}
	if count <= limits.MaxSessions && total <= limits.MaxBytes {
		return nil
	}
	type candidate struct {
		key  []byte
		last int64
		size int
	}
	var items []candidate
	err := b.ForEach(func(key, raw []byte) error {
		if string(key) != string(keep) {
			last, ok := decisionLastSeen(raw)
			if !ok {
				return errors.New("decision context unreadable")
			}
			items = append(items, candidate{slices.Clone(key), last, len(raw)})
		}
		return nil
	})
	if err != nil {
		return err
	}
	slices.SortStableFunc(items, func(a, b candidate) int {
		if a.last < b.last {
			return -1
		}
		if a.last > b.last {
			return 1
		}
		return 0
	})
	for _, item := range items {
		if count <= limits.MaxSessions && total <= limits.MaxBytes {
			break
		}
		if err := b.Delete(item.key); err != nil {
			return err
		}
		total -= item.size
		count--
	}
	return nil
}

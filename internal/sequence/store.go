package sequence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

// Store is the persisted counterpart of Tracker for the live hook path: each
// hook invocation is a fresh process holding one event, so the session window
// lives in a bbolt bucket between invocations. Observe runs the whole
// load → append → evaluate → persist cycle inside ONE write transaction, so
// two concurrent hook processes can never lose each other's appends — the
// second simply waits on bolt's file lock (bounded by the timeout the caller
// opened the shared state database with).
//
// The persisted state is the same content-free projection the in-memory
// window holds — per-rule step verdict bits plus event id, evidence ref, tags,
// confidence, and timestamp — never command, path, URL, or content_preview, so
// the state file gains no transcript content.
// Verdict bits are only meaningful against the exact rule set and projection
// version that produced them: mismatched sessions are discarded.
//
// Hook events use an upstream timestamp when available and otherwise the hook
// receive time, so both wall-clock and event-count windows work. Per-rule
// finding-emission state persists too, so max_matches and duplicate suppression
// hold across invocations. Enforce-eligible matches are returned independently
// of that output quota.
type Store struct {
	db        *bolt.DB
	rules     []*rule.SequenceRule
	cfg       Config
	rulesHash string
}

// bucketSequence holds one record per session key. The handle is the shared
// numbat state database (see internal/state); this package owns only this
// bucket.
var bucketSequence = []byte("sequence")

const (
	maxStoredSessionBytes = 16 << 20
	// Bump sequenceProjectionRevision when projection or enforcement filtering
	// changes the meaning of persisted verdict masks.
	sequenceProjectionRevision = "sequence-projection-v5"
)

// NewStore binds a window store for one compiled rule set onto the shared
// state database, creating its bucket if needed. The caller owns the handle's
// lifecycle; the store never closes it.
func NewStore(db *bolt.DB, rules []*rule.SequenceRule, cfg Config) (*Store, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketSequence)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("sequence: init bucket: %w", err)
	}
	return &Store{
		db:        db,
		rules:     rules,
		cfg:       cfg.normalized(rules),
		rulesHash: fingerprint(rules),
	}, nil
}

// Observe feeds one event through every sequence rule against the persisted
// session window and returns detection and enforcement matches — the same
// contract as Tracker.Observe, with the session state loaded and stored inside
// one write transaction. A session record that is corrupt or was written by a
// different rule set is discarded and reported in the error; matching restarts
// from a fresh window (a documented false negative, never a fabricated chain).
func (s *Store) Observe(ev model.Event) (Observation, error) {
	if s == nil {
		return Observation{}, nil
	}
	keyStr := sessionKey(ev)
	if keyStr == "" {
		return Observation{}, nil
	}
	key := []byte(keyStr)
	var (
		observation Observation
		errs        []error
	)
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSequence)
		sess, loadErr := s.loadSession(b.Get(key))
		if loadErr != nil {
			errs = append(errs, loadErr)
		}
		var stepErrs []error
		observation, stepErrs = observeSession(s.rules, sess, ev, s.cfg.MaxEvents)
		errs = append(errs, stepErrs...)

		val, err := s.encodeSession(sess)
		if err != nil {
			return err
		}
		if err := b.Put(key, val); err != nil {
			return err
		}
		return s.evictOver(b, key)
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("sequence: store: %w", err))
	}
	return observation, errors.Join(errs...)
}

// storedSession is the on-disk shape of one correlation window.
type storedSession struct {
	RulesHash string        `json:"rules_hash"`
	UpdatedAt int64         `json:"updated_at_unix_ms"`
	NextSeq   uint64        `json:"next_seq"`
	Entries   []storedEntry `json:"entries,omitempty"`
	Rules     []storedRule  `json:"rules,omitempty"`
}

// storedEntry is one projected window entry. It retains the identity, evidence
// reference, tags, confidence, timestamp, and verdict bits needed to rebuild a
// chain. Evidence can include sensitive metadata such as a local path or source
// digest; command and content fields are not projected.
type storedEntry struct {
	Seq              uint64         `json:"seq"`
	Timestamp        string         `json:"ts,omitempty"`
	EventID          string         `json:"event_id"`
	Evidence         model.Evidence `json:"evidence"`
	Tags             []string       `json:"tags,omitempty"`
	Confidence       string         `json:"confidence,omitempty"`
	Masks            []uint8        `json:"masks"`
	EnforcementMasks []uint8        `json:"enforcement_masks"`
}

// storedRule is one rule's persisted emission bookkeeping, positional with
// the compiled rule set (the fingerprint pins that correspondence).
type storedRule struct {
	Emitted int      `json:"emitted,omitempty"`
	Seen    []string `json:"seen,omitempty"`
}

// loadSession decodes a stored session, returning a fresh one (plus a
// diagnostic error) when the record is absent-with-error, corrupt, or was
// written by a different rule set.
func (s *Store) loadSession(raw []byte) (*session, error) {
	fresh := &session{rules: make([]ruleState, len(s.rules))}
	if raw == nil {
		return fresh, nil
	}
	if len(raw) > maxStoredSessionBytes {
		return fresh, fmt.Errorf("sequence: corrupt session state discarded: %d bytes exceeds cap %d", len(raw), maxStoredSessionBytes)
	}
	var st storedSession
	if err := json.Unmarshal(raw, &st); err != nil {
		return fresh, fmt.Errorf("sequence: corrupt session state discarded: %w", err)
	}
	if st.RulesHash != s.rulesHash || len(st.Rules) != len(s.rules) {
		// Stale verdicts from another rule set must never assemble a chain.
		// Silent by design: a rules change invalidating windows is normal
		// operation, not a diagnostic-worthy fault.
		return fresh, nil
	}
	if len(st.Entries) > s.cfg.MaxEvents {
		return fresh, fmt.Errorf("sequence: corrupt session state discarded: %d entries exceeds cap %d", len(st.Entries), s.cfg.MaxEvents)
	}
	sess := &session{
		nextSeq:  st.NextSeq,
		ring:     make([]entry, 0, len(st.Entries)),
		rules:    make([]ruleState, len(s.rules)),
		eventIDs: make(map[string]struct{}, len(st.Entries)),
	}
	for entryIndex, se := range st.Entries {
		if se.EventID == "" {
			return fresh, errors.New("sequence: corrupt session state discarded: empty event_id")
		}
		if _, duplicate := sess.eventIDs[se.EventID]; duplicate {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: duplicate event_id %q", se.EventID)
		}
		if se.Seq >= st.NextSeq || entryIndex > 0 && se.Seq <= st.Entries[entryIndex-1].Seq {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: invalid sequence number for event %q", se.EventID)
		}
		if len(se.Masks) != len(s.rules) {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has %d rule masks, want %d", se.EventID, len(se.Masks), len(s.rules))
		}
		if len(se.EnforcementMasks) != len(s.rules) {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has %d enforcement masks, want %d", se.EventID, len(se.EnforcementMasks), len(s.rules))
		}
		for i, mask := range se.Masks {
			allowed := uint8(0xff)
			if steps := s.rules[i].StepCount(); steps < 8 {
				allowed = uint8(1<<steps) - 1
			}
			if mask & ^allowed != 0 {
				return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has invalid mask for rule %q", se.EventID, s.rules[i].Rule().ID)
			}
			if se.EnforcementMasks[i]&^allowed != 0 || se.EnforcementMasks[i]&^mask != 0 {
				return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has invalid enforcement mask for rule %q", se.EventID, s.rules[i].Rule().ID)
			}
		}
		if !model.IsValidConfidence(se.Confidence) {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has invalid confidence %q", se.EventID, se.Confidence)
		}
		if se.Evidence.ArtifactType == "" {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has empty evidence artifact_type", se.EventID)
		}
		e := entry{
			seq:              se.Seq,
			eventID:          se.EventID,
			evidence:         se.Evidence,
			tags:             se.Tags,
			confidence:       se.Confidence,
			masks:            se.Masks,
			enforcementMasks: se.EnforcementMasks,
		}
		e.ts, e.tsOK = parseTimestamp(se.Timestamp)
		if se.Timestamp != "" && !e.tsOK {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: entry %q has invalid timestamp", se.EventID)
		}
		sess.ring = append(sess.ring, e)
		sess.eventIDs[e.eventID] = struct{}{}
	}
	for i, sr := range st.Rules {
		if sr.Emitted < 0 || sr.Emitted > s.rules[i].MaxMatches() || len(sr.Seen) != sr.Emitted {
			return fresh, fmt.Errorf("sequence: corrupt session state discarded: invalid emission state for rule %q", s.rules[i].Rule().ID)
		}
		sess.rules[i].emitted = sr.Emitted
		if len(sr.Seen) > 0 {
			sess.rules[i].seen = make(map[string]struct{}, len(sr.Seen))
			for _, k := range sr.Seen {
				if k == "" {
					return fresh, fmt.Errorf("sequence: corrupt session state discarded: empty chain identity for rule %q", s.rules[i].Rule().ID)
				}
				if _, duplicate := sess.rules[i].seen[k]; duplicate {
					return fresh, fmt.Errorf("sequence: corrupt session state discarded: duplicate chain identity for rule %q", s.rules[i].Rule().ID)
				}
				sess.rules[i].seen[k] = struct{}{}
			}
		}
	}
	return sess, nil
}

// encodeSession serializes a session for storage: ring entries oldest-first,
// seen chain keys sorted, and the wall-clock update time that drives only
// session eviction (never matching).
func (s *Store) encodeSession(sess *session) ([]byte, error) {
	st := storedSession{
		RulesHash: s.rulesHash,
		UpdatedAt: time.Now().UnixMilli(),
		NextSeq:   sess.nextSeq,
		Rules:     make([]storedRule, len(sess.rules)),
	}
	for i := 0; i < len(sess.ring); i++ {
		e := sess.entryAt(i)
		se := storedEntry{
			Seq:              e.seq,
			EventID:          e.eventID,
			Evidence:         e.evidence,
			Tags:             e.tags,
			Confidence:       e.confidence,
			Masks:            e.masks,
			EnforcementMasks: e.enforcementMasks,
		}
		if e.tsOK {
			se.Timestamp = e.ts.Format(time.RFC3339Nano)
		}
		st.Entries = append(st.Entries, se)
	}
	for i, rs := range sess.rules {
		st.Rules[i].Emitted = rs.emitted
		if len(rs.seen) > 0 {
			keys := make([]string, 0, len(rs.seen))
			for k := range rs.seen {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			st.Rules[i].Seen = keys
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("sequence: encode session: %w", err)
	}
	return b, nil
}

// evictOver enforces the session cap inside the same transaction as the
// write: when the bucket exceeds MaxSessions, the least-recently-updated
// sessions are deleted (ties broken by key) until the cap holds. The freshly
// written session is explicitly excluded from the victim set, and enough OTHER
// sessions are deleted to bring the bucket back under the cap. Dropping a
// session whole is the documented bounded-state false negative.
func (s *Store) evictOver(b *bolt.Bucket, justWrote []byte) error {
	count := 0
	cur := b.Cursor()
	for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
		count++
	}
	over := count - s.cfg.MaxSessions
	if over <= 0 {
		return nil
	}
	// Only past the cap (rare) are the records decoded for their ages.
	type aged struct {
		key       string
		updatedAt int64
	}
	all := make([]aged, 0, count)
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		var st struct {
			UpdatedAt int64 `json:"updated_at_unix_ms"`
		}
		// A corrupt record ages as zero and is evicted first.
		_ = json.Unmarshal(v, &st)
		all = append(all, aged{key: string(k), updatedAt: st.UpdatedAt})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].updatedAt != all[j].updatedAt {
			return all[i].updatedAt < all[j].updatedAt
		}
		return all[i].key < all[j].key
	})
	deleted := 0
	for _, a := range all {
		if deleted >= over {
			break
		}
		if a.key == string(justWrote) {
			continue
		}
		if err := b.Delete([]byte(a.key)); err != nil {
			return err
		}
		deleted++
	}
	return nil
}

// fingerprint is a digest of everything that gives step verdicts their
// meaning: each rule's identity, window, cap, and every step expression, in
// load order. Any change — an edited step, a reordered source, a different
// window — yields a different fingerprint, so persisted verdict bits are
// never interpreted against rules that did not produce them.
func fingerprint(rules []*rule.SequenceRule) string {
	return fingerprintForProjection(rules, sequenceProjectionRevision)
}

func fingerprintForProjection(rules []*rule.SequenceRule, projectionRevision string) string {
	var b strings.Builder
	b.WriteString(projectionRevision)
	b.WriteByte('\n')
	for _, r := range rules {
		ru := r.Rule()
		b.WriteString(ru.ID)
		b.WriteByte(0)
		b.WriteString(ru.Version)
		b.WriteByte(0)
		b.WriteString(r.Within().String())
		b.WriteByte(0)
		b.WriteString(strconv.Itoa(r.WithinEvents()))
		b.WriteByte(0)
		b.WriteString(strconv.Itoa(r.MaxMatches()))
		b.WriteByte(0)
		b.WriteString(strconv.FormatBool(ru.IsEnforceEligible()))
		for _, step := range ru.Sequence.Steps {
			b.WriteByte(0)
			b.WriteString(step.Expr)
		}
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

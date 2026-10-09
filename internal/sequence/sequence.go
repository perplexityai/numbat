// Package sequence is the bounded, deterministic window tracker behind
// numbat's multi-step (sequence) rules. A Tracker buffers a short, projected
// window for each correlation partition and, when an event matches the final
// step of a rule's ordered chain, reports one canonical Match carrying every
// contributing event.
//
// Design properties, in order of priority:
//
//   - High precision. Agent, sensor source, session id, and project path all
//     partition the window; artifact events additionally partition on their
//     exact source path. A step predicate that errors evaluates as false,
//     and a wall-clock window whose endpoint timestamps are missing or
//     disordered never matches: every ambiguity resolves to a documented false
//     negative, never a fabricated chain.
//   - Determinism. Matching is a pure function of the observed event order
//     and the events' own timestamps. The tracker never reads the wall clock,
//     so identical input yields identical matches on every run.
//   - Bounded state. Each session holds a fixed-capacity ring of projected
//     entries — per-rule step verdict bits plus the identity fields a finding
//     needs (event id, evidence ref, tags, confidence, timestamp) and
//     deliberately none of the content fields (command, file_path, url,
//     content_preview). Sessions above the cap are evicted least-recently-active.
//     Overflow is an accepted, documented false negative.
//   - Quiet output. One canonical chain per completing event — the earliest
//     valid first step, then the earliest valid event for each later step — at
//     most max_matches findings per (rule, partition), and an emitted-chain
//     cache so re-observing the same events never duplicates a finding. An
//     independent control channel keeps enforce-eligible matches uncapped.
//
// The Tracker is the in-memory window, safe for concurrent Observe calls:
// scan drives it from one goroutine, collect from its HTTP handlers. The live
// hook runs one process per event and uses the Store instead, which persists
// the same partitioned state in bbolt between invocations (see store.go).
package sequence

import (
	"container/list"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

// Config bounds the tracker's state. A non-positive field falls back to its
// DefaultConfig value, so the bounds are always finite.
type Config struct {
	// MaxEvents is the per-partition ring capacity. NewTracker raises it to the
	// largest within_events any rule declares, so a rule's own event window
	// always fits its buffer.
	MaxEvents int
	// MaxSessions caps concurrently tracked partitions; the least-recently
	// active partition is dropped past the cap.
	MaxSessions int
}

// DefaultConfig returns the standard bounds: 256 buffered events per partition,
// 4096 tracked partitions.
func DefaultConfig() Config { return Config{MaxEvents: 256, MaxSessions: 4096} }

// normalized applies defaults to non-positive fields and raises MaxEvents to
// the largest within_events any rule declares, so a rule's own event window
// always fits its buffer. Shared by the Tracker and the Store so both honor
// the same bounds.
func (c Config) normalized(rules []*rule.SequenceRule) Config {
	def := DefaultConfig()
	if c.MaxEvents <= 0 {
		c.MaxEvents = def.MaxEvents
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = def.MaxSessions
	}
	for _, r := range rules {
		if we := r.WithinEvents(); we > c.MaxEvents {
			c.MaxEvents = we
		}
	}
	return c
}

// sessionKey is stricter than timeline grouping. Correlation partitions on the
// hashed project path and, for at-rest events, an exact source-path digest:
// scan processes complete files in discovery order, so relative order across
// files is not evidence of an activity sequence. Live events have no artifact
// boundary and therefore require a real session id.
func sessionKey(ev model.Event) string {
	if ev.SessionID == "" && ev.SourceType != model.SourceArtifact {
		return ""
	}
	artifact := ""
	if ev.SourceType == model.SourceArtifact {
		if ev.Evidence.LocalPath == "" {
			return ""
		}
		artifact = "sha256:" + model.HashContent([]byte(ev.Evidence.LocalPath))
	}
	project := ""
	if ev.ProjectPath != "" {
		project = model.HashPath(ev.ProjectPath)
	}
	parts := []string{ev.SourceAgent, ev.SourceType, ev.SessionID, project}
	if artifact != "" {
		parts = append(parts, artifact)
	}
	return strings.Join(parts, "\x00")
}

// Link is one event's contribution to a matched chain: the identity a finding
// needs, none of the content.
type Link struct {
	EventID    string
	Evidence   model.Evidence
	Tags       []string
	Confidence string
}

// Match is one matched chain. Links holds every contributing event in chain
// order (the last link is the final-step event); Final is that event in full
// for the finding's observed_* fields.
type Match struct {
	Rule  rule.Rule
	Links []Link
	Final model.Event
}

// Observation separates detection output from control decisions. Findings is
// bounded by a rule's max_matches setting; EnforcementRules contains every
// enforce-eligible rule whose chain matched the event. A finding-noise limit
// must never become a policy bypass after the first match.
type Observation struct {
	Findings         []Match
	EnforcementRules []rule.Rule
}

// entry is the projected window record for one observed event. masks[i] bit j
// records a predicate match; enforcementMasks records that the same match also
// passed the static enforcement gate. A failed predicate simply leaves its bit
// clear, so uncertainty is scoped to the exact rule step it affected.
type entry struct {
	seq              uint64
	ts               time.Time
	tsOK             bool
	eventID          string
	evidence         model.Evidence
	tags             []string
	confidence       string
	masks            []uint8
	enforcementMasks []uint8
}

// ruleState is the per-(partition, rule) emission bookkeeping of §match
// semantics: how many chains have been emitted and which exact chains, so the
// cap and the duplicate suppression are both enforced.
type ruleState struct {
	emitted int
	seen    map[string]struct{}
}

// session is one tracked correlation partition: a fixed-capacity ring of
// projected entries plus per-rule emission state. The ring grows lazily to
// its cap, then start advances over the oldest entry; len(ring) is always the
// live entry count.
type session struct {
	ring     []entry
	start    int
	nextSeq  uint64
	rules    []ruleState
	eventIDs map[string]struct{}
	lru      *list.Element
}

// Tracker holds every correlation window for one compiled rule set. Construct
// with NewTracker; the zero value is unusable.
type Tracker struct {
	mu       sync.Mutex
	rules    []*rule.SequenceRule
	cfg      Config
	sessions map[string]*session
	order    *list.List // LRU: front = least recently active; values are session keys
}

// NewTracker builds a tracker for the compiled sequence rules. The ring
// capacity is raised to the largest declared within_events so a rule's event
// window always fits; a wall-clock window wider than the ring can still
// overflow it, which is the documented bounded-memory false negative.
func NewTracker(rules []*rule.SequenceRule, cfg Config) *Tracker {
	return &Tracker{
		rules:    rules,
		cfg:      cfg.normalized(rules),
		sessions: make(map[string]*session),
		order:    list.New(),
	}
}

// Observe feeds one event through every sequence rule and returns its detection
// and enforcement matches in rule load order. Step-evaluation errors are joined
// into the returned error alongside any matches (mirroring Engine.Eval); an
// erroring step counts as false, so an error can suppress a chain but never
// invent one. Observe is nil-safe — a nil Tracker observes nothing — so a
// caller whose rule set has no sequences skips the nil check.
func (t *Tracker) Observe(ev model.Event) (Observation, error) {
	if t == nil {
		return Observation{}, nil
	}
	key := sessionKey(ev)
	if key == "" {
		return Observation{}, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	observation, errs := observeSession(t.rules, t.session(key), ev, t.cfg.MaxEvents)
	return observation, errors.Join(errs...)
}

// observeSession is the per-partition matching core shared by the in-memory
// Tracker and the persisted Store: project the event, match any chains whose
// final step it satisfies, record the emission bookkeeping, and append the
// projection to the ring. s.rules must be sized to rules — the caller owns
// session identity and locking/transaction scope.
func observeSession(rules []*rule.SequenceRule, s *session, ev model.Event, maxEvents int) (Observation, []error) {
	if s.containsEventID(ev.EventID) {
		return Observation{}, nil
	}
	e, errs := project(rules, ev, s.nextSeq)
	s.nextSeq++

	var observation Observation
	for ri, r := range rules {
		n := r.StepCount()
		if e.masks[ri]&(1<<(n-1)) == 0 {
			continue
		}
		ru := r.Rule()
		st := &s.rules[ri]
		enforceEligible := ru.IsEnforceEligible()
		if st.emitted >= r.MaxMatches() && !enforceEligible {
			continue
		}
		chain := findChain(s, r, ri, e)
		if chain == nil {
			continue
		}

		if enforceEligible {
			if trusted := findEnforcementChain(s, r, ri, e); trusted != nil {
				chain = trusted
				observation.EnforcementRules = append(observation.EnforcementRules, ru)
			}
		}

		if st.emitted >= r.MaxMatches() {
			continue
		}
		key := chainKey(ru.ID, chain, e.eventID)
		if _, dup := st.seen[key]; dup {
			continue
		}
		if st.seen == nil {
			st.seen = make(map[string]struct{})
		}
		st.seen[key] = struct{}{}
		st.emitted++
		links := make([]Link, 0, n)
		for _, c := range chain {
			links = append(links, Link{
				EventID:    c.eventID,
				Evidence:   c.evidence,
				Tags:       append([]string(nil), c.tags...),
				Confidence: c.confidence,
			})
		}
		links = append(links, Link{
			EventID:    ev.EventID,
			Evidence:   ev.Evidence,
			Tags:       append([]string(nil), ev.Tags...),
			Confidence: ev.Confidence,
		})
		observation.Findings = append(observation.Findings, Match{Rule: ru, Links: links, Final: ev})
	}

	s.append(e, maxEvents)
	return observation, errs
}

func (s *session) containsEventID(id string) bool {
	if id == "" {
		return false
	}
	_, ok := s.eventIDs[id]
	return ok
}

// session returns (creating if needed) the window for key and marks it most
// recently active. Past MaxSessions the least-recently-active session is
// dropped whole — an accepted false negative, never an error.
func (t *Tracker) session(key string) *session {
	if s, ok := t.sessions[key]; ok {
		t.order.MoveToBack(s.lru)
		return s
	}
	s := &session{rules: make([]ruleState, len(t.rules))}
	s.lru = t.order.PushBack(key)
	t.sessions[key] = s
	if len(t.sessions) > t.cfg.MaxSessions {
		oldest := t.order.Front()
		t.order.Remove(oldest)
		delete(t.sessions, oldest.Value.(string))
	}
	return s
}

// project evaluates every rule step against the event once and distills the
// verdicts plus the finding-identity fields into a window entry. The full
// event is dropped after this; only the projection is buffered.
func project(rules []*rule.SequenceRule, ev model.Event, seq uint64) (entry, []error) {
	e := entry{
		seq:              seq,
		eventID:          ev.EventID,
		evidence:         ev.Evidence,
		tags:             append([]string(nil), ev.Tags...),
		confidence:       ev.Confidence,
		masks:            make([]uint8, len(rules)),
		enforcementMasks: make([]uint8, len(rules)),
	}
	e.ts, e.tsOK = parseTimestamp(ev.Timestamp)
	var errs []error
	activations, activationErr := rule.PrepareSequenceActivations(ev, rules)
	if activationErr != nil {
		errs = append(errs, activationErr)
	}
	for ri, r := range rules {
		for si := 0; si < r.StepCount(); si++ {
			evaluation, evalErr := r.EvalStep(si, activations)
			if evalErr != nil {
				errs = append(errs, evalErr)
			}
			if evaluation.Match {
				e.masks[ri] |= 1 << si
			}
			if !evaluation.EnforcementMatch {
				continue
			}
			e.enforcementMasks[ri] |= 1 << si
		}
	}
	return e, errs
}

// parseTimestamp parses an event's RFC3339 timestamp; ok is false when the
// event carries none or it does not parse, which a wall-clock window treats
// as unverifiable.
func parseTimestamp(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// entryAt returns the i-th oldest live entry.
func (s *session) entryAt(i int) entry { return s.ring[(s.start+i)%len(s.ring)] }

// findChain searches the correlation window for the canonical chain that the
// final entry completes: the EARLIEST buffered event that satisfies the first
// step AND the rule's window relative to the final event, then greedily the
// earliest event for each later step. Greedy-earliest is exact for ordered
// subsequence matching — if any valid chain ends at the final event, this one
// exists — so there is no backtracking and no ambiguity about which events a
// finding cites. Returns the n-1 buffered links in order, or nil.
//
// Window semantics (validated at load): within_events counts the chain's
// span in observed partition events, endpoints included; within bounds
// final.ts - first.ts on event timestamps and requires both endpoints to
// carry parseable, non-disordered timestamps.
func findChain(s *session, r *rule.SequenceRule, ri int, final entry) []entry {
	return findChainWithMasks(s, r, ri, final, false)
}

func findEnforcementChain(s *session, r *rule.SequenceRule, ri int, final entry) []entry {
	n := r.StepCount()
	if final.enforcementMasks[ri]&(1<<(n-1)) == 0 {
		return nil
	}
	return findChainWithMasks(s, r, ri, final, true)
}

func findChainWithMasks(s *session, r *rule.SequenceRule, ri int, final entry, enforcement bool) []entry {
	n := r.StepCount()
	chain := make([]entry, 0, n-1)
	step := 0
	for i := 0; i < len(s.ring) && len(chain) < n-1; i++ {
		c := s.entryAt(i)
		mask := c.masks[ri]
		if enforcement {
			mask = c.enforcementMasks[ri]
		}
		if mask&(1<<step) == 0 {
			continue
		}
		if step == 0 && !firstStepInWindow(r, c, final) {
			continue
		}
		chain = append(chain, c)
		step++
	}
	if len(chain) != n-1 {
		return nil
	}
	return chain
}

// firstStepInWindow reports whether a candidate first link satisfies the
// rule's window against the completing event. Disordered timestamps (first
// later than final) fail closed: a window we cannot verify is no window.
func firstStepInWindow(r *rule.SequenceRule, first, final entry) bool {
	if we := r.WithinEvents(); we > 0 && final.seq-first.seq > uint64(we-1) {
		return false
	}
	if w := r.Within(); w > 0 {
		if !first.tsOK || !final.tsOK {
			return false
		}
		d := final.ts.Sub(first.ts)
		if d < 0 || d > w {
			return false
		}
	}
	return true
}

// chainKey is the deterministic identity of one emitted chain — the same
// rule-id + event-id material the finding id hashes — for the per-(session,
// rule) duplicate-suppression cache.
func chainKey(ruleID string, chain []entry, finalEventID string) string {
	var b strings.Builder
	b.WriteString(ruleID)
	for _, c := range chain {
		b.WriteByte(0)
		b.WriteString(c.eventID)
	}
	b.WriteByte(0)
	b.WriteString(finalEventID)
	return b.String()
}

// append pushes an entry onto the session ring, evicting the oldest entry
// once the ring is at capacity.
func (s *session) append(e entry, max int) {
	if s.eventIDs == nil {
		s.eventIDs = make(map[string]struct{}, max)
	}
	if len(s.ring) < max {
		s.ring = append(s.ring, e)
		s.eventIDs[e.eventID] = struct{}{}
		return
	}
	delete(s.eventIDs, s.ring[s.start].eventID)
	s.ring[s.start] = e
	s.eventIDs[e.eventID] = struct{}{}
	s.start = (s.start + 1) % len(s.ring)
}

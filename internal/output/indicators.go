package output

import (
	"sort"
	"sync"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

// indicatorKey identifies one distinct indicator: a (type, value) pair.
type indicatorKey struct{ typ, val string }

const (
	maxIndicatorKeys       = 10_000
	maxIndicatorValueBytes = 4_096
	maxIndicatorEventIDs   = 65_536
)

// IndicatorAccumulator folds events into deduplicated enrichment indicators
// incrementally, one event at a time, so a long scan never has to retain the
// full event stream to compute the indicator view. Materialize returns a
// cumulative snapshot and does not reset the accumulator. The zero value is not
// ready to use; call NewIndicatorAccumulator.
//
// Add and Materialize are safe for concurrent use: the live OTLP receiver serves
// requests on many goroutines (net/http one per connection) that all fold into
// the same accumulator, so mu guards every read and write of agg. The scanner
// calls these serially and pays only an uncontended lock.
type IndicatorAccumulator struct {
	mu         sync.Mutex
	agg        map[indicatorKey]*Indicator
	seenEvents map[string]struct{}
	seenOrder  []string
	seenNext   int
	truncated  bool
}

// NewIndicatorAccumulator returns an empty accumulator ready for Add.
func NewIndicatorAccumulator() *IndicatorAccumulator {
	return &IndicatorAccumulator{
		agg:        make(map[indicatorKey]*Indicator),
		seenEvents: make(map[string]struct{}),
	}
}

// add records one observation of (typ, val) carried by ev, creating the
// indicator on first sight and updating its count and first/last-seen window.
// The caller (Add) holds a.mu.
func (a *IndicatorAccumulator) add(typ, val string, ev model.Event) {
	if typ == "" || val == "" {
		return
	}
	k := indicatorKey{typ, val}
	ind, ok := a.agg[k]
	if !ok {
		if len(val) > maxIndicatorValueBytes || len(a.agg) >= maxIndicatorKeys {
			a.truncated = true
			return
		}
		ind = &Indicator{
			Type:                  typ,
			Value:                 val,
			SampleSourceAgent:     ev.SourceAgent,
			SampleEventID:         ev.EventID,
			SampleSessionID:       ev.SessionID,
			SampleProjectPathHash: model.HashPath(ev.ProjectPath),
			FirstSeen:             ev.Timestamp,
			LastSeen:              ev.Timestamp,
		}
		a.agg[k] = ind
	}
	ind.Count++
	if ev.Timestamp != "" {
		if ind.FirstSeen == "" || model.CompareTimestamps(ev.Timestamp, ind.FirstSeen) < 0 {
			ind.FirstSeen = ev.Timestamp
		}
		if ind.LastSeen == "" || model.CompareTimestamps(ind.LastSeen, ev.Timestamp) < 0 {
			ind.LastSeen = ev.Timestamp
		}
	}
}

// Add mines redacted event fields for indicators. Duplicate event ids are
// ignored. It returns true only when this call first reaches a safety limit, so
// the caller can emit one truncation diagnostic.
func (a *IndicatorAccumulator) Add(ev model.Event) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen(ev.EventID) {
		return false
	}
	wasTruncated := a.truncated
	if ev.ContentTruncatedForAnalysis() {
		a.truncated = true
	}
	a.mine(ev.URL, ev, false)
	a.mine(ev.Command, ev, false)
	content := ev.ContentForAnalysis()
	if content == "" {
		content = ev.ContentPreview
	}
	a.mine(content, ev, true)
	return !wasTruncated && a.truncated
}

func (a *IndicatorAccumulator) seen(id string) bool {
	if id == "" {
		return false
	}
	if _, ok := a.seenEvents[id]; ok {
		return true
	}
	if len(a.seenOrder) < maxIndicatorEventIDs {
		a.seenOrder = append(a.seenOrder, id)
	} else {
		delete(a.seenEvents, a.seenOrder[a.seenNext])
		a.seenOrder[a.seenNext] = id
		a.seenNext = (a.seenNext + 1) % maxIndicatorEventIDs
	}
	a.seenEvents[id] = struct{}{}
	return false
}

// mine extracts every indicator from one observed field and folds it in. The field is
// routed through redact.String first so masked credential material is gone
// before the indicator regexes run over it. The caller (Add) holds a.mu.
func (a *IndicatorAccumulator) mine(field string, ev model.Event, markdown bool) {
	if field == "" {
		return
	}
	inds, truncated := extractIndicators(redact.String(field), markdown)
	if truncated {
		a.truncated = true
	}
	for _, ind := range inds {
		a.add(ind.typ, ind.val, ev)
	}
}

// Truncated reports whether safety limits caused any indicator candidates to
// be omitted.
func (a *IndicatorAccumulator) Truncated() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.truncated
}

// Materialize returns the accumulated indicators as a deterministically ordered
// slice (by type, then value), so re-running over the same events yields
// byte-identical output. It does not reset the accumulator.
func (a *IndicatorAccumulator) Materialize() []Indicator {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Indicator, 0, len(a.agg))
	for _, ind := range a.agg {
		out = append(out, *ind)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// Indicators folds a stream of events into a deduplicated, sorted slice of
// enrichment indicators: one record per distinct (type, value) pair, with an
// observation count and first/last timestamps. It is a convenience wrapper over
// IndicatorAccumulator for callers that already hold the full event slice; the
// scanner uses the accumulator directly to avoid retaining the stream.
//
// Ordering is deterministic (type, then value) so re-running over the same
// events yields byte-identical output.
func Indicators(events []model.Event) []Indicator {
	acc := NewIndicatorAccumulator()
	for _, ev := range events {
		acc.Add(ev)
	}
	return acc.Materialize()
}

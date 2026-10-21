package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
)

type monitorKey [sha256.Size]byte

type monitorWindow struct {
	events []json.RawMessage
	bytes  int
	last   time.Time
}

// Monitor correlates passive observations, not admitted pending calls. Its
// windows never establish the complete, fresh prefix required by native deny.
// Each caller owns its capture stream; artifacts and identities stay separate.
func (c *Config) Monitor(em *output.Emitter) func(context.Context, model.Event) {
	var mu sync.Mutex
	windows := make(map[monitorKey]*monitorWindow)
	total := 0
	gate := make(chan struct{}, 1)
	withHistory := false
	for _, r := range c.Rules {
		withHistory = withHistory || r.View == decision.Session
	}
	operator, _ := json.Marshal(c.OperatorContext)
	return func(parent context.Context, ev model.Event) {
		ctx, cancel := context.WithTimeout(parent, time.Duration(c.BudgetMS)*time.Millisecond)
		defer cancel()
		phase := "observed"
		if ev.ToolResultForAnalysis() != "" {
			phase = "result"
		}
		o := decision.Project(ev, phase, c.Content)
		o.Subject.Installation, o.Subject.Generation = c.InstallationID, "observational"
		e := decision.Evidence{
			Subject: o.Subject, Current: o.Current(), CurrentComplete: o.Complete,
			OperatorContext: operator, Gaps: []string{"history_coverage_unverified"},
		}
		if withHistory && ev.Evidence.LocalPath == "" {
			e.Gaps = append(e.Gaps, "history_origin_unknown")
		}
		// A collector can receive several exporters with identical session IDs.
		// Without a captured origin, do not invent a cross-request history.
		if withHistory && ev.SessionID != "" && ev.Evidence.LocalPath != "" {
			// Keep source-controlled identity lengths outside retained map keys.
			identity, _ := json.Marshal([]string{
				ev.SourceType, ev.SourceAgent, ev.Evidence.LocalPath,
				ev.ProjectPath, ev.SessionID, ev.SessionTreeID, ev.SubAgentID,
			})
			key := monitorKey(sha256.Sum256(identity))
			mu.Lock()
			now := time.Now()
			for k, w := range windows {
				if now.Sub(w.last) >= time.Duration(c.State.IdleTTLMS)*time.Millisecond {
					total -= w.bytes
					delete(windows, k)
				}
			}
			w := windows[key]
			if w == nil {
				w = &monitorWindow{}
				windows[key] = w
			}
			w.last = now
			e.History = slices.Clone(w.events)
			current := o.Current()
			if len(current) <= min(c.State.MaxBytes, 1<<20) {
				w.events = append(w.events, current)
				w.bytes += len(current)
				total += len(current)
			}
			for len(w.events) > c.State.MaxCalls || w.bytes > min(c.State.MaxBytes, 1<<20) {
				n := len(w.events[0])
				w.events = w.events[1:]
				w.bytes -= n
				total -= n
			}
			for len(windows) > c.State.MaxSessions || total > c.State.MaxBytes {
				var oldest monitorKey
				var last time.Time
				for k, candidate := range windows {
					if last.IsZero() || candidate.last.Before(last) {
						oldest, last = k, candidate.last
					}
				}
				total -= windows[oldest].bytes
				delete(windows, oldest)
			}
			mu.Unlock()
		}
		// Bound concurrent provider work without an unbounded internal queue.
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		case <-ctx.Done():
		}
		c.Evaluate(ctx, Evaluation{
			Events: []model.Event{ev},
			Evidence: func(_ model.Event, view string) decision.Evidence {
				if view == decision.Action {
					action := e
					action.History, action.Gaps = nil, nil
					return action
				}
				return e
			},
		}, em)
	}
}

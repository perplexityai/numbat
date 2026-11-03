package evaluator

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
)

const (
	backgroundItems = 64
	backgroundBytes = 8 << 20
	backgroundAge   = 5 * time.Second
)

type backgroundJob struct {
	plan *evaluationPlan
	size int
	at   time.Time
}

// Background keeps inference off a collector's admission path. Observe is
// called under the collector's processing lock; only background result writes
// acquire that same lock, so their errors cannot taint a different export.
// Close must run after producers stop and before the shared emitter closes.
type Background struct {
	config   *Config
	emit     *output.Emitter
	outputMu sync.Locker
	snapshot func(model.Event) Evaluation
	cancel   context.CancelFunc
	done     chan struct{}
	jobs     chan backgroundJob

	mu         sync.Mutex
	items      int
	bytes      int
	closed     bool
	overloaded bool
}

func (c *Config) Background(em *output.Emitter, outputMu sync.Locker) *Background {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Background{
		config: c, emit: em, outputMu: outputMu, snapshot: c.monitorSnapshot(),
		cancel: cancel, done: make(chan struct{}), jobs: make(chan backgroundJob, backgroundItems),
	}
	go b.run(ctx)
	return b
}

// Observe snapshots history before later events arrive. It never waits for a
// provider or queue slot and does not inherit a completed HTTP request's context.
func (b *Background) Observe(_ context.Context, ev model.Event) {
	plan := b.config.prepare(b.snapshot(ev))
	selected := false
	for _, r := range plan.rules {
		selected = selected || r.invocation.selected
	}
	if !selected {
		plan.skip(b.config, b.emit, "", nil)
		return
	}
	size, err := plan.detach()
	if err != nil || size > backgroundBytes {
		plan.skip(b.config, b.emit, "queue_bytes_limit", nil)
		return
	}
	b.mu.Lock()
	reason := ""
	switch {
	case b.closed:
		reason = "collector_shutdown"
	case b.items >= backgroundItems || b.bytes+size > backgroundBytes:
		reason = "queue_full"
	default:
		b.items++
		b.bytes += size
		b.jobs <- backgroundJob{plan: plan, size: size, at: time.Now()}
	}
	warn := reason == "queue_full" && !b.overloaded
	b.overloaded = reason == "queue_full"
	b.mu.Unlock()
	if warn {
		b.emit.Diag("warn", "decision queue full; optional model checks skipped, telemetry processing continues")
	}
	if reason != "" {
		plan.skip(b.config, b.emit, reason, nil)
	}
}

func (b *Background) run(ctx context.Context) {
	defer close(b.done)
	for job := range b.jobs {
		switch {
		case ctx.Err() != nil:
			job.plan.skip(b.config, b.emit, "collector_shutdown", b.outputMu)
		case time.Since(job.at) > backgroundAge:
			job.plan.skip(b.config, b.emit, "queue_expired", b.outputMu)
		default:
			job.plan.run(ctx, b.config, b.emit, b.outputMu)
		}
		b.mu.Lock()
		b.items--
		b.bytes -= job.size
		b.mu.Unlock()
	}
}

func (b *Background) Close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.cancel()
		close(b.jobs)
	}
	b.mu.Unlock()
	<-b.done
}

// Selectors have already inspected originals. Retain only immutable finding
// metadata and the approved inference projection, not hidden raw message/tool
// bodies. The byte cap accounts for serialized metadata and evidence in flight.
func (p *evaluationPlan) detach() (int, error) {
	events := make([]model.Event, len(p.in.Events))
	for i, ev := range p.in.Events {
		ev = ev.WithoutAnalysisContent()
		ev.Content, ev.ToolInput, ev.ToolResult = "", "", ""
		events[i] = ev
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return 0, err
	}
	var detached []model.Event
	if err := json.Unmarshal(raw, &detached); err != nil {
		return 0, err
	}
	p.in.Events = detached
	size := len(raw)
	for i := range p.rules {
		job := &p.rules[i]
		job.invocation.Event = detached[job.eventIndex]
		evidence, err := json.Marshal(job.invocation.Evidence)
		if err != nil {
			return 0, err
		}
		size += len(evidence)
	}
	return size, nil
}

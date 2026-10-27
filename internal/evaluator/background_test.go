package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/rule"
)

func backgroundOffer(b *Background, mu *sync.Mutex, ev model.Event) {
	mu.Lock()
	defer mu.Unlock()
	b.Observe(context.Background(), ev)
}

func awaitBackground(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("background work did not reach the expected boundary")
	}
}

func waitBackgroundIdle(t *testing.T, b *Background) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		idle := b.items == 0
		b.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("background work did not finish")
}

func TestBackgroundQueueBoundsAndShutdown(t *testing.T) {
	for _, kind := range []string{"items", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			c, hits := runtimeConfig(t, func([]byte) {
				once.Do(func() { close(started) })
				<-release
			})
			t.Cleanup(func() { close(release) })
			if err := c.ConfigureRules([]rule.Rule{runtimeRule(decision.Action)}); err != nil {
				t.Fatal(err)
			}
			var records bytes.Buffer
			em := output.New(&records, io.Discard, "test")
			var mu sync.Mutex
			b := c.Background(em, &mu)
			t.Cleanup(b.Close)
			ev := runtimeEvent("first", "session", "/first")
			backgroundOffer(b, &mu, ev)
			awaitBackground(t, started)
			count := backgroundItems + 1
			if kind == "bytes" {
				count = 12
				ev.Command = strings.Repeat("x", 1<<20)
			}
			for range count {
				backgroundOffer(b, &mu, ev)
			}
			b.mu.Lock()
			items, size := b.items, b.bytes
			b.mu.Unlock()
			if items > backgroundItems || size > backgroundBytes || (kind == "bytes" && items >= count) {
				t.Fatalf("queue limit not enforced: items=%d bytes=%d", items, size)
			}
			b.Close()
			if hits.Load() != 1 {
				t.Fatalf("shutdown dispatched queued provider work: %d", hits.Load())
			}
			if !bytes.Contains(records.Bytes(), []byte(`"reason":"queue_full"`)) ||
				!bytes.Contains(records.Bytes(), []byte(`"reason":"collector_shutdown"`)) ||
				bytes.Contains(records.Bytes(), []byte(`"deny_candidate":true`)) {
				t.Fatalf("missing bounded-work outcomes: %s", records.Bytes())
			}
		})
	}
}

func TestBackgroundSnapshotPrecedesLaterEvents(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var requests [][]byte
	c, _ := runtimeConfig(t, func(raw []byte) {
		requests = append(requests, bytes.Clone(raw))
		if bytes.Contains(raw, []byte("/block")) && len(requests) == 1 {
			once.Do(func() { close(started) })
			<-release
		}
	})
	t.Cleanup(func() { once.Do(func() { close(started) }) })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	r := runtimeRule(decision.Session)
	r.Decision.Select = `event.file_path in ["/block", "/target"]`
	if err := c.ConfigureRules([]rule.Rule{r}); err != nil {
		t.Fatal(err)
	}
	var records bytes.Buffer
	em := output.New(&records, io.Discard, "test")
	var mu sync.Mutex
	b := c.Background(em, &mu)
	t.Cleanup(b.Close)
	backgroundOffer(b, &mu, runtimeEvent("seed", "s", "/seed"))
	backgroundOffer(b, &mu, runtimeEvent("block", "s", "/block"))
	awaitBackground(t, started)
	ev := runtimeEvent("target", "s", "/target")
	ev.Tags = []string{"original-tag"}
	backgroundOffer(b, &mu, ev)
	ev.Tags[0] = "mutated-tag"
	backgroundOffer(b, &mu, runtimeEvent("future", "s", "/future"))
	releaseOnce.Do(func() { close(release) })
	waitBackgroundIdle(t, b)
	b.Close()
	if len(requests) != 2 || !bytes.Contains(requests[1], []byte("/seed")) ||
		bytes.Contains(requests[1], []byte("/future")) {
		t.Fatalf("queued history used future or missing evidence: %q", requests)
	}
	if !bytes.Contains(records.Bytes(), []byte("original-tag")) || bytes.Contains(records.Bytes(), []byte("mutated-tag")) {
		t.Fatal("queued finding metadata changed after admission")
	}
}

func TestBackgroundExpiryAndOversizedMetadata(t *testing.T) {
	c, hits := runtimeConfig(t, nil)
	if err := c.ConfigureRules([]rule.Rule{runtimeRule(decision.Action)}); err != nil {
		t.Fatal(err)
	}
	var records bytes.Buffer
	em := output.New(&records, io.Discard, "test")
	plan := c.prepare(c.monitorSnapshot()(runtimeEvent("old", "s", "/old")))
	size, err := plan.detach()
	if err != nil {
		t.Fatal(err)
	}
	b := &Background{config: c, emit: em, done: make(chan struct{}), jobs: make(chan backgroundJob, 1), items: 1, bytes: size}
	b.jobs <- backgroundJob{plan: plan, size: size, at: time.Now().Add(-2 * backgroundAge)}
	close(b.jobs)
	b.run(context.Background())
	if hits.Load() != 0 || b.items != 0 || b.bytes != 0 ||
		!bytes.Contains(records.Bytes(), []byte(`"reason":"queue_expired"`)) {
		t.Fatal("expired work was evaluated or retained")
	}
	var mu sync.Mutex
	live := c.Background(em, &mu)
	t.Cleanup(live.Close)
	ev := runtimeEvent("large", "s", "/large")
	ev.Command = strings.Repeat("x", backgroundBytes)
	backgroundOffer(live, &mu, ev)
	live.Close()
	if hits.Load() != 0 || !bytes.Contains(records.Bytes(), []byte(`"reason":"queue_bytes_limit"`)) {
		t.Fatal("oversized metadata was admitted")
	}
}

func TestBackgroundDropsPrivateBodiesAfterSelection(t *testing.T) {
	c, _ := runtimeConfig(t, nil)
	c.Content = "redacted"
	r := runtimeRule(decision.Action)
	r.Decision.Select = `event.content.contains("private-body")`
	if err := c.ConfigureRules([]rule.Rule{r}); err != nil {
		t.Fatal(err)
	}
	ev := runtimeEvent("event", "s", "/path")
	ev.Content = "private-body"
	plan := c.prepare(c.monitorSnapshot()(ev))
	if !plan.rules[0].invocation.selected {
		t.Fatal("selector did not see the original")
	}
	if _, err := plan.detach(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan.in.Events)
	if err != nil || bytes.Contains(raw, []byte("private-body")) ||
		plan.rules[0].invocation.Event.ContentForAnalysis() != "" {
		t.Fatalf("queued metadata retained an unrelated body: %s %v", raw, err)
	}
}

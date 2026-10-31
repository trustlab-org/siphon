package googleworkspace

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	reports "google.golang.org/api/admin/reports/v1"

	"github.com/HelixY2J/collector/internal/dedupe"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/fakegws"
	"github.com/HelixY2J/collector/internal/pull"
)

type sink struct {
	mu   sync.Mutex
	seen map[string]int
}

func (k *sink) consume(ctx context.Context, out <-chan pull.Pending) {
	for {
		select {
		case p := <-out:
			k.mu.Lock()
			for _, m := range p.Batch {
				id, _ := m.MetaGet("event_id")
				k.seen[id]++
			}
			k.mu.Unlock()
			_ = p.Ack(ctx, nil)
		case <-ctx.Done():
			return
		}
	}
}

func (k *sink) has(ids []string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, id := range ids {
		if k.seen[id] == 0 {
			return false
		}
	}
	return true
}

func (k *sink) duplicates() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, c := range k.seen {
		n += c - 1
	}
	return n
}

func ids(t *testing.T, acts []*reports.Activity) []string {
	t.Helper()
	var out []string
	for _, a := range acts {
		evs, err := split(item(t, a), "login", envelope.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			out = append(out, e.id)
		}
	}
	return out
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEndToEndAgainstFakeAPI(t *testing.T) {
	fake := fakegws.New(1, 0.2)
	synth := fakegws.NewSynth(1, "example.ac.in", 20)
	api := httptest.NewServer(fake)
	defer api.Close()

	add := func(n int, at func(i int) time.Time) []*reports.Activity {
		var acts []*reports.Activity
		for i := range n {
			a := synth.Activity("login", at(i))
			fake.Add(a)
			acts = append(acts, a)
		}
		return acts
	}
	now := time.Now()
	history := add(2500, func(i int) time.Time { return now.Add(-50*time.Minute + time.Duration(i)*time.Second) })

	cl := &client{http: api.Client(), base: api.URL + "/"}
	s, _, store := newTestStream(t, cl)
	out := make(chan pull.Pending)
	s.out = out
	s.overlap = 30 * time.Minute
	s.timing = timing{interval: 20 * time.Millisecond, recheck: time.Minute, sweepInterval: 200 * time.Millisecond, initialLookback: time.Hour, maxWindow: time.Hour}
	fast := backoff.NewExponentialBackOff()
	fast.InitialInterval, fast.MaxInterval, fast.MaxElapsedTime = time.Millisecond, 5*time.Millisecond, 5*time.Second
	s.boff = fast

	k := &sink{seen: map[string]int{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go k.consume(ctx, out)

	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s.run(runCtx); close(done) }()
	eventually(t, "history delivered across pages and 429s", func() bool { return k.has(ids(t, history)) })

	late := add(10, func(int) time.Time { return time.Now().Add(-10 * time.Minute) })
	tooLate := add(1, func(int) time.Time { return time.Now().Add(-2 * time.Hour) })
	eventually(t, "late events caught by the sweep", func() bool { return k.has(ids(t, late)) })
	if d := k.duplicates(); d != 0 {
		t.Fatalf("got %d duplicates before any restart", d)
	}

	stopRun()
	<-done
	restarted := *s
	restarted.seen = dedupe.NewSeen()
	restarted.store = store
	fresh := add(5, func(int) time.Time { return time.Now() })
	go restarted.run(ctx)
	eventually(t, "events after restart", func() bool { return k.has(ids(t, fresh)) })

	if k.has(ids(t, tooLate)) {
		t.Fatal("event older than the overlap should be out of reach")
	}
	st := fake.Stats()
	if st.Throttled == 0 {
		t.Fatal("test did not exercise 429 handling")
	}
	t.Logf("requests=%d throttled=%d duplicates-after-restart=%d", st.Requests, st.Throttled, k.duplicates())
}

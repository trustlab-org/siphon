package googleworkspace

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/dedupe"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

// fakeAlerts serves alerts sorted newest-updated first, a fixed number per page.
type fakeAlerts struct {
	alerts []map[string]any
	per    int
	calls  int
}

func (f *fakeAlerts) page(_ context.Context, token string) (*alertPage, error) {
	f.calls++
	start := 0
	if token != "" {
		start = int(token[0] - '0')
	}
	end := min(start+f.per, len(f.alerts))
	p := &alertPage{Alerts: f.alerts[start:end]}
	if end < len(f.alerts) {
		p.NextPageToken = string(rune('0' + end))
	}
	return p, nil
}

func alert(id string, updated time.Time) map[string]any {
	return map[string]any{
		"customerId": "025s899b",
		"alertId":    id,
		"type":       "User's password changed",
		"source":     "User Changes",
		"createTime": updated.Add(-time.Minute).Format(time.RFC3339Nano),
		"updateTime": updated.Format(time.RFC3339Nano),
		"data":       map[string]any{"@type": "type.googleapis.com/google.apps.alertcenter.type.UserChanges", "name": "User's password changed"},
		"metadata":   map[string]any{"status": "NOT_STARTED", "severity": "LOW"},
	}
}

func newAlertTestStream(t *testing.T, p alertPager) (*alertStream, chan pull.Pending, checkpoint.Store) {
	t.Helper()
	store, err := checkpoint.OpenFile(filepath.Join(t.TempDir(), "alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan pull.Pending)
	res := service.MockResources()
	m := pull.NewMetrics(res.Metrics())
	return &alertStream{
		key:             "google_workspace_alerts/example",
		meta:            envelope.Meta{Server: "google-workspace", SourceProgram: alertsName},
		pager:           p,
		store:           store,
		seen:            dedupe.NewSeen(),
		boff:            backoff.NewExponentialBackOff(),
		interval:        time.Millisecond,
		overlap:         10 * time.Minute,
		lookback:        24 * time.Hour,
		unavailableWait: time.Millisecond,
		out:             out,
		log:             res.Logger(),
		m:               m,
		health:          pull.NewHealth(m, res.Logger(), sourceName, "alerts"),
		now:             time.Now,
	}, out, store
}

// collect acks every batch and records the alert ids it saw, in order.
func collect(out <-chan pull.Pending) func() []string {
	var got []string
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case p := <-out:
				for _, m := range p.Batch {
					var env envelope.Envelope
					raw, _ := m.AsBytes()
					_ = json.Unmarshal(raw, &env)
					var a map[string]any
					_ = json.Unmarshal([]byte(env.Raw), &a)
					got = append(got, text(a["alertId"]))
				}
				_ = p.Ack(context.Background(), nil)
			case <-stop:
				return
			}
		}
	}()
	return func() []string { close(stop); <-done; return got }
}

func TestAlertsCollectsNewThenOnlyUpdated(t *testing.T) {
	base := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	f := &fakeAlerts{per: 2, alerts: []map[string]any{
		alert("a3", base.Add(-1*time.Hour)),
		alert("a2", base.Add(-2*time.Hour)),
		alert("a1", base.Add(-3*time.Hour)),
	}}
	s, out, store := newAlertTestStream(t, f)
	finish := collect(out)
	cursor := base.Add(-24 * time.Hour)

	next, err := s.poll(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(base.Add(-1 * time.Hour)) {
		t.Fatalf("cursor = %s, want newest updateTime", next)
	}
	raw, _ := store.Get(context.Background(), s.key)
	if string(raw) != next.Format(time.RFC3339Nano) {
		t.Fatalf("stored cursor %q", raw)
	}

	f.alerts = append([]map[string]any{alert("a1", base), alert("a4", base.Add(-30*time.Minute))}, f.alerts...)
	f.calls = 0
	if _, err := s.poll(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	got := finish()

	want := []string{"a3", "a2", "a1", "a1", "a4"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if f.calls != 2 {
		t.Fatalf("second poll made %d page calls, want it to stop once past the cursor", f.calls)
	}
}

func TestAlertsEventIDStableAcrossUpdates(t *testing.T) {
	base := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	s, _, _ := newAlertTestStream(t, &fakeAlerts{per: 10})
	newest := base
	b1, _ := s.batch([]map[string]any{alert("x", base)}, base.Add(-time.Hour), map[string]time.Time{}, &newest)
	b2, _ := s.batch([]map[string]any{alert("x", base.Add(time.Hour))}, base.Add(-time.Hour), map[string]time.Time{}, &newest)
	id1, _ := b1[0].MetaGet("event_id")
	id2, _ := b2[0].MetaGet("event_id")
	if id1 == "" || id1 != id2 {
		t.Fatalf("an updated alert must keep its event id so it overwrites downstream: %q vs %q", id1, id2)
	}
}

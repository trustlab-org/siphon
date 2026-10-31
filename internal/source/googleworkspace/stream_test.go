package googleworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"
	reports "google.golang.org/api/admin/reports/v1"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/dedupe"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

type fakePager struct {
	t     testing.TB
	pages [][]*reports.Activity
	calls int
}

func (f *fakePager) page(_ context.Context, _ string, _, _ time.Time, token string) (*activityPage, error) {
	f.calls++
	i := 0
	if token != "" {
		i = int(token[0] - '0')
	}
	res := &activityPage{Items: items(f.t, f.pages[i])}
	if i+1 < len(f.pages) {
		res.NextPageToken = string(rune('0' + i + 1))
	}
	return res, nil
}

func activity(q int64, at string, names ...string) *reports.Activity {
	a := &reports.Activity{Id: &reports.ActivityId{ApplicationName: "login", CustomerId: "C1", Time: at, UniqueQualifier: q}}
	for _, n := range names {
		a.Events = append(a.Events, &reports.ActivityEvents{Type: "login", Name: n})
	}
	return a
}

func newTestStream(t *testing.T, p pager) (*stream, chan pull.Pending, checkpoint.Store) {
	t.Helper()
	store, err := checkpoint.OpenFile(filepath.Join(t.TempDir(), "cp.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan pull.Pending)
	res := service.MockResources()
	m := pull.NewMetrics(res.Metrics())
	return &stream{
		app:     "login",
		key:     "google_workspace/example.ac.in/login",
		meta:    envelope.Meta{Org: "lab", Server: "example.ac.in", SourceProgram: "google_workspace_login"},
		pager:   p,
		store:   store,
		seen:    dedupe.NewSeen(),
		boff:    backoff.NewExponentialBackOff(),
		overlap: time.Hour,
		timing:  timing{interval: time.Millisecond, recheck: time.Minute, initialLookback: time.Hour, maxWindow: time.Hour},
		out:     out,
		log:     res.Logger(),
		m:       m,
		health:  pull.NewHealth(m, res.Logger(), sourceName, "login"),
		now:     time.Now,
	}, out, store
}

// drain acks every batch with ackErr and returns the event ids it saw.
func drain(out <-chan pull.Pending, ackErr error) (<-chan []string, chan<- struct{}) {
	ids := make(chan []string, 1)
	stop := make(chan struct{})
	go func() {
		var got []string
		for {
			select {
			case p := <-out:
				for _, m := range p.Batch {
					id, _ := m.MetaGet("event_id")
					got = append(got, id)
				}
				_ = p.Ack(context.Background(), ackErr)
			case <-stop:
				ids <- got
				return
			}
		}
	}()
	return ids, stop
}

func TestWindowEmitsOncePerEventAcrossOverlap(t *testing.T) {
	p := &fakePager{t: t, pages: [][]*reports.Activity{
		{activity(1, "2026-09-30T10:00:00Z", "login_success", "login_verification")},
		{activity(2, "2026-09-30T09:59:00Z", "login_failure")},
	}}
	s, out, store := newTestStream(t, p)
	ids, stop := drain(out, nil)
	cursor := time.Date(2026, 9, 30, 9, 30, 0, 0, time.UTC)
	end := cursor.Add(time.Hour)

	if err := s.window(context.Background(), span{cursor: cursor, end: end, back: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := s.window(context.Background(), span{cursor: cursor, end: end, back: time.Hour}); err != nil {
		t.Fatal(err)
	}
	close(stop)
	got := <-ids

	if len(got) != 3 {
		t.Fatalf("want 3 events across two overlapping windows, got %d", len(got))
	}
	if p.calls != 4 {
		t.Fatalf("want 2 pages per window, got %d calls", p.calls)
	}
	raw, _ := store.Get(context.Background(), s.key)
	if string(raw) != end.Format(time.RFC3339Nano) {
		t.Fatalf("cursor = %q, want %s", raw, end.Format(time.RFC3339Nano))
	}
}

func TestNackedWindowDoesNotAdvanceCursor(t *testing.T) {
	p := &fakePager{t: t, pages: [][]*reports.Activity{{activity(1, "2026-09-30T10:00:00Z", "login_success")}}}
	s, out, store := newTestStream(t, p)
	ids, stop := drain(out, errors.New("kafka down"))
	cursor := time.Date(2026, 9, 30, 9, 30, 0, 0, time.UTC)

	if err := s.window(context.Background(), span{cursor: cursor, end: cursor.Add(time.Hour), back: time.Hour}); err == nil {
		t.Fatal("want error for nacked window")
	}
	close(stop)
	<-ids

	if raw, _ := store.Get(context.Background(), s.key); raw != nil {
		t.Fatalf("cursor advanced to %q despite nack", raw)
	}
	if s.seen.Len() != 0 {
		t.Fatal("nacked events must stay eligible for re-emit")
	}
}

func TestSplitFlattensParameters(t *testing.T) {
	a := activity(9, "2026-09-30T10:00:00Z", "login_failure")
	a.Events[0].Parameters = []*reports.ActivityEventsParameters{
		{Name: "login_type", Value: "google_password"},
		{Name: "is_suspicious"},
		{Name: "login_challenge_method", MultiValue: []string{"password", "idv_preregistered_phone"}},
	}
	evs, err := split(item(t, a), "login", envelope.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope.Envelope
	_ = json.Unmarshal(evs[0].body, &env)
	var vendor struct {
		Params map[string]any `json:"params"`
		Events []struct {
			Parameters []map[string]any `json:"parameters"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(env.Raw), &vendor); err != nil {
		t.Fatal(err)
	}
	if vendor.Params["login_type"] != "google_password" || vendor.Params["is_suspicious"] != false {
		t.Fatalf("bad params: %+v", vendor.Params)
	}
	if m, ok := vendor.Params["login_challenge_method"].([]any); !ok || len(m) != 2 {
		t.Fatalf("multi-value param lost: %+v", vendor.Params)
	}
	if len(vendor.Events[0].Parameters) != 3 {
		t.Fatal("original parameters list must be kept")
	}
}

func TestSplitProducesEnvelopePerEvent(t *testing.T) {
	a := activity(7, "2026-09-30T10:00:00Z", "login_success", "login_verification")
	raw := item(t, a)
	evs, err := split(raw, "login", envelope.Meta{Org: "lab", Server: "example.ac.in", SourceProgram: "google_workspace_login"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].id == evs[1].id {
		t.Fatalf("want 2 distinct events, got %+v", evs)
	}
	if len(raw["events"].([]any)) != 2 {
		t.Fatal("split must not mutate the activity")
	}
	var env envelope.Envelope
	if err := json.Unmarshal(evs[1].body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.EventID != evs[1].id || env.Meta.Server != "example.ac.in" {
		t.Fatalf("bad meta: %+v", env.Meta)
	}
	var vendor struct {
		Events []struct{ Name string } `json:"events"`
	}
	if err := json.Unmarshal([]byte(env.Raw), &vendor); err != nil {
		t.Fatalf("raw must be a JSON string: %v", err)
	}
	if len(vendor.Events) != 1 || vendor.Events[0].Name != "login_verification" {
		t.Fatalf("want exactly the second event, got %+v", vendor.Events)
	}
	again, _ := split(raw, "login", envelope.Meta{})
	if again[0].id != evs[0].id {
		t.Fatal("event id must be deterministic")
	}
}

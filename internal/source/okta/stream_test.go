package okta

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

const fakeBase = "https://example.okta.com" + logsPath

// fakePager serves canned pages by URL; an unknown URL is an empty page.
type fakePager struct {
	mu    sync.Mutex
	pages map[string]*page
	errs  map[string]error
	calls []string
}

func (f *fakePager) start(time.Time) string       { return fakeBase + "?start" }
func (f *fakePager) owns(u string) bool           { return strings.HasPrefix(u, fakeBase) }
func (f *fakePager) throttle(*page) time.Duration { return 0 }

func (f *fakePager) page(_ context.Context, u string) (*page, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, u)
	if err := f.errs[u]; err != nil {
		return nil, err
	}
	if p := f.pages[u]; p != nil {
		return p, nil
	}
	return &page{next: u}, nil
}

func (f *fakePager) called(u string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == u {
			return true
		}
	}
	return false
}

func events(uuids ...string) []map[string]any {
	out := make([]map[string]any, len(uuids))
	for i, u := range uuids {
		out[i] = map[string]any{"uuid": u, "published": fmt.Sprintf("2026-10-29T11:%02d:00Z", i), "eventType": "user.session.start"}
	}
	return out
}

func newTestStream(t *testing.T, p pager) (*stream, chan pull.Pending, checkpoint.Store) {
	t.Helper()
	store, err := checkpoint.OpenFile(filepath.Join(t.TempDir(), "okta.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan pull.Pending)
	res := service.MockResources()
	m := pull.NewMetrics(res.Metrics())
	return &stream{
		key:             "okta_system_log/okta/example.okta.com",
		host:            "example.okta.com",
		meta:            envelope.Meta{Org: "lab", Server: "okta", SourceProgram: sourceName},
		pager:           p,
		store:           store,
		boff:            backoff.NewExponentialBackOff(),
		interval:        time.Minute,
		lookback:        time.Hour,
		unavailableWait: time.Minute,
		pageSize:        1000,
		out:             out,
		log:             res.Logger(),
		m:               m,
		health:          pull.NewHealth(m, res.Logger(), sourceName, application),
		now:             time.Now,
	}, out, store
}

// drain acks every batch with ackErr and collects the event ids it saw.
func drain(out <-chan pull.Pending, ackErr error) (stop func() []string) {
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		for {
			select {
			case p := <-out:
				mu.Lock()
				for _, m := range p.Batch {
					id, _ := m.MetaGet("event_id")
					got = append(got, id)
				}
				mu.Unlock()
				_ = p.Ack(context.Background(), ackErr)
			case <-done:
				return
			}
		}
	}()
	return func() []string {
		close(done)
		<-exited
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

func cursorOf(t *testing.T, store checkpoint.Store) string {
	t.Helper()
	raw, err := store.Get(context.Background(), "okta_system_log/okta/example.okta.com")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestPollCommitsNextLinkAfterAck(t *testing.T) {
	p := &fakePager{pages: map[string]*page{
		fakeBase + "?start": {events: events("u-1", "u-2"), next: fakeBase + "?after=2"},
	}}
	s, out, store := newTestStream(t, p)
	stop := drain(out, nil)
	res, err := s.poll(context.Background(), fakeBase+"?start")
	ids := stop()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != envelope.ID("example.okta.com", "u-1") {
		t.Fatalf("ids = %v", ids)
	}
	if res.next != fakeBase+"?after=2" || cursorOf(t, store) != fakeBase+"?after=2" {
		t.Fatalf("next = %q, stored = %q", res.next, cursorOf(t, store))
	}
	if res.wait != time.Minute {
		t.Fatalf("a partial page must wait the poll interval, got %s", res.wait)
	}
}

func TestPollKeepsCursorOnNack(t *testing.T) {
	p := &fakePager{pages: map[string]*page{
		fakeBase + "?start": {events: events("u-1"), next: fakeBase + "?after=1"},
	}}
	s, out, store := newTestStream(t, p)
	stop := drain(out, errors.New("kafka down"))
	_, err := s.poll(context.Background(), fakeBase+"?start")
	stop()
	if err == nil {
		t.Fatal("a nacked page must fail the poll")
	}
	if got := cursorOf(t, store); got != "" {
		t.Fatalf("cursor advanced to %q despite the nack", got)
	}
}

func TestPollEmptyPageKeepsCursor(t *testing.T) {
	p := &fakePager{pages: map[string]*page{
		fakeBase + "?after=2": {next: fakeBase + "?after=3"},
	}}
	s, out, store := newTestStream(t, p)
	stop := drain(out, nil)
	res, err := s.poll(context.Background(), fakeBase+"?after=2")
	stop()
	if err != nil {
		t.Fatal(err)
	}
	if res.next != fakeBase+"?after=2" || cursorOf(t, store) != "" {
		t.Fatalf("empty page moved the cursor: next %q, stored %q", res.next, cursorOf(t, store))
	}
}

func TestPollFullPageContinuesImmediately(t *testing.T) {
	p := &fakePager{pages: map[string]*page{
		fakeBase + "?start": {events: events("u-1", "u-2"), next: fakeBase + "?after=2"},
	}}
	s, out, _ := newTestStream(t, p)
	s.pageSize = 2
	stop := drain(out, nil)
	res, err := s.poll(context.Background(), fakeBase+"?start")
	stop()
	if err != nil || res.wait != 0 {
		t.Fatalf("err %v, wait %s; a full page means more is waiting", err, res.wait)
	}
}

func TestPollSkipsMalformedButAdvances(t *testing.T) {
	evs := events("u-1")
	evs = append(evs, map[string]any{"eventType": "no.uuid"})
	p := &fakePager{pages: map[string]*page{
		fakeBase + "?start": {events: evs, next: fakeBase + "?after=2"},
	}}
	s, out, store := newTestStream(t, p)
	stop := drain(out, nil)
	_, err := s.poll(context.Background(), fakeBase+"?start")
	ids := stop()
	if err != nil || len(ids) != 1 || cursorOf(t, store) != fakeBase+"?after=2" {
		t.Fatalf("err %v, ids %v, stored %q", err, ids, cursorOf(t, store))
	}
}

func TestPollRefusesForeignNextLink(t *testing.T) {
	p := &fakePager{pages: map[string]*page{
		fakeBase + "?start": {events: events("u-1"), next: "https://evil.example.com/api/v1/logs?after=1"},
	}}
	s, out, store := newTestStream(t, p)
	stop := drain(out, nil)
	_, err := s.poll(context.Background(), fakeBase+"?start")
	stop()
	if err == nil || cursorOf(t, store) != "" {
		t.Fatalf("err %v, stored %q; a foreign next link must never be stored", err, cursorOf(t, store))
	}
}

func TestLoadCursorIgnoresForeignCursor(t *testing.T) {
	s, _, store := newTestStream(t, &fakePager{})
	ctx := context.Background()
	if err := store.Set(ctx, s.key, []byte("https://evil.example.com/api/v1/logs?after=1")); err != nil {
		t.Fatal(err)
	}
	cursor, resumed, ok := s.loadCursor(ctx)
	if !ok || resumed || cursor != fakeBase+"?start" {
		t.Fatalf("cursor %q resumed %v ok %v", cursor, resumed, ok)
	}
	if err := store.Set(ctx, s.key, []byte(fakeBase+"?after=9")); err != nil {
		t.Fatal(err)
	}
	if cursor, resumed, _ = s.loadCursor(ctx); !resumed || cursor != fakeBase+"?after=9" {
		t.Fatalf("cursor %q resumed %v", cursor, resumed)
	}
}

func TestRunRestartsWhenStoredCursorRejected(t *testing.T) {
	old := fakeBase + "?after=old"
	p := &fakePager{errs: map[string]error{old: &apiError{status: 400, code: "E0000001", summary: "since is over 180 days"}}}
	s, out, store := newTestStream(t, p)
	if err := store.Set(context.Background(), s.key, []byte(old)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx)
		close(done)
	}()
	stop := drain(out, nil)
	deadline := time.Now().Add(5 * time.Second)
	for !p.called(fakeBase+"?start") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	stop()
	if !p.called(fakeBase + "?start") {
		t.Fatal("a rejected stored cursor must restart from the lookback")
	}
}

package okta

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

const application = "system_log"

type pager interface {
	start(since time.Time) string
	owns(rawURL string) bool
	page(ctx context.Context, rawURL string) (*page, error)
	throttle(p *page) time.Duration
}

// stream follows Okta's polling chain; the cursor is the next link, saved only after the page it follows is acked.
type stream struct {
	key             string
	host            string
	meta            envelope.Meta
	pager           pager
	store           checkpoint.Store
	boff            backoff.BackOff
	interval        time.Duration
	lookback        time.Duration
	unavailableWait time.Duration
	pageSize        int
	out             chan<- pull.Pending
	log             *service.Logger
	m               pull.Metrics
	health          *pull.Health
	now             func() time.Time
}

// result says where the next poll starts and how long to wait before it.
type result struct {
	next string
	wait time.Duration
}

func (s *stream) run(ctx context.Context) {
	cursor, resumed, ok := s.loadCursor(ctx)
	if !ok {
		return
	}
	for ctx.Err() == nil {
		res, err := s.poll(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			switch {
			case resumed && badRequest(err):
				since := s.now().Add(-s.lookback)
				s.log.Errorf("okta: stored cursor rejected (%v); restarting from %s, events between the two may be missed", err, since.Format(time.RFC3339))
				cursor, resumed = s.pager.start(since), false
			case unavailable(err):
				s.health.Down(fmt.Sprintf("okta: System Log not readable (%v); check client_id, key_id, the okta.logs.read grant and the app's Read-Only Administrator role; retrying every %s", err, s.unavailableWait))
				pull.Sleep(ctx, s.unavailableWait)
			default:
				s.m.Errors.Incr(1, sourceName, application)
				s.log.Errorf("okta: poll failed: %v", err)
				pull.Sleep(ctx, s.interval)
			}
			continue
		}
		s.health.Up()
		cursor, resumed = res.next, false
		if res.wait > 0 {
			pull.Sleep(ctx, res.wait)
		}
	}
}

// poll fetches one page, waits for Bento to ack it, then commits the next link.
func (s *stream) poll(ctx context.Context, cursor string) (result, error) {
	var p *page
	err := pull.Retry(ctx, s.boff, retryable, s.onRetry, func() (err error) {
		p, err = s.pager.page(ctx, cursor)
		return err
	})
	if err != nil {
		return result{}, err
	}
	// Okta's guidance: an empty page keeps the current URL for the next poll
	if len(p.events) == 0 {
		s.m.Lag.Set(0, sourceName, application)
		return result{next: cursor, wait: max(s.interval, s.pager.throttle(p))}, nil
	}

	batch, newest := s.batch(p.events)
	if len(batch) > 0 {
		var win pull.Window
		ack := win.Track()
		select {
		case s.out <- pull.Pending{Batch: batch, Ack: ack}:
		case <-ctx.Done():
			return result{}, ctx.Err()
		}
		if err := win.Wait(ctx); err != nil {
			return result{}, fmt.Errorf("page not acknowledged: %w", err)
		}
		s.m.Emitted.Incr(int64(len(batch)), sourceName, application)
		s.m.Lag.Set(int64(s.now().Sub(newest).Seconds()), sourceName, application)
	}

	next := p.next
	switch {
	case next == "":
		next = s.pager.start(newest)
		s.log.Warnf("okta: page had no next link; resuming from %s", newest.Format(time.RFC3339Nano))
	case !s.pager.owns(next):
		return result{}, fmt.Errorf("next link %q is not this org's System Log URL", next)
	}
	if err := s.store.Set(ctx, s.key, []byte(next)); err != nil {
		return result{}, fmt.Errorf("save cursor: %w", err)
	}
	res := result{next: next, wait: s.pager.throttle(p)}
	if len(p.events) < s.pageSize {
		res.wait = max(res.wait, s.interval)
	}
	return res, nil
}

// batch converts a page; newest is the latest published time among the converted events.
func (s *stream) batch(events []map[string]any) (service.MessageBatch, time.Time) {
	var batch service.MessageBatch
	var newest time.Time
	for _, e := range events {
		ev, err := convert(e, s.host, s.meta)
		if err != nil {
			s.m.Skipped.Incr(1, sourceName, application)
			s.log.Warnf("okta: skipping malformed event: %v", err)
			continue
		}
		if ev.published.After(newest) {
			newest = ev.published
		}
		msg := service.NewMessage(ev.body)
		msg.MetaSet("event_id", ev.id)
		msg.MetaSet("source_program", s.meta.SourceProgram)
		batch = append(batch, msg)
	}
	if newest.IsZero() {
		newest = s.now()
	}
	return batch, newest
}

// loadCursor returns the stored next link, or a fresh polling URL when there is none or it fails the ownership check.
func (s *stream) loadCursor(ctx context.Context) (cursor string, resumed, ok bool) {
	for {
		raw, err := s.store.Get(ctx, s.key)
		if err == nil {
			if raw != nil && s.pager.owns(string(raw)) {
				return string(raw), true, true
			}
			if raw != nil {
				s.log.Warnf("okta: ignoring stored cursor %q, it is not this org's System Log URL", raw)
			}
			return s.pager.start(s.now().Add(-s.lookback)), false, true
		}
		s.m.Errors.Incr(1, sourceName, application)
		s.log.Errorf("okta: load cursor: %v", err)
		if !pull.Sleep(ctx, s.interval) {
			return "", false, false
		}
	}
}

func (s *stream) onRetry(err error, wait time.Duration) {
	s.m.Errors.Incr(1, sourceName, application)
	s.log.Warnf("okta: retrying in %s: %v", wait.Round(time.Millisecond), err)
}

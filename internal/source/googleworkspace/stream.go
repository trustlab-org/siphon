package googleworkspace

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/dedupe"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

type pager interface {
	page(ctx context.Context, app string, start, end time.Time, token string) (*activityPage, error)
}

type timing struct {
	interval        time.Duration
	recheck         time.Duration
	sweepInterval   time.Duration
	initialLookback time.Duration
	maxWindow       time.Duration
	unavailableWait time.Duration
}

// stream polls one applicationName with its own cursor, dedupe set and backoff.
type stream struct {
	app     string
	key     string
	meta    envelope.Meta
	overlap time.Duration
	pager   pager
	store   checkpoint.Store
	seen    *dedupe.Seen
	boff    backoff.BackOff
	timing  timing
	out     chan<- pull.Pending
	log     *service.Logger
	m       pull.Metrics
	health  *pull.Health
	now     func() time.Time
	primed  bool
}

// span is one poll: fetch [cursor-back, end) and commit end.
type span struct {
	cursor, end time.Time
	back        time.Duration
}

func (s *stream) run(ctx context.Context) {
	cursor, ok := s.loadCursor(ctx)
	if !ok {
		return
	}
	var lastSweep time.Time
	for ctx.Err() == nil {
		now := s.now()
		sp := span{cursor: cursor, end: now, back: min(s.timing.recheck, s.overlap)}
		if sp.end.Sub(cursor) > s.timing.maxWindow {
			sp.end = cursor.Add(s.timing.maxWindow)
		}
		sweeping := now.Sub(lastSweep) >= s.timing.sweepInterval
		if sweeping {
			sp.back = s.overlap
		}
		if err := s.window(ctx, sp); err != nil {
			if ctx.Err() != nil {
				return
			}
			if unavailable(err) {
				s.markUnavailable(err)
				pull.Sleep(ctx, s.timing.unavailableWait)
				continue
			}
			s.m.Errors.Incr(1, sourceName, s.app)
			s.log.Errorf("%s: window %s..%s failed: %v", s.app, cursor.Format(time.RFC3339), sp.end.Format(time.RFC3339), err)
			pull.Sleep(ctx, s.timing.interval)
			continue
		}
		s.health.Up()
		if sweeping {
			lastSweep = now
		}
		cursor = sp.end
		s.m.Lag.Set(int64(s.now().Sub(cursor).Seconds()), sourceName, s.app)
		if sp.end.Equal(now) {
			pull.Sleep(ctx, s.timing.interval)
		}
	}
}

// window emits every unseen event in the span and commits its end only once all of it is acked.
func (s *stream) window(ctx context.Context, sp span) error {
	start := sp.cursor.Add(-sp.back)
	var win pull.Window
	fresh := map[string]time.Time{}
	token := ""
	for {
		var page *activityPage
		err := pull.Retry(ctx, s.boff, retryable, s.onRetry, func() (err error) {
			page, err = s.pager.page(ctx, s.app, start, sp.end, token)
			return err
		})
		if err != nil {
			return err
		}
		if batch := s.batch(page.Items, fresh); len(batch) > 0 {
			ack := win.Track()
			select {
			case s.out <- pull.Pending{Batch: batch, Ack: ack}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if token = page.NextPageToken; token == "" {
			break
		}
	}
	if err := win.Wait(ctx); err != nil {
		return fmt.Errorf("window not acknowledged: %w", err)
	}
	s.record(sp, fresh)
	if err := s.store.Set(ctx, s.key, []byte(sp.end.UTC().Format(time.RFC3339Nano))); err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}
	return nil
}

// record marks committed ids as seen and measures events that showed up behind the cursor.
func (s *stream) record(sp span, fresh map[string]time.Time) {
	seenAt := s.now()
	late := 0
	for id, at := range fresh {
		s.seen.Add(id, at)
		if s.primed && at.Before(sp.cursor) {
			late++
			lateness := seenAt.Sub(at)
			s.m.Lateness.Timing(lateness.Nanoseconds(), sourceName, s.app)
			if lateness > s.overlap*8/10 {
				s.log.Warnf("%s: event arrived %s late, close to the %s overlap; raise it to avoid losing events", s.app, lateness.Round(time.Second), s.overlap)
			}
		}
	}
	s.primed = true
	s.seen.Prune(sp.end.Add(-s.overlap))
	s.m.Emitted.Incr(int64(len(fresh)), sourceName, s.app)
	s.m.Late.Incr(int64(late), sourceName, s.app)
}

func (s *stream) batch(items []map[string]any, fresh map[string]time.Time) service.MessageBatch {
	var batch service.MessageBatch
	for _, a := range items {
		evs, err := split(a, s.app, s.meta)
		if err != nil {
			s.m.Skipped.Incr(1, sourceName, s.app)
			s.log.Warnf("%s: skipping malformed activity: %v", s.app, err)
			continue
		}
		for _, e := range evs {
			if _, dup := fresh[e.id]; dup || s.seen.Has(e.id) {
				continue
			}
			fresh[e.id] = e.at
			msg := service.NewMessage(e.body)
			msg.MetaSet("event_id", e.id)
			msg.MetaSet("source_program", s.meta.SourceProgram)
			msg.MetaSet("application", s.app)
			batch = append(batch, msg)
		}
	}
	return batch
}

func (s *stream) loadCursor(ctx context.Context) (time.Time, bool) {
	for {
		raw, err := s.store.Get(ctx, s.key)
		if err == nil {
			if raw == nil {
				return s.now().Add(-s.timing.initialLookback), true
			}
			t, perr := time.Parse(time.RFC3339Nano, string(raw))
			if perr == nil {
				return t, true
			}
			err = fmt.Errorf("corrupt cursor %q: %w", raw, perr)
		}
		s.m.Errors.Incr(1, sourceName, s.app)
		s.log.Errorf("%s: load cursor: %v", s.app, err)
		if !pull.Sleep(ctx, s.timing.interval) {
			return time.Time{}, false
		}
	}
}

// markUnavailable logs once when the tenant's plan or permissions do not offer this log type; polling continues at a slow rate.
func (s *stream) markUnavailable(err error) {
	s.health.Down(fmt.Sprintf("%s: not available to this tenant (%v); retrying every %s", s.app, err, s.timing.unavailableWait))
}

func (s *stream) onRetry(err error, wait time.Duration) {
	s.m.Errors.Incr(1, sourceName, s.app)
	s.log.Warnf("%s: retrying in %s: %v", s.app, wait.Round(time.Millisecond), err)
}

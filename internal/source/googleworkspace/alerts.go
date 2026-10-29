package googleworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"
	"google.golang.org/api/googleapi"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/dedupe"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

const (
	alertsName     = "google_workspace_alerts"
	alertsBase     = "https://alertcenter.googleapis.com/"
	alertsScope    = "https://www.googleapis.com/auth/apps.alerts"
	alertsPageSize = 100

	fOverlap = "overlap"
)

func init() {
	if err := service.RegisterBatchInput(alertsName, alertsSpec(), newAlertsInput); err != nil {
		panic(err)
	}
}

func alertsSpec() *service.ConfigSpec {
	return service.NewConfigSpec().
		Beta().
		Categories("Services").
		Summary("Pulls Google Workspace Alert Center alerts, including updates to existing alerts.").
		Fields(
			service.NewStringField(fCredentials).
				Description("Path to the service account JSON key. Mount it; never bake it into an image.").
				Default(""),
			service.NewStringField(fSubject).
				Description("Admin user with Alert Center view access that the service account impersonates.").
				Default(""),
			service.NewStringField(fCustomerID).
				Description("Workspace customer id without the leading C; empty uses the subject's own customer.").
				Default(""),
			service.NewStringField(fOrg).Description("Organisation name for meta.org."),
			service.NewStringField(fServer).Description("meta.server value; it names the index series downstream.").Example("google-workspace"),
			service.NewDurationField(fInterval).Default("1m"),
			service.NewDurationField(fOverlap).
				Description("How far each poll re-reads behind the newest update already collected.").
				Default("10m"),
			service.NewDurationField(fInitialLookback).
				Description("Where collection starts when there is no cursor yet.").
				Default("24h"),
			service.NewDurationField(fUnavailableWait).
				Description("How often to re-check when the API is not enabled or not delegated.").
				Advanced().
				Default("1h"),
			service.NewBackOffField(fBackoff, false, &backoff.ExponentialBackOff{
				InitialInterval: time.Second,
				MaxInterval:     2 * time.Minute,
				MaxElapsedTime:  15 * time.Minute,
			}),
			checkpoint.ConfigField(fCheckpoint),
		)
}

type alertPage struct {
	Alerts        []map[string]any `json:"alerts"`
	NextPageToken string           `json:"nextPageToken"`
}

type alertPager interface {
	page(ctx context.Context, token string) (*alertPage, error)
}

type alertClient struct {
	http       *http.Client
	base       string
	customerID string
}

// page lists alerts newest-updated first, so a poll can stop once it reaches alerts it has already collected.
func (c *alertClient) page(ctx context.Context, token string) (*alertPage, error) {
	q := url.Values{}
	q.Set("orderBy", "updateTime desc")
	q.Set("pageSize", strconv.Itoa(alertsPageSize))
	if c.customerID != "" {
		q.Set("customerId", c.customerID)
	}
	if token != "" {
		q.Set("pageToken", token)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"v1beta1/alerts?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := googleapi.CheckResponse(resp); err != nil {
		return nil, err
	}
	var p alertPage
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode alerts page: %w", err)
	}
	return &p, nil
}

type alertsInput struct {
	credentials string
	subject     string
	customerID  string
	stream      *alertStream
	store       checkpoint.Store

	out     chan pull.Pending
	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newAlertsInput(conf *service.ParsedConfig, res *service.Resources) (service.BatchInput, error) {
	in := &alertsInput{out: make(chan pull.Pending)}
	s := &alertStream{log: res.Logger(), m: newMetrics(res.Metrics()), seen: dedupe.NewSeen(), out: in.out, now: time.Now}
	var err error
	if in.credentials, err = conf.FieldString(fCredentials); err != nil {
		return nil, err
	}
	if in.subject, err = conf.FieldString(fSubject); err != nil {
		return nil, err
	}
	if in.customerID, err = conf.FieldString(fCustomerID); err != nil {
		return nil, err
	}
	if in.credentials == "" || in.subject == "" {
		return nil, errors.New("credentials_file and subject are required")
	}
	if s.meta.Org, err = conf.FieldString(fOrg); err != nil {
		return nil, err
	}
	if s.meta.Server, err = conf.FieldString(fServer); err != nil {
		return nil, err
	}
	if s.interval, err = conf.FieldDuration(fInterval); err != nil {
		return nil, err
	}
	if s.overlap, err = conf.FieldDuration(fOverlap); err != nil {
		return nil, err
	}
	if s.lookback, err = conf.FieldDuration(fInitialLookback); err != nil {
		return nil, err
	}
	if s.unavailableWait, err = conf.FieldDuration(fUnavailableWait); err != nil {
		return nil, err
	}
	if s.interval <= 0 || s.unavailableWait <= 0 || s.overlap < 0 || s.lookback < 0 {
		return nil, errors.New("poll_interval and unavailable_retry must be positive; other durations non-negative")
	}
	if s.boff, err = conf.FieldBackOff(fBackoff); err != nil {
		return nil, err
	}
	if in.store, err = checkpoint.FromConfig(conf, fCheckpoint); err != nil {
		return nil, err
	}
	s.store = in.store
	s.meta.SourceProgram = alertsName
	s.key = alertsName + "/" + s.meta.Server
	in.stream = s
	return service.AutoRetryNacksBatched(in), nil
}

func (in *alertsInput) Connect(ctx context.Context) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.started {
		return nil
	}
	h, err := delegatedHTTP(in.credentials, in.subject, alertsScope)
	if err != nil {
		return err
	}
	in.stream.pager = &alertClient{http: h, base: alertsBase, customerID: in.customerID}
	runCtx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	in.stream.log.Infof("alerts: polling every %s, overlap %s", in.stream.interval, in.stream.overlap)
	in.wg.Add(1)
	go func() {
		defer in.wg.Done()
		in.stream.run(runCtx)
	}()
	in.started = true
	return nil
}

func (in *alertsInput) ReadBatch(ctx context.Context) (service.MessageBatch, service.AckFunc, error) {
	select {
	case p := <-in.out:
		return p.Batch, p.Ack, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (in *alertsInput) Close(ctx context.Context) error {
	in.mu.Lock()
	if in.cancel != nil {
		in.cancel()
	}
	in.mu.Unlock()
	done := make(chan struct{})
	go func() {
		in.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return in.store.Close(ctx)
}

// alertStream polls the Alert Center with a cursor on updateTime, so both new and updated alerts are collected.
type alertStream struct {
	key             string
	meta            envelope.Meta
	pager           alertPager
	store           checkpoint.Store
	seen            *dedupe.Seen
	boff            backoff.BackOff
	interval        time.Duration
	overlap         time.Duration
	lookback        time.Duration
	unavailableWait time.Duration
	out             chan<- pull.Pending
	log             *service.Logger
	m               metrics
	now             func() time.Time
	dormant         bool
}

func (s *alertStream) run(ctx context.Context) {
	cursor, ok := s.loadCursor(ctx)
	if !ok {
		return
	}
	for ctx.Err() == nil {
		next, err := s.poll(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if unavailable(err) {
				s.markUnavailable(err)
				pull.Sleep(ctx, s.unavailableWait)
				continue
			}
			s.m.errors.Incr(1, sourceName, "alerts")
			s.log.Errorf("alerts: poll failed: %v", err)
			pull.Sleep(ctx, s.interval)
			continue
		}
		s.markAvailable()
		cursor = next
		pull.Sleep(ctx, s.interval)
	}
}

// poll emits every alert updated since cursor-overlap that it has not sent before, and commits the newest updateTime once all are acked.
func (s *alertStream) poll(ctx context.Context, cursor time.Time) (time.Time, error) {
	floor := cursor.Add(-s.overlap)
	newest := cursor
	fresh := map[string]time.Time{}
	var win pull.Window
	token := ""
	for {
		var page *alertPage
		err := pull.Retry(ctx, s.boff, retryable, s.onRetry, func() (err error) {
			page, err = s.pager.page(ctx, token)
			return err
		})
		if err != nil {
			return cursor, err
		}
		batch, reachedFloor := s.batch(page.Alerts, floor, fresh, &newest)
		if len(batch) > 0 {
			ack := win.Track()
			select {
			case s.out <- pull.Pending{Batch: batch, Ack: ack}:
			case <-ctx.Done():
				return cursor, ctx.Err()
			}
		}
		if token = page.NextPageToken; reachedFloor || token == "" {
			break
		}
	}
	if err := win.Wait(ctx); err != nil {
		return cursor, fmt.Errorf("alerts not acknowledged: %w", err)
	}
	for key, at := range fresh {
		s.seen.Add(key, at)
	}
	s.seen.Prune(newest.Add(-s.overlap))
	s.m.emitted.Incr(int64(len(fresh)), sourceName, "alerts")
	if newest.After(cursor) {
		if err := s.store.Set(ctx, s.key, []byte(newest.UTC().Format(time.RFC3339Nano))); err != nil {
			return cursor, fmt.Errorf("save cursor: %w", err)
		}
	}
	return newest, nil
}

// batch converts one page; it reports reachedFloor once alerts are older than the floor, since pages are sorted newest first.
func (s *alertStream) batch(alerts []map[string]any, floor time.Time, fresh map[string]time.Time, newest *time.Time) (service.MessageBatch, bool) {
	var batch service.MessageBatch
	for _, a := range alerts {
		updated := text(a["updateTime"])
		at, err := time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			s.m.skipped.Incr(1, sourceName, "alerts")
			s.log.Warnf("alerts: skipping alert without updateTime: %v", err)
			continue
		}
		if at.Before(floor) {
			return batch, true
		}
		alertID := text(a["alertId"])
		version := alertID + "|" + updated
		if _, dup := fresh[version]; dup || s.seen.Has(version) {
			continue
		}
		raw, err := json.Marshal(a)
		if err != nil {
			s.m.skipped.Incr(1, sourceName, "alerts")
			continue
		}
		m := s.meta
		m.EventID = envelope.ID(text(a["customerId"]), "alerts", alertID)
		body, err := envelope.Envelope{Meta: m, Raw: string(raw)}.Marshal()
		if err != nil {
			s.m.skipped.Incr(1, sourceName, "alerts")
			continue
		}
		fresh[version] = at
		if at.After(*newest) {
			*newest = at
		}
		msg := service.NewMessage(body)
		msg.MetaSet("event_id", m.EventID)
		msg.MetaSet("source_program", s.meta.SourceProgram)
		msg.MetaSet("application", "alerts")
		batch = append(batch, msg)
	}
	return batch, false
}

func (s *alertStream) loadCursor(ctx context.Context) (time.Time, bool) {
	for {
		raw, err := s.store.Get(ctx, s.key)
		if err == nil {
			if raw == nil {
				return s.now().Add(-s.lookback), true
			}
			t, perr := time.Parse(time.RFC3339Nano, string(raw))
			if perr == nil {
				return t, true
			}
			err = fmt.Errorf("corrupt cursor %q: %w", raw, perr)
		}
		s.m.errors.Incr(1, sourceName, "alerts")
		s.log.Errorf("alerts: load cursor: %v", err)
		if !pull.Sleep(ctx, s.interval) {
			return time.Time{}, false
		}
	}
}

func (s *alertStream) markUnavailable(err error) {
	s.m.available.Set(0, sourceName, "alerts")
	if !s.dormant {
		s.dormant = true
		s.log.Warnf("alerts: Alert Center not available (%v); check the API is enabled, the apps.alerts scope is delegated and the subject has Alert Center view access; retrying every %s", err, s.unavailableWait)
	}
}

func (s *alertStream) markAvailable() {
	s.m.available.Set(1, sourceName, "alerts")
	if s.dormant {
		s.dormant = false
		s.log.Infof("alerts: available again")
	}
}

func (s *alertStream) onRetry(err error, wait time.Duration) {
	s.m.errors.Incr(1, sourceName, "alerts")
	s.log.Warnf("alerts: retrying in %s: %v", wait.Round(time.Millisecond), err)
}

package googleworkspace

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/dedupe"
	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/pull"
)

const (
	sourceName = "google_workspace"

	fCredentials     = "credentials_file"
	fSubject         = "subject"
	fCustomerID      = "customer_id"
	fApplications    = "applications"
	fOrg             = "org"
	fServer          = "server"
	fInterval        = "poll_interval"
	fRecheck         = "recheck"
	fSweepInterval   = "sweep_interval"
	fDefaultOverlap  = "default_overlap"
	fOverlaps        = "overlaps"
	fInitialLookback = "initial_lookback"
	fMaxWindow       = "max_window"
	fUnavailableWait = "unavailable_retry"
	fBackoff         = "backoff"
	fCheckpoint      = "checkpoint"
)

func init() {
	if err := service.RegisterBatchInput(sourceName, spec(), newInput); err != nil {
		panic(err)
	}
}

func spec() *service.ConfigSpec {
	return service.NewConfigSpec().
		Beta().
		Categories("Services").
		Summary("Pulls Google Workspace audit activity from the Admin SDK Reports API.").
		Fields(
			service.NewStringField(fCredentials).
				Description("Path to the service account JSON key. Mount it; never bake it into an image.").
				Default(""),
			service.NewStringField(fSubject).
				Description("Admin user the service account impersonates via domain-wide delegation.").
				Example("admin@example.ac.in").
				Default(""),
			service.NewStringField(fCustomerID).
				Description("Workspace customer id; empty uses the subject's own customer.").
				Default(""),
			service.NewStringListField(fApplications).
				Description("Reports API applicationName values to collect, each with its own cursor.").
				Default([]string{"login"}),
			service.NewStringField(fOrg).Description("Organisation name for meta.org."),
			service.NewStringField(fServer).Description("meta.server value; it names the index series downstream.").Example("google-workspace"),
			service.NewDurationField(fInterval).Default("1m"),
			service.NewDurationField(fRecheck).
				Description("How far every poll reaches behind the cursor.").
				Default("5m"),
			service.NewDurationField(fSweepInterval).
				Description("How often a poll reaches back the full overlap to catch late-arriving events.").
				Default("10m"),
			service.NewDurationField(fDefaultOverlap).
				Description("Overlap for applications without a built-in lag profile.").
				Default("3h"),
			service.NewStringMapField(fOverlaps).
				Description("Per-application overlap overrides, e.g. `token: 6h`.").
				Advanced().
				Default(map[string]any{}),
			service.NewDurationField(fInitialLookback).
				Description("Where a stream starts when it has no cursor yet.").
				Default("24h"),
			service.NewDurationField(fMaxWindow).
				Description("Largest single window, bounding backfill work per commit.").
				Default("6h"),
			service.NewDurationField(fUnavailableWait).
				Description("How often to re-check a log type the tenant's plan or permissions do not offer.").
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

type input struct {
	credentials string
	subject     string
	customerID  string
	apps        []string
	overlaps    map[string]time.Duration
	meta        envelope.Meta
	timing      timing
	boff        *backoff.ExponentialBackOff
	store       checkpoint.Store
	log         *service.Logger
	m           metrics

	out     chan pull.Pending
	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newInput(conf *service.ParsedConfig, res *service.Resources) (service.BatchInput, error) {
	in := &input{log: res.Logger(), m: newMetrics(res.Metrics()), out: make(chan pull.Pending)}
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
	if in.apps, err = conf.FieldStringList(fApplications); err != nil {
		return nil, err
	}
	if len(in.apps) == 0 {
		return nil, errors.New("applications must not be empty")
	}
	if in.meta.Org, err = conf.FieldString(fOrg); err != nil {
		return nil, err
	}
	if in.meta.Server, err = conf.FieldString(fServer); err != nil {
		return nil, err
	}
	if in.timing, err = parseTiming(conf); err != nil {
		return nil, err
	}
	if in.overlaps, err = parseOverlaps(conf, in.apps); err != nil {
		return nil, err
	}
	if in.boff, err = conf.FieldBackOff(fBackoff); err != nil {
		return nil, err
	}
	if in.store, err = checkpoint.FromConfig(conf, fCheckpoint); err != nil {
		return nil, err
	}
	return service.AutoRetryNacksBatched(in), nil
}

func parseTiming(conf *service.ParsedConfig) (t timing, err error) {
	if t.interval, err = conf.FieldDuration(fInterval); err != nil {
		return
	}
	if t.recheck, err = conf.FieldDuration(fRecheck); err != nil {
		return
	}
	if t.sweepInterval, err = conf.FieldDuration(fSweepInterval); err != nil {
		return
	}
	if t.initialLookback, err = conf.FieldDuration(fInitialLookback); err != nil {
		return
	}
	if t.maxWindow, err = conf.FieldDuration(fMaxWindow); err != nil {
		return
	}
	if t.unavailableWait, err = conf.FieldDuration(fUnavailableWait); err != nil {
		return
	}
	if t.interval <= 0 || t.maxWindow <= 0 || t.unavailableWait <= 0 || t.recheck < 0 || t.sweepInterval < 0 || t.initialLookback < 0 {
		err = errors.New("poll_interval and max_window must be positive; other durations non-negative")
	}
	return
}

func parseOverlaps(conf *service.ParsedConfig, apps []string) (map[string]time.Duration, error) {
	fallback, err := conf.FieldDuration(fDefaultOverlap)
	if err != nil {
		return nil, err
	}
	overrides, err := conf.FieldStringMap(fOverlaps)
	if err != nil {
		return nil, err
	}
	return overlaps(apps, overrides, fallback)
}

func (in *input) Connect(ctx context.Context) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.started {
		return nil
	}
	cl, err := newClient(in.credentials, in.subject, in.customerID)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	for _, app := range in.apps {
		s := in.newStream(app, cl)
		in.log.Infof("%s: polling every %s, overlap %s", app, in.timing.interval, s.overlap)
		in.wg.Add(1)
		go func() {
			defer in.wg.Done()
			s.run(runCtx)
		}()
	}
	in.started = true
	return nil
}

func (in *input) newStream(app string, p pager) *stream {
	meta := in.meta
	meta.SourceProgram = sourceName + "_" + app
	boff := *in.boff
	return &stream{
		app:     app,
		key:     sourceName + "/" + in.meta.Server + "/" + app,
		meta:    meta,
		overlap: in.overlaps[app],
		pager:   p,
		store:   in.store,
		seen:    dedupe.NewSeen(),
		boff:    &boff,
		timing:  in.timing,
		out:     in.out,
		log:     in.log,
		m:       in.m,
		now:     time.Now,
	}
}

func (in *input) ReadBatch(ctx context.Context) (service.MessageBatch, service.AckFunc, error) {
	select {
	case p := <-in.out:
		return p.Batch, p.Ack, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (in *input) Close(ctx context.Context) error {
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

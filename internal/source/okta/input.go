package okta

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/warpstreamlabs/bento/public/service"

	"github.com/HelixY2J/collector/internal/checkpoint"
	"github.com/HelixY2J/collector/internal/pull"
)

const (
	sourceName = "okta_system_log"

	fOrgURL          = "org_url"
	fClientID        = "client_id"
	fKeyID           = "key_id"
	fPrivateKey      = "private_key_file"
	fOrg             = "org"
	fServer          = "server"
	fInterval        = "poll_interval"
	fPageSize        = "page_size"
	fInitialLookback = "initial_lookback"
	fUnavailableWait = "unavailable_retry"
	fBackoff         = "backoff"
	fCheckpoint      = "checkpoint"

	maxPageSize = 1000
	maxLookback = 90 * 24 * time.Hour
	maxInterval = 24 * time.Hour
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
		Summary("Pulls the Okta System Log through an API Services app using private_key_jwt and DPoP.").
		Fields(
			service.NewStringField(fOrgURL).
				Description("Okta org URL, without -admin.").
				Example("https://example.okta.com"),
			service.NewStringField(fClientID).Description("Client ID of the API Services app granted okta.logs.read."),
			service.NewStringField(fKeyID).Description("kid of the app's public key in Okta."),
			service.NewStringField(fPrivateKey).
				Description("Path to the app's RSA private key in PEM. Mount it; never bake it into an image."),
			service.NewStringField(fOrg).Description("Organisation name for meta.org."),
			service.NewStringField(fServer).Description("meta.server value; it names the index series downstream.").Example("okta"),
			service.NewDurationField(fInterval).
				Description("Wait between polls once caught up; Okta advises no more than a day.").
				Default("1m"),
			service.NewIntField(fPageSize).
				Description("Events per request, up to 1000.").
				Advanced().
				Default(maxPageSize),
			service.NewDurationField(fInitialLookback).
				Description("Where collection starts when there is no cursor yet; Okta keeps 90 days.").
				Default("24h"),
			service.NewDurationField(fUnavailableWait).
				Description("How often to re-check when the app's credentials, grant or role are rejected.").
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
	orgURL   *url.URL
	clientID string
	keyID    string
	key      *rsa.PrivateKey
	stream   *stream
	store    checkpoint.Store
	*pull.Driver
}

func newInput(conf *service.ParsedConfig, res *service.Resources) (service.BatchInput, error) {
	in := &input{Driver: pull.NewDriver()}
	m := pull.NewMetrics(res.Metrics())
	s := &stream{
		log:    res.Logger(),
		m:      m,
		health: pull.NewHealth(m, res.Logger(), sourceName, application),
		out:    in.Out(),
		now:    time.Now,
	}
	rawURL, err := conf.FieldString(fOrgURL)
	if err != nil {
		return nil, err
	}
	if in.orgURL, err = parseOrgURL(rawURL); err != nil {
		return nil, err
	}
	if in.clientID, err = conf.FieldString(fClientID); err != nil {
		return nil, err
	}
	if in.keyID, err = conf.FieldString(fKeyID); err != nil {
		return nil, err
	}
	keyFile, err := conf.FieldString(fPrivateKey)
	if err != nil {
		return nil, err
	}
	if in.clientID == "" || in.keyID == "" || keyFile == "" {
		return nil, errors.New("client_id, key_id and private_key_file are required")
	}
	if in.key, err = loadRSAKey(keyFile); err != nil {
		return nil, err
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
	if s.pageSize, err = conf.FieldInt(fPageSize); err != nil {
		return nil, err
	}
	if s.lookback, err = conf.FieldDuration(fInitialLookback); err != nil {
		return nil, err
	}
	if s.unavailableWait, err = conf.FieldDuration(fUnavailableWait); err != nil {
		return nil, err
	}
	switch {
	case s.interval <= 0 || s.interval > maxInterval:
		return nil, fmt.Errorf("poll_interval must be between 0 and %s", maxInterval)
	case s.pageSize < 1 || s.pageSize > maxPageSize:
		return nil, fmt.Errorf("page_size must be between 1 and %d", maxPageSize)
	case s.lookback < 0 || s.lookback > maxLookback:
		return nil, fmt.Errorf("initial_lookback must be between 0 and %s, Okta's retention", maxLookback)
	case s.unavailableWait <= 0:
		return nil, errors.New("unavailable_retry must be positive")
	}
	if s.boff, err = conf.FieldBackOff(fBackoff); err != nil {
		return nil, err
	}
	if in.store, err = checkpoint.FromConfig(conf, fCheckpoint); err != nil {
		return nil, err
	}
	s.store = in.store
	s.host = in.orgURL.Host
	s.meta.SourceProgram = sourceName
	s.key = sourceName + "/" + s.meta.Server + "/" + s.host
	in.stream = s
	return service.AutoRetryNacksBatched(in), nil
}

// parseOrgURL accepts the bare org URL; the -admin console host serves the UI, not the API.
func parseOrgURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("org_url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("org_url %q must look like https://example.okta.com", raw)
	}
	if label, _, _ := strings.Cut(u.Host, "."); strings.HasSuffix(label, "-admin") {
		return nil, fmt.Errorf("org_url %q is the admin console; drop -admin from the host", raw)
	}
	return u, nil
}

func (in *input) Connect(ctx context.Context) error {
	return in.Start(func() ([]func(context.Context), error) {
		dk, err := newDPoPKey()
		if err != nil {
			return nil, fmt.Errorf("dpop key: %w", err)
		}
		in.stream.pager = newClient(in.orgURL, in.clientID, in.keyID, in.key, dk, http.DefaultTransport, in.stream.pageSize)
		in.stream.log.Infof("okta: polling %s every %s", in.orgURL.Host, in.stream.interval)
		return []func(context.Context){in.stream.run}, nil
	})
}

func newClient(org *url.URL, clientID, keyID string, key *rsa.PrivateKey, dk *dpopKey, base http.RoundTripper, pageSize int) *client {
	tokenURL := *org
	tokenURL.Path = tokenPath
	ts := &tokenSource{
		http:     &http.Client{Transport: base, Timeout: httpTimeout},
		tokenURL: tokenURL.String(),
		clientID: clientID,
		keyID:    keyID,
		key:      key,
		dpop:     dk,
		now:      time.Now,
	}
	return &client{
		http:     &http.Client{Transport: &dpopTransport{base: base, ts: ts}, Timeout: httpTimeout},
		base:     org,
		pageSize: pageSize,
		now:      time.Now,
	}
}

func (in *input) Close(ctx context.Context) error {
	if err := in.Stop(ctx); err != nil {
		return err
	}
	return in.store.Close(ctx)
}

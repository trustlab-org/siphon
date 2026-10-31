package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	logsPath     = "/api/v1/logs"
	tokenPath    = "/oauth2/v1/token"
	userAgent    = "siphon-collector (okta_system_log)"
	maxPageBody  = 64 << 20
	maxRateWait  = 2 * time.Minute
	httpTimeout  = 60 * time.Second
	rateHeadroom = 10
)

// page is one System Log response plus the rate-limit state Okta reported with it.
type page struct {
	events    []map[string]any
	next      string
	limit     int
	remaining int
	reset     time.Time
}

// apiError is a non-2xx System Log response; Okta's errorCode tells permission problems from bad requests.
type apiError struct {
	status     int
	code       string
	summary    string
	retryAfter time.Duration
}

func (e *apiError) Error() string {
	return fmt.Sprintf("okta system log: %d %s: %s", e.status, e.code, e.summary)
}

func (e *apiError) RetryAfter() time.Duration { return e.retryAfter }

type client struct {
	http     *http.Client
	base     *url.URL
	pageSize int
	now      func() time.Time
}

// start is the first polling URL: no until and ascending order, so Okta returns an endless chain of next links.
func (c *client) start(since time.Time) string {
	q := url.Values{
		"since":     {since.UTC().Format(time.RFC3339Nano)},
		"sortOrder": {"ASCENDING"},
		"limit":     {strconv.Itoa(c.pageSize)},
	}
	u := *c.base
	u.Path = logsPath
	u.RawQuery = q.Encode()
	return u.String()
}

// owns reports whether u is a System Log URL on our org, so a tampered cursor or link can never send the token elsewhere.
func (c *client) owns(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == c.base.Scheme && u.Host == c.base.Host && u.Path == logsPath && u.User == nil
}

func (c *client) page(ctx context.Context, rawURL string) (*page, error) {
	if !c.owns(rawURL) {
		return nil, fmt.Errorf("refusing to fetch %q: not this org's System Log URL", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	p := &page{next: nextLink(resp.Header)}
	p.limit, _ = strconv.Atoi(resp.Header.Get("X-Rate-Limit-Limit"))
	p.remaining, _ = strconv.Atoi(resp.Header.Get("X-Rate-Limit-Remaining"))
	if s, err := strconv.ParseInt(resp.Header.Get("X-Rate-Limit-Reset"), 10, 64); err == nil {
		p.reset = time.Unix(s, 0)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.apiError(resp, p.reset)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxPageBody))
	dec.UseNumber()
	if err := dec.Decode(&p.events); err != nil {
		return nil, fmt.Errorf("decode system log page: %w", err)
	}
	return p, nil
}

func (c *client) apiError(resp *http.Response, reset time.Time) error {
	var body struct {
		Code    string `json:"errorCode"`
		Summary string `json:"errorSummary"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&body)
	e := &apiError{status: resp.StatusCode, code: body.Code, summary: body.Summary}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.retryAfter = c.untilReset(reset)
	}
	return e
}

// untilReset is how long to wait for a rate-limit window to reopen, with a second of slack for clock skew.
func (c *client) untilReset(reset time.Time) time.Duration {
	if reset.IsZero() {
		return 0
	}
	return min(max(reset.Sub(c.now())+time.Second, time.Second), maxRateWait)
}

// throttle returns a wait when the page left little of the org-wide rate limit, since other integrations share it.
func (c *client) throttle(p *page) time.Duration {
	if p.limit <= 0 || p.remaining*100 >= p.limit*rateHeadroom {
		return 0
	}
	return c.untilReset(p.reset)
}

// nextLink returns the rel="next" target from RFC 8288 Link headers.
func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		for v != "" {
			open := strings.IndexByte(v, '<')
			end := strings.IndexByte(v, '>')
			if open < 0 || end < open {
				break
			}
			target := v[open+1 : end]
			params := v[end+1:]
			if i := strings.IndexByte(params, '<'); i >= 0 {
				params = params[:i]
			}
			for _, p := range strings.Split(params, ";") {
				k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
				if strings.EqualFold(k, "rel") && strings.Trim(val, `"`) == "next" {
					return target
				}
			}
			v = v[end+1:]
		}
	}
	return ""
}

func retryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var aerr *apiError
	if errors.As(err, &aerr) {
		return aerr.status == http.StatusTooManyRequests || aerr.status >= 500
	}
	var terr *authError
	if errors.As(err, &terr) {
		return terr.status == http.StatusTooManyRequests || terr.status >= 500
	}
	// network failures and truncated bodies are transient
	return true
}

// unavailable is a credentials, grant or role problem that only an admin can fix, so it is retried slowly.
func unavailable(err error) bool {
	var terr *authError
	if errors.As(err, &terr) {
		return terr.status < 500 && terr.status != http.StatusTooManyRequests
	}
	var aerr *apiError
	if errors.As(err, &aerr) {
		return aerr.status == http.StatusUnauthorized || aerr.status == http.StatusForbidden || aerr.status == http.StatusNotFound
	}
	return false
}

// badRequest is Okta rejecting the query itself, e.g. a stored cursor past the retention limit.
func badRequest(err error) bool {
	var aerr *apiError
	return errors.As(err, &aerr) && aerr.status == http.StatusBadRequest
}

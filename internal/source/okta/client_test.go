package okta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestNextLink(t *testing.T) {
	cases := []struct {
		name   string
		header []string
		want   string
	}{
		{"okta", []string{`<https://o.okta.com/api/v1/logs?since=a>; rel="self"`, `<https://o.okta.com/api/v1/logs?after=1_1>; rel="next"`}, "https://o.okta.com/api/v1/logs?after=1_1"},
		{"joined", []string{`<https://o/a?x=1,2>; rel="self", <https://o/b>; rel="next"`}, "https://o/b"},
		{"self only", []string{`<https://o/a>; rel="self"`}, ""},
		{"none", nil, ""},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.header {
			h.Add("Link", v)
		}
		if got := nextLink(h); got != c.want {
			t.Errorf("%s: nextLink = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestOwns(t *testing.T) {
	org, _ := url.Parse("https://example.okta.com")
	c := &client{base: org, pageSize: 1000}
	cases := map[string]bool{
		c.start(time.Now()): true,
		"https://example.okta.com/api/v1/logs?after=1_1":       true,
		"https://evil.example.com/api/v1/logs?after=1_1":       false,
		"http://example.okta.com/api/v1/logs?after=1_1":        false,
		"https://example.okta.com/api/v1/users":                false,
		"https://user:pw@example.okta.com/api/v1/logs?after=1": false,
		"::not a url": false,
	}
	for u, want := range cases {
		if got := c.owns(u); got != want {
			t.Errorf("owns(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestParseOrgURL(t *testing.T) {
	cases := map[string]bool{
		"https://integrator-1.okta.com":       true,
		"https://integrator-1.okta.com/":      true,
		"https://integrator-1-admin.okta.com": false,
		"http://integrator-1.okta.com":        false,
		"https://integrator-1.okta.com/admin": false,
		"integrator-1.okta.com":               false,
	}
	for raw, ok := range cases {
		if _, err := parseOrgURL(raw); (err == nil) != ok {
			t.Errorf("parseOrgURL(%q) err = %v, want ok %v", raw, err, ok)
		}
	}
}

func TestRateLimitedPageWaitsForReset(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Rate-Limit-Limit", "60")
		w.Header().Set("X-Rate-Limit-Remaining", "0")
		w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(now.Add(20*time.Second).Unix(), 10))
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit due to too many requests."}`)
	}))
	defer srv.Close()
	org, _ := url.Parse(srv.URL)
	c := &client{http: srv.Client(), base: org, pageSize: 1000, now: func() time.Time { return now }}

	_, err := c.page(context.Background(), c.start(now))
	var aerr *apiError
	if !errors.As(err, &aerr) || aerr.code != "E0000047" || aerr.RetryAfter() != 21*time.Second {
		t.Fatalf("err = %#v; want E0000047 with a 21s retry hint", err)
	}
	if !retryable(err) || unavailable(err) {
		t.Fatal("a rate limit must be retried, not treated as unavailable")
	}
}

func TestThrottleKeepsHeadroom(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := &client{now: func() time.Time { return now }}
	reset := now.Add(30 * time.Second)
	if d := c.throttle(&page{limit: 60, remaining: 5, reset: reset}); d != 31*time.Second {
		t.Errorf("5/60 left: wait %s, want 31s", d)
	}
	if d := c.throttle(&page{limit: 60, remaining: 30, reset: reset}); d != 0 {
		t.Errorf("30/60 left: wait %s, want 0", d)
	}
	if d := c.throttle(&page{}); d != 0 {
		t.Errorf("no headers: wait %s, want 0", d)
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		err                    error
		retry, unavail, badReq bool
	}{
		{&apiError{status: 429}, true, false, false},
		{&apiError{status: 503}, true, false, false},
		{&apiError{status: 401}, false, true, false},
		{&apiError{status: 403, code: "E0000006"}, false, true, false},
		{&apiError{status: 400}, false, false, true},
		{&authError{status: 401, code: "invalid_client"}, false, true, false},
		{&authError{status: 400, code: "invalid_scope"}, false, true, false},
		{&authError{status: 503}, true, false, false},
		{&url.Error{Op: "Get", URL: "u", Err: &authError{status: 401}}, false, true, false},
		{&url.Error{Op: "Get", URL: "u", Err: context.Canceled}, false, false, false},
		{fmt.Errorf("decode system log page: unexpected EOF"), true, false, false},
	}
	for _, c := range cases {
		if retryable(c.err) != c.retry || unavailable(c.err) != c.unavail || badRequest(c.err) != c.badReq {
			t.Errorf("%v: retryable %v unavailable %v badRequest %v", c.err, retryable(c.err), unavailable(c.err), badRequest(c.err))
		}
	}
}

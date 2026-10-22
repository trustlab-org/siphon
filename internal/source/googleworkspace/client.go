package googleworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"golang.org/x/oauth2/google"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/googleapi"
)

const (
	pageSize    = 1000
	defaultBase = "https://admin.googleapis.com/"
)

type activityPage struct {
	Items         []map[string]any `json:"items"`
	NextPageToken string           `json:"nextPageToken"`
}

type client struct {
	http       *http.Client
	base       string
	customerID string
}

func newClient(credentialsFile, subject, customerID string) (*client, error) {
	raw, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	jwt, err := google.JWTConfigFromJSON(raw, reports.AdminReportsAuditReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	jwt.Subject = subject
	httpClient := jwt.Client(context.Background())
	httpClient.Timeout = 60 * time.Second
	return &client{http: httpClient, base: defaultBase, customerID: customerID}, nil
}

func (c *client) page(ctx context.Context, app string, start, end time.Time, token string) (*activityPage, error) {
	q := url.Values{}
	q.Set("startTime", start.UTC().Format(time.RFC3339Nano))
	q.Set("endTime", end.UTC().Format(time.RFC3339Nano))
	q.Set("maxResults", strconv.Itoa(pageSize))
	if c.customerID != "" {
		q.Set("customerId", c.customerID)
	}
	if token != "" {
		q.Set("pageToken", token)
	}
	u := c.base + "admin/reports/v1/activity/users/all/applications/" + url.PathEscape(app) + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
	var p activityPage
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode %s page: %w", app, err)
	}
	return &p, nil
}

func retryable(err error) bool {
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		case http.StatusForbidden:
			return rateLimited(gerr)
		}
		return false
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		return true
	}
	return !errors.Is(err, context.Canceled)
}

func unavailable(err error) bool {
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) {
		return false
	}
	switch gerr.Code {
	case http.StatusBadRequest, http.StatusNotFound:
		return true
	case http.StatusForbidden:
		return !rateLimited(gerr)
	}
	return false
}

func rateLimited(gerr *googleapi.Error) bool {
	for _, e := range gerr.Errors {
		if e.Reason == "rateLimitExceeded" || e.Reason == "userRateLimitExceeded" || e.Reason == "quotaExceeded" {
			return true
		}
	}
	return false
}

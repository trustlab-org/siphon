package pull

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// RetryAfter is implemented by errors that carry a server-requested wait, such as a rate limit time
type RetryAfter interface {
	RetryAfter() time.Duration
}

func Retry(ctx context.Context, boff backoff.BackOff, retryable func(error) bool, onRetry func(error, time.Duration), fn func() error) error {
	boff.Reset()
	h := &hinted{BackOff: boff}
	op := func() error {
		err := fn()
		if err != nil && !retryable(err) {
			return backoff.Permanent(err)
		}
		var ra RetryAfter
		if errors.As(err, &ra) {
			h.hint = ra.RetryAfter()
		}
		return err
	}
	return backoff.RetryNotify(op, backoff.WithContext(h, ctx), onRetry)
}

type hinted struct {
	backoff.BackOff
	hint time.Duration
}

func (h *hinted) NextBackOff() time.Duration {
	d := h.BackOff.NextBackOff()
	if d != backoff.Stop && h.hint > d {
		d = h.hint
	}
	h.hint = 0
	return d
}

func Sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

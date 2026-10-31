package pull

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
)

type hintErr struct{ d time.Duration }

func (e hintErr) Error() string             { return "rate limited" }
func (e hintErr) RetryAfter() time.Duration { return e.d }

func TestRetryHonoursServerHint(t *testing.T) {
	var waits []time.Duration
	calls := 0
	err := Retry(context.Background(), &backoff.ConstantBackOff{Interval: time.Millisecond},
		func(error) bool { return true },
		func(_ error, d time.Duration) { waits = append(waits, d) },
		func() error {
			calls++
			switch calls {
			case 1:
				return hintErr{d: 30 * time.Millisecond}
			case 2:
				return errors.New("plain")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(waits) != 2 || waits[0] != 30*time.Millisecond || waits[1] != time.Millisecond {
		t.Fatalf("waits = %v; want the hint once, then the normal backoff", waits)
	}
}

func TestDriverStartsOnce(t *testing.T) {
	d := NewDriver()
	setups := 0
	ran := make(chan struct{}, 2)
	setup := func() ([]func(context.Context), error) {
		setups++
		return []func(context.Context){func(ctx context.Context) {
			ran <- struct{}{}
			<-ctx.Done()
		}}, nil
	}
	for range 2 {
		if err := d.Start(setup); err != nil {
			t.Fatal(err)
		}
	}
	<-ran
	if err := d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if setups != 1 || len(ran) != 0 {
		t.Fatalf("setups = %d, extra loops = %d; reconnects must not start duplicate loops", setups, len(ran))
	}
}

func TestDriverRetriesFailedSetup(t *testing.T) {
	d := NewDriver()
	if err := d.Start(func() ([]func(context.Context), error) { return nil, errors.New("no creds") }); err == nil {
		t.Fatal("want the setup error")
	}
	started := false
	if err := d.Start(func() ([]func(context.Context), error) { started = true; return nil, nil }); err != nil || !started {
		t.Fatal("a failed setup must allow a later Connect to try again")
	}
}

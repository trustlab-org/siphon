package pull

import (
	"context"
	"sync"

	"github.com/warpstreamlabs/bento/public/service"
)

// Driver runs a polling inputs goroutines and hands their batches over bento
type Driver struct {
	out     chan Pending
	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewDriver() *Driver {
	return &Driver{out: make(chan Pending)}
}

// Out is where poll loops send batches; a send blocks until bento reads it
func (d *Driver) Out() chan<- Pending { return d.out }

func (d *Driver) Start(setup func() ([]func(context.Context), error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return nil
	}
	loops, err := setup()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	for _, loop := range loops {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			loop(ctx)
		}()
	}
	d.started = true
	return nil
}

func (d *Driver) ReadBatch(ctx context.Context) (service.MessageBatch, service.AckFunc, error) {
	select {
	case p := <-d.out:
		return p.Batch, p.Ack, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (d *Driver) Stop(ctx context.Context) error {
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

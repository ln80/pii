package pii

import (
	"context"
	"sync"
	"time"
)

type ClearFunc func()

type BuildFunc func(namespace string) Protector

type Factory interface {
	Instance(namespace string) (Protector, ClearFunc)

	Monitor(ctx context.Context)
}

type FactoryConfig struct {
	IDLE, MonitorPeriod time.Duration
}

type factory struct {
	mu      sync.RWMutex
	reg     map[string]Protector
	builder BuildFunc
	*FactoryConfig
}

func NewFactory(b BuildFunc, opts ...func(*FactoryConfig)) Factory {
	if b == nil {
		panic("invalid Protector builfer func , nil value found")
	}

	f := &factory{
		reg:     make(map[string]Protector),
		builder: b,
		FactoryConfig: &FactoryConfig{
			IDLE:          20 * time.Minute,
			MonitorPeriod: 5 * time.Second,
		},
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(f.FactoryConfig)
	}

	return f
}

func (f *factory) Instance(namespace string) (Protector, ClearFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.reg[namespace]; !ok {
		f.reg[namespace] = f.builder(namespace)
	}

	clearFunc := func() {
		// Force Protector to clear cache without considering the current context.
		// Ignore the returned error, which unlikely to occure.
		_ = f.reg[namespace].Clear(context.Background(), true)
	}

	return f.reg[namespace], clearFunc
}

func (f *factory) clear(ctx context.Context, force bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for nspace, p := range f.reg {
		// clear protector encryption materials cache
		// internally, Protector.Clear will check and proceed based on Protector.CacheTTL
		_ = p.Clear(ctx, force)

		// remove inactive protectors based on last activity timestamp
		if t := p.LastActiveAt(); !t.IsZero() && t.Add(f.IDLE).Before(time.Now()) || force {
			delete(f.reg, nspace)
		}
	}
}

func (f *factory) Monitor(ctx context.Context) {
	ticker := time.NewTicker(f.MonitorPeriod)
	go func() {
		defer f.clear(ctx, true)

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				f.clear(ctx, false)
			}
		}
	}()
}

// func ProofRead() {

// 	f := NewFactory(nil)
// 	f.Monitor(context.TODO())

// 	p, clear := f.Instance("tenantID")
// 	defer clear()

// 	p.Encrypt(context.TODO())

// }

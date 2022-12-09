package pii

import (
	"context"
	"sync"
	"time"
)

// FactoryClearFunc presents the function returned by Factory.Instance method.
// It tells the associated Protector instance to immediately clear the cache of encryption materials.
type FactoryClearFunc func()

// FactoryNewFunc is used by the Factory service to create Perotector instance per namespace.
type FactoryNewFunc func(namespace string) Protector

// Factory manages and maintains a registry of Protector services.
//
// It monitors each Protector service to track its activity
// and regularly clears encryption materials caches.
type Factory interface {

	// Instance creates a new Protector instance for the given namespace or returns the existing one.
	Instance(namespace string) (Protector, FactoryClearFunc)

	// Monitor starts a long-running process in a separate Goroutine.
	// It checks Protectors' activities and removes inactive ones,
	// and clears their caches based on their cache TTL config.
	Monitor(ctx context.Context)
}

// FactoryConfig presents the configuration of Factory service
type FactoryConfig struct {

	// IDLE is the duration used to define whether a Protector service is inactive.
	IDLE time.Duration

	// MonitorPeriod is the frequency of the regular checks made by the monitoring process.
	MonitorPeriod time.Duration
}

type factory struct {
	mu           sync.RWMutex
	reg          map[string]Protector
	newProtector FactoryNewFunc
	*FactoryConfig
}

// NewFactory returns a thread-safe factory service instance.
// It panics if builderFunc is nil.
// Options params allow overwriting the default configuration.
func NewFactory(newProt FactoryNewFunc, opts ...func(*FactoryConfig)) Factory {
	if newProt == nil {
		panic("invalid new Protector func, nil value found")
	}

	f := &factory{
		reg:          make(map[string]Protector),
		newProtector: newProt,
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

// Instance implements Factory interface
func (f *factory) Instance(namespace string) (Protector, FactoryClearFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.reg[namespace]; !ok {
		// Wraps the returned protector to track its activities
		tp := &traceable{Protector: f.newProtector(namespace)}
		f.reg[namespace] = tp
		tp.markOp()
	}

	FactoryClearFunc := func() {
		// Force Protector to clear cache without considering the current context.
		// Ignore the returned error, which unlikely to occur.
		_ = f.reg[namespace].Clear(context.Background(), true)
	}

	return f.reg[namespace], FactoryClearFunc
}

func (f *factory) clear(ctx context.Context, force bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for nspace, p := range f.reg {
		// clear protector encryption materials cache
		_ = p.Clear(ctx, force)

		// remove inactive protectors based on last activity timestamp
		tp, ok := p.(*traceable)
		if t := tp.lastOpsAt; ok && !t.IsZero() && t.Add(f.IDLE).Before(time.Now()) || force {
			delete(f.reg, nspace)
		}
	}
}

// Monitor implements Factory interface
func (f *factory) Monitor(ctx context.Context) {
	ticker := time.NewTicker(f.MonitorPeriod)
	go func() {
		defer func() {
			// Use a timed-out context to ensure the original context cancellation
			// will not prevent clearing the cache.
			clearCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			f.clear(clearCtx, true)
			cancel()
		}()

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

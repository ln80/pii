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

type factory struct {
	mu      sync.RWMutex
	reg     map[string]Protector
	builder BuildFunc
}

func NewFactory(b BuildFunc) Factory {
	if b == nil {
		b = func(nspace string) Protector {
			return NewProtector(nspace)
		}
	}

	return &factory{
		reg:     make(map[string]Protector),
		builder: b,
	}
}

func (f *factory) Instance(namespace string) (Protector, ClearFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.reg[namespace]; !ok {
		f.reg[namespace] = f.builder(namespace)
	}

	clearFunc := func() {
		// force Protector to clear cache without considering the current context.
		// ignore the error return which unlikely occure
		_ = f.reg[namespace].Clear(context.Background(), true)
	}

	return f.reg[namespace], clearFunc
}

func (f *factory) clear(ctx context.Context, force bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, p := range f.reg {
		_ = p.Clear(ctx, force)
	}
}

func (f *factory) Monitor(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
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

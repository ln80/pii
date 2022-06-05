package pii

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ln80/pii/memory"
	"github.com/ln80/pii/testutil"
)

type spyProtector struct {
	Protector

	mu    sync.RWMutex
	Calls testutil.FuncCalls
}

func (tp *spyProtector) Clear(ctx context.Context, force bool) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if tp.Calls == nil {
		tp.Calls = testutil.NewFuncCalls()
	}
	tp.Calls["Clear"] = append(tp.Calls["Clear"], time.Now())

	return tp.Protector.Clear(ctx, force)
}

func TestFactory(t *testing.T) {

	assertProtectorCount := func(t *testing.T, f *factory, count int) {
		if want, got := count, len(f.reg); want != got {
			t.Fatalf("expect Protectors count be %d, got %d", want, got)
		}
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	builder := func(namespace string) Protector {
		return &spyProtector{
			Protector: NewProtector(namespace, memory.NewKeyEngine(), func(pc *ProtectorConfig) {
				pc.CacheEnabled = true
				pc.CacheTTL = 1
				pc.GracefullMode = true
			}),
		}
	}

	// setup Factory and overwrite default durations with short values
	idle := 500 * time.Millisecond
	period := 100 * time.Millisecond
	margin := 10 * time.Millisecond
	f := NewFactory(builder, func(fc *FactoryConfig) {
		fc.IDLE = idle
		fc.MonitorPeriod = period
	})

	// init two Protectors & assert registry count
	p1, _ := f.Instance("namespace_1")
	_, _ = f.Instance("namespace_1")
	p2, _ := f.Instance("namespace_2")

	assertProtectorCount(t, f.(*factory), 2)

	// start monitoring
	f.Monitor(ctx)

	// wait and spy Protectors' calls execs
	time.Sleep(margin)
	time.Sleep(period)

	p1.(*traceable).Protector.(*spyProtector).Calls.AssertCount(t, "Clear", 1)
	p2.(*traceable).Protector.(*spyProtector).Calls.AssertCount(t, "Clear", 1)

	// assert Monitor periodically clears resources
	time.Sleep(period)

	p1.(*traceable).Protector.(*spyProtector).Calls.AssertCount(t, "Clear", 2)

	p2.(*traceable).Protector.(*spyProtector).Calls.AssertCount(t, "Clear", 2)

	// assert sure Factory already deleted inactive Protectors from registry
	time.Sleep(idle)
	time.Sleep(margin)

	assertProtectorCount(t, f.(*factory), 0)

	// init a new Protector and force context cancelation
	p3, _ := f.Instance("namespace_2")

	if want, got := 1, len(f.(*factory).reg); want != got {
		t.Fatalf("expect %d, %d be equals", want, got)
	}

	time.Sleep(margin)
	time.Sleep(period)

	p3.(*traceable).Protector.(*spyProtector).Calls.AssertCount(t, "Clear", 1)

	cancelCtx()

	time.Sleep(margin)

	// assert Protector was deleted from registry even is not IDLE
	assertProtectorCount(t, f.(*factory), 0)
}

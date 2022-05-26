package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/pii/testutil"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	eng := NewKeyEngine()

	testutil.KeyEngineTestSuite(t, ctx, eng)

	eng = NewCacheWrapper(eng, 20*time.Minute)

	testutil.KeyEngineTestSuite(t, ctx, eng)
}

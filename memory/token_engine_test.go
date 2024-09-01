package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/pii/testutil"
)

func TestTokenEngine(t *testing.T) {
	ctx := context.Background()

	t.Run("in-memory engine", func(t *testing.T) {
		testutil.TokenEngineTestSuite(t, ctx, NewTokenEngine())
	})

	t.Run("in-memory cache wrapper engine", func(t *testing.T) {
		originEngine := NewTokenEngine()
		testutil.TokenEngineTestSuite(t, ctx, NewTokenCacheWrapper(originEngine, 20*time.Minute))
	})
}

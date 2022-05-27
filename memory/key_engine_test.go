package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/pii/testutil"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	t.Run("in-memory engine", func(t *testing.T) {
		eng := NewKeyEngine()

		testutil.KeyEngineTestSuite(t, ctx, eng)
	})

	t.Run("in-memory cache wrapper engine", func(t *testing.T) {
		originEng := NewKeyEngine()

		eng := NewCacheWrapper(originEng, 20*time.Minute)

		testutil.KeyEngineTestSuite(t, ctx, eng)
	})
}

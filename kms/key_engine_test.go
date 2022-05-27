package kms

import (
	"context"
	"testing"

	"github.com/ln80/pii/memory"
	"github.com/ln80/pii/testutil"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	originEng := memory.NewKeyEngine()

	testutil.WithKMSKey(t, func(kmsvc interface{}, key string) {
		resolver := NewStaticKMSKeyResolver(key)

		eng := NewKMSWrapper(kmsvc.(ClientAPI), resolver, originEng)

		testutil.KeyEngineTestSuite(t, ctx, eng)
	})
}

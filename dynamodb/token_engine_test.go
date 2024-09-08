package dynamodb

import (
	"context"
	"testing"
	"time"

	db_testutil "github.com/ln80/pii/dynamodb/testutil"
	"github.com/ln80/pii/memory"
	"github.com/ln80/pii/testutil"
)

func TestTokenEngine(t *testing.T) {
	ctx := context.Background()

	db_testutil.WithDynamoDBTable(t, func(dbsvc interface{}, table string) {

		// prepare dynamodb token engine
		eng := NewEngine(dbsvc.(ClientAPI), table)

		// run test suite against the dynamodb engine directly
		ctx1, cc1 := capacityContext(ctx)
		testutil.TokenEngineTestSuite(t, ctx1, eng)

		// run test suite against a cached dynamodb engine
		ctx2, cc2 := capacityContext(ctx)
		testutil.TokenEngineTestSuite(t, ctx2, memory.NewTokenCacheWrapper(eng, 20*time.Minute))

		// compare consumed capacities in both cases, and assert that the later consume less
		// as sub queries hit the cache.
		if cc1.Total <= cc2.Total {
			t.Fatalf("expect cached engine's consumed capacity '%f' be less than '%f'", cc2.Total, cc1.Total)
		}
	})
}

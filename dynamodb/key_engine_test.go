package dynamodb

import (
	"context"
	"testing"

	"github.com/ln80/pii/testutil"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	testutil.WithDynamoDBTable(t, func(dbsvc interface{}, table string) {
		eng := NewKeyEngine(dbsvc.(ClientAPI), table)
		testutil.KeyEngineTestSuite(t, ctx, eng)
	})
}

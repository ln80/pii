package dynamodb

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/ln80/pii/testutil"
	testdynamodb "github.com/ln80/pii/testutil/dynamodb"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	testdynamodb.WithTable(t, func(dbsvc *dynamodb.Client, table string) {
		eng := NewKeyEngine(dbsvc, table)
		testutil.KeyEngineTestSuite(t, ctx, eng)
	})
}

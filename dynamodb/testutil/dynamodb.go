package testutil

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// following keys and attributes must be equals their equivalents defined in dynamodb package
const (
	HashKey  string = "_pk"
	RangeKey string = "_sk"
	LsiKey          = "_lsik"
)

var (
	LsiProjAttr []string = []string{"_key", "_kid"}
)

var (
	dbsvc  *dynamodb.Client
	dbonce sync.Once
	rdm    = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func genTableName(prefix string) string {
	now := strconv.FormatInt(time.Now().UnixNano(), 36)
	random := strconv.FormatInt(int64(rdm.Int31()), 36)
	return prefix + "-" + now + "-" + random
}

func WithDynamoDBTable(t *testing.T, tfn func(dbsvc interface{}, table string)) {
	ctx := context.Background()

	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("dynamodb test endpoint not found")
	}

	dbonce.Do(func() {
		cfg, err := config.LoadDefaultConfig(
			ctx,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider("TEST", "TEST", "TEST"),
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		dbsvc = dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.EndpointResolver = dynamodb.EndpointResolverFromURL(endpoint)
		})
	})

	table := genTableName("tmp-table")

	if err := CreateTable(ctx, dbsvc, table); err != nil {
		t.Fatalf("failed to create test table '%s': %v", table, err)
	}

	t.Log("dynamodb test table created:", table)

	defer func() {
		if err := deleteTable(ctx, dbsvc, table); err != nil {
			t.Fatalf("failed to remove test table '%s': %v", table, err)
		}
		t.Log("dynamodb test table deleted:", table)
	}()

	tfn(dbsvc, table)
}

func CreateTable(ctx context.Context, svc *dynamodb.Client, table string) error {
	_, err := svc.CreateTable(ctx, &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String(HashKey),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(RangeKey),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String(LsiKey),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String(HashKey),
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String(RangeKey),
				KeyType:       types.KeyTypeRange,
			},
		},
		TableName:   aws.String(table),
		BillingMode: types.BillingModePayPerRequest,
		LocalSecondaryIndexes: []types.LocalSecondaryIndex{
			{
				IndexName: aws.String("_lsi"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String(HashKey),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String(LsiKey),
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
				// Projection: &types.Projection{
				// 	ProjectionType:   types.ProjectionTypeInclude,
				// 	NonKeyAttributes: LsiProjAttr,
				// },
			},
		},
	})
	if err != nil {
		var (
			er1 *types.TableAlreadyExistsException
			er2 *types.ResourceInUseException
		)
		if errors.As(err, &er1) || errors.As(err, &er2) {
			return nil
		}

		return err
	}

	if err = waitForTable(ctx, svc, table); err != nil {
		return err
	}

	return nil

}

func deleteTable(ctx context.Context, svc *dynamodb.Client, table string) error {
	if _, err := svc.DeleteTable(ctx, &dynamodb.DeleteTableInput{
		TableName: aws.String(table),
	}); err != nil {
		return err
	}
	return nil
}

func waitForTable(ctx context.Context, svc *dynamodb.Client, table string) error {
	w := dynamodb.NewTableExistsWaiter(svc)
	if err := w.Wait(ctx,
		&dynamodb.DescribeTableInput{
			TableName: aws.String(table),
		},
		2*time.Minute,
		func(o *dynamodb.TableExistsWaiterOptions) {
			o.MaxDelay = 5 * time.Second
			o.MinDelay = 1 * time.Second
		}); err != nil {
		return fmt.Errorf("timed out while waiting for table to become active: %w", err)
	}
	return nil
}

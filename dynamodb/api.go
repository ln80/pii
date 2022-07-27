package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/ln80/pii/dynamodb/testutil"
)

// ClientAPI presents an interface for a sub-part of the AWS Dynamodb client service:
// github.com/aws/aws-sdk-go-v2/service/dynamodb
type ClientAPI interface {
	dynamodb.QueryAPIClient

	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// CreateTable is an alias of CreateTable func defined in testutil package.
// Mainly used for test and local dev purposes.
var CreateTable = testutil.CreateTable

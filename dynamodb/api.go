package dynamodb

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http"
)

type ClientAPI interface {
	dynamodb.QueryAPIClient

	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// IsConditionCheckFailure checks if the given error is an aws error that expresses a conditional failure exception.
// It works seamlessly in both single write and within a transaction operation.
func IsConditionCheckFailure(err error) bool {
	if strings.Contains(err.Error(), "ConditionalCheckFailedException") {
		return true
	}
	var oe *smithy.OperationError
	if errors.As(err, &oe) {
		var re *http.ResponseError
		if errors.As(err, &re) {
			var tce *types.TransactionCanceledException
			if errors.As(err, &tce) {
				for _, reason := range tce.CancellationReasons {
					if *reason.Code == "ConditionalCheckFailed" {
						return true
					}
				}
			}
		}
	}

	return false
}

package dynamodb

import (
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// isConditionCheckFailure checks if the given error is an aws error that expresses a conditional failure exception.
// It works seamlessly in both single write and within a transaction operation.
func isConditionCheckFailure(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "ConditionalCheckFailedException") {
		return true
	}
	var tce *types.TransactionCanceledException
	if errors.As(err, &tce) {
		for _, reason := range tce.CancellationReasons {
			if *reason.Code == "ConditionalCheckFailed" {
				return true
			}
		}
	}

	return false
}

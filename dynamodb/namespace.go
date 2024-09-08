package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type NamespaceItem struct {
	Item
	Namespace string `dynamodbav:"_nspace"`
	At        int64  `dynamodbav:"_at"`
}

// NamespaceRegistry mainly used internally or by a cron to look up for namespaces to clean.
type NamespaceRegistry interface {
	// ListNamespace returns a list of registred namespaces.
	// Namespaces are mainly added to the internal registry during the GetOrCtreateKeys ops.
	ListNamespace(ctx context.Context) ([]string, error)
}

var _ NamespaceRegistry = &Engine{}

func (e *Engine) addNamespace(ctx context.Context, namespace string) error {
	item := NamespaceItem{
		Item: Item{
			HashKey:  nsHashKeyVal,
			RangeKey: namespace,
		},
		Namespace: namespace,
		At:        time.Now().Unix(),
	}

	m, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	expr, err := expression.
		NewBuilder().
		WithCondition(
			expression.AttributeNotExists(
				expression.Name(hashKey),
			).And(
				expression.AttributeNotExists(
					expression.Name(rangeKey),
				),
			),
		).Build()
	if err != nil {
		return err
	}

	ctx, cc := capacityContext(ctx)

	out, err := e.svc.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(e.table),
		Item:                      m,
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ReturnConsumedCapacity:    types.ReturnConsumedCapacityIndexes,
	})
	if out != nil {
		addConsumedCapacity(cc, out.ConsumedCapacity)
	}
	if err != nil {
		if isConditionCheckFailure(err) {
			return nil
		}
		return err
	}
	return nil
}

func (e *Engine) ListNamespace(ctx context.Context) ([]string, error) {
	expr, err := expression.NewBuilder().
		WithKeyCondition(
			expression.Key(hashKey).Equal(expression.Value(nsHashKeyVal)),
		).
		WithProjection(
			expression.NamesList(expression.Name(attrNamespace)),
		).
		Build()
	if err != nil {
		return nil, err
	}

	p := dynamodb.NewQueryPaginator(e.svc, &dynamodb.QueryInput{
		TableName:                 aws.String(e.table),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ConsistentRead:            aws.Bool(true),
		ProjectionExpression:      expr.Projection(),
	})

	items := []NamespaceItem{}
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		pageItems := []NamespaceItem{}
		if err = attributevalue.UnmarshalListOfMaps(out.Items, &pageItems); err != nil {
			return nil, err
		}
		items = append(items, pageItems...)
	}

	r := make([]string, len(items))
	for i, item := range items {
		r[i] = item.Namespace
	}

	return r, nil
}

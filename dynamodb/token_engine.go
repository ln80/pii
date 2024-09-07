package dynamodb

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/ln80/pii/core"
)

var _ core.TokenEngine = &Engine{}

type TokenItem struct {
	Item
	Namespace  string `dynamodbav:"_nspace"`
	Token      string `dynamodbav:"_tkn"`
	TokenValue string `dynamodbav:"_tknv"`
	CreatedAt  int64  `dynamodbav:"_createdAt"`
}

// Detokenize implements core.TokenEngine.
func (e *Engine) Detokenize(ctx context.Context, namespace string, tokens []string) (tokenValues core.TokenValueMap, err error) {
	count := len(tokens)
	if count == 0 {
		return
	}

	defer func() {
		if err != nil {
			err = errors.Join(core.ErrDetokenizeFailure, err)
		}
	}()

	tokenValues = make(core.TokenValueMap)

	slices.Sort(tokens)

	ops := []expression.OperandBuilder{}
	for i := 0; i < count; i++ {
		ops = append(ops, expression.Value(tokens[i]))
	}

	b := expression.NewBuilder().
		WithKeyCondition(
			expression.Key(hashKey).Equal(expression.Value(namespace)).
				And(
					expression.Key(rangeKey).Between(
						expression.Value("token#"+tokens[0]),
						expression.Value("token#"+tokens[len(tokens)-1]),
					),
				),
		).
		WithFilter(
			expression.Name(attrToken).In(ops[0], ops[1:count]...),
		).
		WithProjection(
			expression.NamesList(expression.Name(attrToken), expression.Name(attrTokenValue)),
		)

	expr, err := b.Build()
	if err != nil {
		return
	}

	ctx, cc := capacityContext(ctx)
	p := dynamodb.NewQueryPaginator(e.svc, &dynamodb.QueryInput{
		TableName:                 aws.String(e.table),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ConsistentRead:            aws.Bool(true),
		ProjectionExpression:      expr.Projection(),
		ReturnConsumedCapacity:    types.ReturnConsumedCapacityIndexes,
	})

	items := []TokenItem{}
	for p.HasMorePages() {
		var out *dynamodb.QueryOutput
		out, err = p.NextPage(ctx)
		if out != nil {
			addConsumedCapacity(cc, out.ConsumedCapacity)
		}
		if err != nil {
			return
		}
		pageItems := []TokenItem{}
		if err = attributevalue.UnmarshalListOfMaps(out.Items, &pageItems); err != nil {
			return nil, err
		}
		items = append(items, pageItems...)
	}

	for _, item := range items {
		tokenValues[item.Token] = core.TokenRecord{
			Token: item.Token,
			Value: core.TokenData(item.TokenValue),
		}
	}

	return
}

// Tokenize implements core.TokenEngine.
func (e *Engine) Tokenize(ctx context.Context, namespace string, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (valueTokens core.ValueTokenMap, err error) {
	cfg := core.TokenizeConfig{
		TokenGenFunc: core.DefaultTokenGen,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}

	ctx, _ = capacityContext(ctx)

	defer func() {
		if err != nil {
			err = errors.Join(core.ErrTokenizeFailure, err)
		}
	}()

	if cfg.TokenGenFunc == nil {
		err = core.ErrTokenGenFuncNotFound
		return
	}

	valueTokens, err = e.getTokens(ctx, namespace, values)
	if err != nil {
		return
	}

	if len(valueTokens) == 0 {
		if err = e.addNamespace(ctx, namespace); err != nil {
			return
		}
	}

	missedTokens := []core.TokenRecord{}
	for _, value := range values {
		if _, ok := valueTokens[value]; ok {
			continue
		}
		newToken, err := cfg.TokenGenFunc(ctx, namespace, value)
		if err != nil {
			return nil, err
		}
		missedTokens = append(missedTokens, core.TokenRecord{
			Token: newToken,
			Value: value,
		})
	}

	if err = e.createTokens(ctx, namespace, missedTokens); err != nil {
		return
	}

	for _, r := range missedTokens {
		valueTokens[r.Value] = r
	}

	return
}

func (e *Engine) DeleteToken(ctx context.Context, namespace string, token string) (err error) {
	defer func() {
		if err != nil {
			err = errors.Join(core.ErrDeleteTokenFailure, err)
		}
	}()

	expr, _ := expression.
		NewBuilder().
		WithCondition(
			expression.AttributeExists(
				expression.Name(hashKey),
			).And(
				expression.AttributeExists(
					expression.Name(rangeKey),
				),
			),
		).Build()

	ctx, cc := capacityContext(ctx)
	out, err := e.svc.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(e.table),
		Key: map[string]types.AttributeValue{
			hashKey: &types.AttributeValueMemberS{
				Value: namespace,
			},
			rangeKey: &types.AttributeValueMemberS{
				Value: "token#" + token,
			},
		},
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ReturnConsumedCapacity:    types.ReturnConsumedCapacityIndexes,
	})
	if out != nil {
		addConsumedCapacity(cc, out.ConsumedCapacity)
	}
	if err != nil {
		return
	}

	return
}

func (e *Engine) createTokens(ctx context.Context, namespace string, tokens []core.TokenRecord) error {
	for _, t := range tokens {
		item := TokenItem{
			Item: Item{
				HashKey:  namespace,
				RangeKey: "token#" + t.Token,
				LSIKey:   "token@" + string(t.Value),
			},
			Namespace:  namespace,
			Token:      t.Token,
			TokenValue: string(t.Value),
			CreatedAt:  time.Now().Unix(),
		}

		mt, err := attributevalue.MarshalMap(item)
		if err != nil {
			return err
		}

		expr, _ := expression.
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

		ctx, cc := capacityContext(ctx)
		out, err := e.svc.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:                 aws.String(e.table),
			Item:                      mt,
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
			ReturnConsumedCapacity:    types.ReturnConsumedCapacityIndexes,
		})
		if out != nil {
			addConsumedCapacity(cc, out.ConsumedCapacity)
		}
		if err != nil {
			// if isConditionCheckFailure(err) {
			// 	// if err := handleExist(idkey); err != nil {
			// 	// 	return nil, nil, err
			// 	// }
			// 	continue
			// }
			return err
		}

	}
	return nil
}

func (e *Engine) getTokens(ctx context.Context, namespace string, values []core.TokenData) (tokens core.ValueTokenMap, err error) {
	count := len(values)
	if count == 0 {
		return
	}

	tokens = make(map[core.TokenData]core.TokenRecord)

	slices.Sort(values)

	ops := []expression.OperandBuilder{}
	for i := 0; i < count; i++ {
		ops = append(ops, expression.Value(values[i]))
	}

	b := expression.NewBuilder().
		WithKeyCondition(
			expression.Key(hashKey).Equal(expression.Value(namespace)).
				And(
					expression.Key(lsiKey).Between(
						expression.Value("token@"+values[0]),
						expression.Value("token@"+values[len(values)-1]),
					),
				),
		).
		WithFilter(
			expression.Name(attrTokenValue).In(ops[0], ops[1:count]...),
		).
		WithProjection(
			expression.NamesList(expression.Name(attrToken), expression.Name(attrTokenValue)),
		)

	expr, err := b.Build()
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
		IndexName:                 aws.String(lsi),
		ReturnConsumedCapacity:    types.ReturnConsumedCapacityIndexes,
	})

	ctx, cc := capacityContext(ctx)

	items := []TokenItem{}
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if out != nil {
			addConsumedCapacity(cc, out.ConsumedCapacity)
		}
		if err != nil {
			return nil, err
		}
		pageItems := []TokenItem{}
		if err = attributevalue.UnmarshalListOfMaps(out.Items, &pageItems); err != nil {
			return nil, err
		}
		items = append(items, pageItems...)
	}

	for _, item := range items {
		tokens[core.TokenData(item.TokenValue)] = core.TokenRecord{
			Token: item.Token,
			Value: core.TokenData(item.TokenValue),
		}
	}
	return
}

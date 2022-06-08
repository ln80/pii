package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/ln80/pii/aes"
	"github.com/ln80/pii/core"
)

// Const
const (
	hashKey  = "_pk"
	rangeKey = "_sk"

	attrKeyID      = "_sub"
	attrKey        = "_key"
	attrDisabledAt = "_disabledAt"
	attrDeletedAt  = "_deletedAt"
	attrState      = "_state"
)

// KeyItem defines Dynamodb Key Engine table schema.
type KeyItem struct {
	HashKey    string `dynamodbav:"_pk"`
	RangeKey   string `dynamodbav:"_sk"`
	Namespace  string `dynamodbav:"_nspace"`
	KeyID      string `dynamodbav:"_sub"`
	Key        []byte `dynamodbav:"_key"`
	State      string `dynamodbav:"_state"`
	CreatedAt  int64  `dynamodbav:"_createdAt"`
	DisabledAt int64  `dynamodbav:"_disabledAt"`
	DeletedAt  int64  `dynamodbav:"_deletedAt"`
}

type engine struct {
	svc   ClientAPI
	table string
}

var _ core.KeyEngine = &engine{}

// NewKeyEngine returns a core.KeyEngine implementation built on top of a Dynamodb table.
//
// It requires a non-empty value for Dynamodb client service and table name parameters. Otherwise, it will panic.
func NewKeyEngine(svc ClientAPI, table string) core.KeyEngine {
	if svc == nil {
		panic("invalid Dynamodb client service, nil value found")
	}
	if table == "" {
		panic("invalid dynamodb table name, emtpy value found")
	}

	eng := &engine{
		svc:   svc,
		table: table,
	}

	return eng
}

func (e *engine) updateKeyItem(ctx context.Context, namespace, keyID string, expr expression.Expression) error {
	if _, err := e.svc.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		Key: map[string]types.AttributeValue{
			hashKey:  &types.AttributeValueMemberS{Value: namespace},
			rangeKey: &types.AttributeValueMemberS{Value: keyID},
		},
		TableName:                 aws.String(e.table),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
	}); err != nil {
		return err
	}
	return nil
}

func (e *engine) createKeys(ctx context.Context, nspace string, keys []core.IDKey) (exist map[string]struct{}, err error) {
	exist = map[string]struct{}{}
	for _, idkey := range keys {
		kItem := KeyItem{
			HashKey:   nspace,
			RangeKey:  idkey.ID(),
			Namespace: nspace,
			KeyID:     idkey.ID(),
			Key:       []byte(idkey.Key()),
			CreatedAt: time.Now().UTC().Unix(),
			State:     core.StateActive,
		}

		mk, err := attributevalue.MarshalMap(kItem)
		if err != nil {
			return nil, err
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
			return nil, err
		}

		if _, err = e.svc.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:                 aws.String(e.table),
			Item:                      mk,
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		}); err != nil {
			if isConditionCheckFailure(err) {
				// perform a second check with a specific condition
				// to distinguish new fresh created keys from the deleted/disabled ones
				// update must returns the new fresh key value
				// condition must be cost effective
				exist[idkey.ID()] = struct{}{}
				continue
			}

			return nil, err
		}
	}

	return exist, nil
}

// DeleteKey implements core.KeyEngine
func (e *engine) DeleteKey(ctx context.Context, namespace string, keyID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %v", core.ErrDeleteKeyFailure, err)
		}
	}()

	now := time.Now().UTC()
	expr, err := expression.
		NewBuilder().
		WithUpdate(
			expression.
				Set(expression.Name(attrState), expression.Value(core.StateDeleted)).
				Set(expression.Name(attrDeletedAt), expression.Value(now.Unix())),
		).
		WithCondition(
			expression.NotEqual(expression.Name(attrState), expression.Value(core.StateDeleted)),
		).Build()
	if err != nil {
		return
	}

	if err = e.updateKeyItem(ctx, namespace, keyID, expr); err != nil {
		if isConditionCheckFailure(err) {
			err = nil
		}
		return
	}

	return
}

// DisableKey implements core.KeyEngine
func (e *engine) DisableKey(ctx context.Context, namespace string, keyID string) (err error) {
	defer func() {
		if err != nil {
			if !errors.Is(err, core.ErrKeyNotFound) {
				err = fmt.Errorf("%w: %v", core.ErrDisableKeyFailure, err)
			}
		}
	}()

	expr, err := expression.
		NewBuilder().
		WithUpdate(
			expression.
				Set(expression.Name(attrState), expression.Value(core.StateDisabled)).
				Set(expression.Name(attrDisabledAt), expression.Value(time.Now().UTC().Unix())),
		).
		WithCondition(
			expression.NotEqual(expression.Name(attrState), expression.Value(core.StateDeleted)),
		).Build()
	if err != nil {
		return
	}

	if err = e.updateKeyItem(ctx, namespace, keyID, expr); err != nil {
		if isConditionCheckFailure(err) {
			err = fmt.Errorf("%w: hard deleted key", core.ErrKeyNotFound)
		}
		return
	}

	return nil
}

// RenableKey implements core.KeyEngine
func (e *engine) RenableKey(ctx context.Context, namespace string, keyID string) (err error) {
	defer func() {
		if err != nil {
			if !errors.Is(err, core.ErrKeyNotFound) {
				err = fmt.Errorf("%w: %v", core.ErrRenableKeyFailure, err)
			}
		}
	}()

	expr, err := expression.
		NewBuilder().
		WithUpdate(
			expression.
				Set(expression.Name(attrState), expression.Value(core.StateActive)),
		).
		WithCondition(
			expression.NotEqual(expression.Name(attrState), expression.Value(core.StateDeleted)),
		).Build()
	if err != nil {
		return
	}

	if err = e.updateKeyItem(ctx, namespace, keyID, expr); err != nil {
		if isConditionCheckFailure(err) {
			err = fmt.Errorf("%w: hard deleted key", core.ErrKeyNotFound)
		}
		return
	}

	return nil
}

// GetKeys implements core.KeyEngine
func (e *engine) GetKeys(ctx context.Context, namespace string, keyIDs []string) (keys core.KeyMap, err error) {
	count := len(keyIDs)
	if count == 0 {
		return keys, nil
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %v", core.ErrGetKeyFailure, err)
		}
	}()

	keys = core.NewKeyMap()

	sort.Strings(keyIDs)

	ops := []expression.OperandBuilder{}
	for i := 0; i < count; i++ {
		ops = append(ops, expression.Value(keyIDs[i]))
	}

	b := expression.NewBuilder().
		WithKeyCondition(
			expression.Key(hashKey).Equal(expression.Value(namespace)).
				And(
					expression.Key(rangeKey).Between(expression.Value(keyIDs[0]), expression.Value(keyIDs[len(keyIDs)-1])),
				),
		).
		WithFilter(
			expression.And(
				expression.Name(attrState).Equal(expression.Value(core.StateActive)),
				expression.Name(attrKeyID).In(ops[0], ops[1:count]...),
			),
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
	})

	items := []KeyItem{}
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		pageItems := []KeyItem{}
		if err = attributevalue.UnmarshalListOfMaps(out.Items, &pageItems); err != nil {
			return nil, err
		}

		items = append(items, pageItems...)
	}

	for _, item := range items {
		keys[item.KeyID] = core.Key(string(item.Key))
	}

	return keys, nil
}

// GetOrCreateKeys implements core.KeyEngine
func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen core.KeyGen) (keys core.KeyMap, err error) {
	if keyGen == nil {
		keyGen = aes.Key256GenFn
	}

	keys, err = e.GetKeys(ctx, namespace, keyIDs)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %v", core.ErrPeristKeyFailure, err)
		}
	}()

	missedKeys := []core.IDKey{}
	for _, keyID := range keyIDs {
		if _, ok := keys[keyID]; ok {
			continue
		}

		k, err := keyGen(ctx, namespace, keyID)
		if err != nil {
			return nil, err
		}
		missedKeys = append(missedKeys, core.NewIDKey(keyID, k))
	}

	disabledOrDeleted, err := e.createKeys(ctx, namespace, missedKeys)
	if err != nil {
		return
	}

	for _, missedKey := range missedKeys {
		if _, ok := disabledOrDeleted[missedKey.ID()]; ok {
			continue
		}
		keys[missedKey.ID()] = missedKey.Key()
	}

	return
}

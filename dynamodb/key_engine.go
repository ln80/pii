package dynamodb

import (
	"context"
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

const (
	HashKey  = "_pk"
	RangeKey = "_sk"

	attrSubject    = "_sub"
	attrKey        = "_ckey"
	attrDisabledAt = "_di_at"
	attrDeletedAt  = "_de_at"
	attrState      = "_state"
)

type KeyItem struct {
	HashKey    string `dynamodbav:"_pk"`
	RangeKey   string `dynamodbav:"_sk"`
	Namespace  string `dynamodbav:"_nspace"`
	SubID      string `dynamodbav:"_sub"`
	Key        []byte `dynamodbav:"_ckey"`
	State      string `dynamodbav:"_state"`
	CreatedAt  int64  `dynamodbav:"_cr_at"`
	DisabledAt int64  `dynamodbav:"_di_at,omitempty"`
	DeletedAt  int64  `dynamodbav:"_de_at,omitempty"`
}

type engine struct {
	svc   ClientAPI
	table string
}

var _ core.KeyUpdaterEngine = &engine{}

func NewKeyEngine(svc ClientAPI, table string) core.KeyUpdaterEngine {
	eng := &engine{
		svc:   svc,
		table: table,
		// KeyStoreConfig: &KeyStoreConfig{
		// 	HardDeleteAfter: time.Hour * 24 * 7,
		// },
	}

	// for _, opt := range opts {
	// 	if opt == nil {
	// 		continue
	// 	}

	// 	opt(store.KeyStoreConfig)
	// }

	return eng
}

func (e *engine) updateKeyItem(ctx context.Context, namespace, keyID string, expr expression.Expression) error {
	if _, err := e.svc.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		Key: map[string]types.AttributeValue{
			HashKey:  &types.AttributeValueMemberS{Value: namespace},
			RangeKey: &types.AttributeValueMemberS{Value: keyID},
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
			SubID:     idkey.ID(),
			Key:       []byte(idkey.Key()),
			CreatedAt: time.Now().UTC().Unix(),
			State:     core.StateActive,
		}

		mk, err := attributevalue.MarshalMap(kItem)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to marshal data", core.ErrPeristKeyFailed)
		}

		expr, err := expression.
			NewBuilder().
			WithCondition(
				expression.AttributeNotExists(
					expression.Name(HashKey),
				).And(
					expression.AttributeNotExists(
						expression.Name(RangeKey),
					),
				),
			).Build()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to build query", core.ErrPeristKeyFailed)
		}

		if _, err = e.svc.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:                 aws.String(e.table),
			Item:                      mk,
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		}); err != nil {
			if IsConditionCheckFailure(err) {
				exist[idkey.ID()] = struct{}{}
				continue
			}

			return nil, fmt.Errorf("%w: concerned keyID %s: %v", core.ErrPeristKeyFailed, idkey.ID(), err)
		}
	}

	return exist, nil
}

// UpdateKeys implements core.KeyUpdaterEngine
func (e *engine) UpdateKeys(ctx context.Context, namespace string, keys []core.IDKey) error {
	for _, idkey := range keys {
		expr, err := expression.
			NewBuilder().
			WithUpdate(
				expression.
					Set(expression.Name(attrKey), expression.Value(idkey.Key())),
			).
			WithCondition(
				expression.NotEqual(expression.Name(attrState), expression.Value(core.StateDeleted)),
			).Build()
		if err != nil {
			return err
		}
		if err := e.updateKeyItem(ctx, namespace, idkey.ID(), expr); err != nil {
			if IsConditionCheckFailure(err) {
				continue
			}
			return err
		}
	}

	return nil
}

// DeleteKey implements core.KeyUpdaterEngine
func (e *engine) DeleteKey(ctx context.Context, namespace string, keyID string) error {
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
		return err
	}
	if err := e.updateKeyItem(ctx, namespace, keyID, expr); err != nil {
		if IsConditionCheckFailure(err) {
			return nil
		}
		return err
	}

	return nil
}

// DisableKey implements core.KeyUpdaterEngine
func (e *engine) DisableKey(ctx context.Context, namespace string, keyID string) error {
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
		return err
	}
	if err := e.updateKeyItem(ctx, namespace, keyID, expr); err != nil {
		if IsConditionCheckFailure(err) {
			return fmt.Errorf("%w: for %s: key already hard deleted", core.ErrDisableKeyFailed, keyID)
		}
		return err
	}

	return nil
}

// RenableKey implements core.KeyUpdaterEngine
func (e *engine) RenableKey(ctx context.Context, namespace string, keyID string) error {
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
		return err
	}
	if err := e.updateKeyItem(ctx, namespace, keyID, expr); err != nil {
		if IsConditionCheckFailure(err) {
			return fmt.Errorf("%w: for %s: key already hard deleted", core.ErrRenableKeyFailed, keyID)
		}
		return err
	}

	return nil
}

// GetKeys implements core.KeyUpdaterEngine
func (e *engine) GetKeys(ctx context.Context, namespace string, keyIDs ...string) (keys core.KeyMap, err error) {
	count := len(keyIDs)
	if count == 0 {
		return keys, nil
	}

	keys = core.NewKeyMap()

	sort.Strings(keyIDs)

	ops := []expression.OperandBuilder{}
	for i := 0; i < count; i++ {
		ops = append(ops, expression.Value(keyIDs[i]))
	}

	b := expression.NewBuilder().
		WithKeyCondition(
			expression.Key(HashKey).Equal(expression.Value(namespace)).
				And(
					expression.Key(RangeKey).Between(expression.Value(keyIDs[0]), expression.Value(keyIDs[len(keyIDs)-1])),
				),
		).
		WithFilter(
			expression.And(
				expression.Name(attrState).Equal(expression.Value(core.StateActive)),
				expression.Name(attrSubject).In(ops[0], ops[1:count]...),
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

		err = attributevalue.UnmarshalListOfMaps(out.Items, &items)
		if err != nil {
			return nil, err
		}

		for _, item := range items {
			keys[item.SubID] = core.Key(item.Key)
		}
	}

	return keys, nil
}

// GetOrCreateKeys implements core.KeyUpdaterEngine
func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen core.KeyGen) (core.KeyMap, error) {
	if keyGen == nil {
		keyGen = aes.Key256GenFn
	}

	keys, err := e.GetKeys(ctx, namespace, keyIDs...)
	if err != nil {
		return nil, err
	}

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

	// TODO fix needed:
	// createkeys result might also contains new fresh keys (created just after the GetKeys read)
	disabledOrDeleted, err := e.createKeys(ctx, namespace, missedKeys)
	if err != nil {
		return nil, err
	}

	for _, missedKey := range missedKeys {
		if _, ok := disabledOrDeleted[missedKey.ID()]; ok {
			continue
		}
		keys[missedKey.ID()] = missedKey.Key()
	}

	return keys, nil
}

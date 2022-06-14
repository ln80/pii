package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	nsHashKeyVal = "#ns_"

	hashKey  = "_pk"
	rangeKey = "_sk"

	// lsi, a local secondary index, used to optimize the following read queries:
	// - get active keys given a set of keyIDs
	// - get disabled keys since/until a date
	lsi    = "_lsi"
	lsiKey = "_lsik"

	attrKeyID      = "_kid"
	attrKey        = "_key"
	attrNamespace  = "_nspace"
	attrDisabledAt = "_disabledAt"
	attrDeletedAt  = "_deletedAt"
	attrEnabledAt  = "_enabledAt"
	attrState      = "_state"
)

type Item struct {
	HashKey  string `dynamodbav:"_pk"`
	RangeKey string `dynamodbav:"_sk"`
	LSIKey   string `dynamodbav:"_lsik,omitempty"`
}

// KeyItem defines Dynamodb Key Engine table schema.
type KeyItem struct {
	Item
	Namespace  string `dynamodbav:"_nspace"`
	KeyID      string `dynamodbav:"_kid"`
	Key        []byte `dynamodbav:"_key"`
	State      string `dynamodbav:"_state"`
	CreatedAt  int64  `dynamodbav:"_createdAt"`
	DisabledAt int64  `dynamodbav:"_disabledAt,omitempty"`
	DeletedAt  int64  `dynamodbav:"_deletedAt,omitempty"`
	EnabledAt  int64  `dynamodbav:"_enabledAt,omitempty"`
}

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

// KeyEngine extends core.KeyEngine to add NamespaceRegistry utilities
type KeyEngine interface {
	core.KeyEngine
	NamespaceRegistry
}

type engine struct {
	svc   ClientAPI
	table string

	*core.KeyEngineConfig
}

var _ core.KeyEngine = &engine{}

// NewKeyEngine returns a core.KeyEngine implementation built on top of a Dynamodb table.
//
// It requires a non-empty value for Dynamodb client service and table name parameters. Otherwise, it will panic.
func NewKeyEngine(svc ClientAPI, table string, opts ...func(ec *core.KeyEngineConfig)) KeyEngine {
	if svc == nil {
		panic("invalid Dynamodb client service, nil value found")
	}
	if table == "" {
		panic("invalid dynamodb table name, empty value found")
	}

	eng := &engine{
		svc:             svc,
		table:           table,
		KeyEngineConfig: core.NewKeyEngineConfig(),
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(eng.KeyEngineConfig)
	}

	return eng
}

func (e *engine) addNamespace(ctx context.Context, namespace string) error {
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

	if _, err := e.svc.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(e.table),
		Item:                      m,
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}); err != nil {
		if isConditionCheckFailure(err) {
			return nil
		}
		return err
	}
	return nil
}

func (e *engine) ListNamespace(ctx context.Context) ([]string, error) {
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

func (e *engine) createKeys(ctx context.Context, nspace string, keys []core.IDKey) (disabledOrDeleted map[string]struct{}, freshNew map[string]string, err error) {
	disabledOrDeleted = map[string]struct{}{}
	freshNew = map[string]string{}

	handleExist := func(idkey core.IDKey) error {
		// fake update; active key always has a value
		// it allows to read the existing key value only if state is Active
		expr, _ := expression.
			NewBuilder().
			WithUpdate(
				expression.
					Set(
						expression.Name(attrKey),
						expression.IfNotExists(expression.Name(attrKey), expression.Value(nil)),
					),
			).
			WithCondition(
				expression.Equal(expression.Name(attrState), expression.Value(core.StateActive)),
			).Build()

		out, err := e.svc.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			Key: map[string]types.AttributeValue{
				hashKey:  &types.AttributeValueMemberS{Value: nspace},
				rangeKey: &types.AttributeValueMemberS{Value: idkey.ID()},
			},
			TableName:                 aws.String(e.table),
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
			UpdateExpression:          expr.Update(),
			ReturnValues:              types.ReturnValueUpdatedNew,
		})
		if err != nil {
			if isConditionCheckFailure(err) {
				disabledOrDeleted[idkey.ID()] = struct{}{}
				return nil
			}
		}

		r := map[string][]byte{}
		_ = attributevalue.UnmarshalMap(out.Attributes, &r)

		freshNew[idkey.ID()] = string(r[attrKey])

		return nil
	}

	for _, idkey := range keys {
		now := time.Now()
		kItem := KeyItem{
			Item: Item{
				HashKey:  nspace,
				RangeKey: idkey.ID(),
				LSIKey:   "enabled@" + idkey.ID(),
			},
			Namespace: nspace,
			KeyID:     idkey.ID(),
			Key:       []byte(idkey.Key()),
			CreatedAt: now.Unix(),
			EnabledAt: now.Unix(),
			State:     core.StateActive,
		}

		mk, err := attributevalue.MarshalMap(kItem)
		if err != nil {
			return nil, nil, err
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
			return nil, nil, err
		}

		if _, err = e.svc.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:                 aws.String(e.table),
			Item:                      mk,
			ConditionExpression:       expr.Condition(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		}); err != nil {
			if isConditionCheckFailure(err) {
				if err := handleExist(idkey); err != nil {
					return nil, nil, err
				}
				continue
			}
			return nil, nil, err
		}
	}

	return disabledOrDeleted, freshNew, nil
}

// DeleteKey implements core.KeyEngine
func (e *engine) DeleteKey(ctx context.Context, namespace string, keyID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %v", core.ErrDeleteKeyFailure, err)
		}
	}()

	now := time.Now()
	expr, err := expression.
		NewBuilder().
		WithUpdate(
			expression.
				Set(expression.Name(attrState), expression.Value(core.StateDeleted)).
				Set(expression.Name(attrDeletedAt), expression.Value(now.Unix())).
				// Free LSI resource, it's only useful for active and disabled keys
				Remove(expression.Name(lsiKey)),
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

	now := time.Now()
	expr, err := expression.
		NewBuilder().
		WithUpdate(
			expression.
				Set(expression.Name(attrState), expression.Value(core.StateDisabled)).
				Set(expression.Name(attrDisabledAt), expression.IfNotExists(
					expression.Name(attrDisabledAt), expression.Value(now.Unix()),
				)).
				// Replace the LSI value by pattern: state@{timestamp}
				Set(expression.Name(lsiKey), expression.Value("disabled@"+strconv.FormatInt(now.Unix(), 10))).
				Remove(expression.Name(attrEnabledAt)),
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
				Set(expression.Name(attrState), expression.Value(core.StateActive)).
				Set(expression.Name(attrEnabledAt), expression.IfNotExists(
					expression.Name(attrEnabledAt), expression.Value(time.Now().Unix()),
				)).
				// replace lsi value with pattern state@{keyID}
				Set(expression.Name(lsiKey), expression.Value("enabled@"+keyID)).
				Remove(expression.Name(attrDisabledAt)),
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
					expression.Key(lsiKey).Between(
						expression.Value("enabled@"+keyIDs[0]),
						expression.Value("enabled@"+keyIDs[len(keyIDs)-1]),
					),
				),
		).
		WithFilter(
			expression.Name(attrKeyID).In(ops[0], ops[1:count]...),
		).
		WithProjection(
			expression.NamesList(expression.Name(attrKeyID), expression.Name(attrKey)),
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

	// add namespace to an internal list when keys are not found,
	// which is likely the case of namespace first query.
	// Otherwise, the method is idempotent and shouldn't cost a penny
	// in case of redundant calls
	if len(keys) == 0 {
		if err := e.addNamespace(ctx, namespace); err != nil {
			return nil, err
		}
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

	disabledOrDeleted, freshNew, err := e.createKeys(ctx, namespace, missedKeys)
	if err != nil {
		return
	}

	for _, missedKey := range missedKeys {
		if _, ok := disabledOrDeleted[missedKey.ID()]; ok {
			continue
		}
		if key, ok := freshNew[missedKey.ID()]; ok {
			keys[missedKey.ID()] = core.Key(key)
			continue
		}

		keys[missedKey.ID()] = missedKey.Key()
	}

	return
}

// DeleteUnusedKeys implements core.KeyEngine
func (e *engine) DeleteUnusedKeys(ctx context.Context, namespace string) (err error) {
	expr, err := expression.NewBuilder().
		WithKeyCondition(
			expression.Key(hashKey).Equal(expression.Value(namespace)).And(
				expression.Key(lsiKey).Between(
					expression.Value("disabled@"+strconv.FormatInt(time.Now().Add(-e.GracePeriod).Unix(), 10)),
					expression.Value("disabled@"+strconv.FormatInt(time.Now().Unix(), 10)),
				),
			),
		).
		WithProjection(
			expression.NamesList(expression.Name(attrKeyID)),
		).Build()
	if err != nil {
		err = fmt.Errorf("%w: %v", core.ErrDeleteKeyFailure, err)
		return
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
	})

	items := []map[string]string{}
	for p.HasMorePages() {
		var out *dynamodb.QueryOutput
		out, err = p.NextPage(ctx)
		if err != nil {
			return
		}
		pageItems := []map[string]string{}
		if err = attributevalue.UnmarshalListOfMaps(out.Items, &pageItems); err != nil {
			return
		}
		items = append(items, pageItems...)
	}

	for i, item := range items {
		keyID := item[attrKeyID]
		if err = e.DeleteKey(ctx, namespace, keyID); err != nil {
			err = fmt.Errorf("%w: keyID '%s#%s' at #%d", err, namespace, keyID, i)
			return
		}
	}

	return
}

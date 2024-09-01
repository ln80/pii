package dynamodb

import (
	"context"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type ContextKey string

const (
	CapacityContextKey ContextKey = "CapacityContextKey"
)

type consumedCapacity struct {
	Total      float64
	Read       float64
	Write      float64
	GSI        map[string]float64
	GSIRead    map[string]float64
	GSIWrite   map[string]float64
	LSI        map[string]float64
	LSIRead    map[string]float64
	LSIWrite   map[string]float64
	Table      float64
	TableRead  float64
	TableWrite float64
	TableName  string
}

func capacityContext(ctx context.Context) (context.Context, *consumedCapacity) {
	cc := capacityFromContext(ctx)
	if cc != nil {
		return ctx, cc
	}
	cc = &consumedCapacity{}
	return context.WithValue(ctx, CapacityContextKey, cc), cc
}

func capacityFromContext(ctx context.Context) *consumedCapacity {
	cc, ok := ctx.Value(CapacityContextKey).(*consumedCapacity)
	if !ok {
		return nil
	}
	return cc
}
func (cc *consumedCapacity) IsZero() bool {
	return cc == nil || reflect.DeepEqual(*cc, consumedCapacity{})
}

func addConsumedCapacity(cc *consumedCapacity, raw *types.ConsumedCapacity) {
	if cc == nil || raw == nil {
		return
	}
	if raw.CapacityUnits != nil {
		cc.Total += *raw.CapacityUnits
	}
	if raw.ReadCapacityUnits != nil {
		cc.Read += *raw.ReadCapacityUnits
	}
	if raw.WriteCapacityUnits != nil {
		cc.Write += *raw.WriteCapacityUnits
	}
	if len(raw.GlobalSecondaryIndexes) > 0 {
		if cc.GSI == nil {
			cc.GSI = make(map[string]float64, len(raw.GlobalSecondaryIndexes))
		}
		for name, consumed := range raw.GlobalSecondaryIndexes {
			cc.GSI[name] = cc.GSI[name] + *consumed.CapacityUnits
			if consumed.ReadCapacityUnits != nil {
				if cc.GSIRead == nil {
					cc.GSIRead = make(map[string]float64, len(raw.GlobalSecondaryIndexes))
				}
				cc.GSIRead[name] = cc.GSIRead[name] + *consumed.ReadCapacityUnits
			}
			if consumed.WriteCapacityUnits != nil {
				if cc.GSIWrite == nil {
					cc.GSIWrite = make(map[string]float64, len(raw.GlobalSecondaryIndexes))
				}
				cc.GSIWrite[name] = cc.GSIWrite[name] + *consumed.WriteCapacityUnits
			}
		}
	}
	if len(raw.LocalSecondaryIndexes) > 0 {
		if cc.LSI == nil {
			cc.LSI = make(map[string]float64, len(raw.LocalSecondaryIndexes))
		}
		for name, consumed := range raw.LocalSecondaryIndexes {
			cc.LSI[name] = cc.LSI[name] + *consumed.CapacityUnits
			if consumed.ReadCapacityUnits != nil {
				if cc.LSIRead == nil {
					cc.LSIRead = make(map[string]float64, len(raw.LocalSecondaryIndexes))
				}
				cc.LSIRead[name] = cc.LSIRead[name] + *consumed.ReadCapacityUnits
			}
			if consumed.WriteCapacityUnits != nil {
				if cc.LSIWrite == nil {
					cc.LSIWrite = make(map[string]float64, len(raw.LocalSecondaryIndexes))
				}
				cc.LSIWrite[name] = cc.LSIWrite[name] + *consumed.WriteCapacityUnits
			}
		}
	}
	if raw.Table != nil {
		cc.Table += *raw.Table.CapacityUnits
		if raw.Table.ReadCapacityUnits != nil {
			cc.TableRead += *raw.Table.ReadCapacityUnits
		}
		if raw.Table.WriteCapacityUnits != nil {
			cc.TableWrite += *raw.Table.WriteCapacityUnits
		}
	}
	if raw.TableName != nil {
		cc.TableName = *raw.TableName
	}
}

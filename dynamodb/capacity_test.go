package dynamodb

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/mitchellh/copystructure"
)

func TestConsumedCapacity(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		cc := &consumedCapacity{}
		if !cc.IsZero() {
			t.Fatal("expect true, got false")
		}
		cc = &consumedCapacity{GSI: map[string]float64{"GSI1": 20.4}}
		if cc.IsZero() {
			t.Fatal("expect true, got false")
		}
	})

	t.Run("add", func(t *testing.T) {
		cc1 := consumedCapacity{
			Total:      10,
			GSI:        map[string]float64{"GSI1": 10},
			GSIRead:    map[string]float64{},
			GSIWrite:   map[string]float64{},
			LSI:        map[string]float64{"LSI1": 10},
			LSIRead:    map[string]float64{},
			LSIWrite:   map[string]float64{},
			Table:      0,
			TableRead:  0,
			TableWrite: 0,
		}
		copy, _ := copystructure.Copy(cc1)
		old := copy.(consumedCapacity)

		raw := &types.ConsumedCapacity{
			CapacityUnits: aws.Float64(5),
			GlobalSecondaryIndexes: map[string]types.Capacity{"GSI1": {
				CapacityUnits: aws.Float64(5),
			}},
			LocalSecondaryIndexes: map[string]types.Capacity{
				"LSI1": {
					CapacityUnits: aws.Float64(5),
				},
				"LSI2": {
					CapacityUnits: aws.Float64(5),
				},
			},
		}
		addConsumedCapacity(&cc1, raw)

		if want, got := old.Total+*raw.CapacityUnits, cc1.Total; want != got {
			t.Fatalf("expect %v,%v be equals", want, got)
		}
		if want, got := old.GSI["GSI1"]+*raw.GlobalSecondaryIndexes["GSI1"].CapacityUnits, cc1.GSI["GSI1"]; want != got {
			t.Fatalf("expect %v,%v be equals", want, got)
		}

		if want, got := old.LSI["LSI1"]+*raw.LocalSecondaryIndexes["LSI1"].CapacityUnits, cc1.LSI["LSI1"]; want != got {
			t.Fatalf("expect %v,%v be equals", want, got)
		}
		if want, got := old.LSI["LSI2"]+*raw.LocalSecondaryIndexes["LSI2"].CapacityUnits, cc1.LSI["LSI2"]; want != got {
			t.Fatalf("expect %v,%v be equals", want, got)
		}
	})
}

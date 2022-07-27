package dynamodb

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/pii/core"
	db_testutil "github.com/ln80/pii/dynamodb/testutil"
	"github.com/ln80/pii/testutil"
)

// Interface guard:
// Make sure Engine Mock implements dynamodb extended key engine
var _ KeyEngine = &testutil.EngineMock{}

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()

	db_testutil.WithDynamoDBTable(t, func(dbsvc interface{}, table string) {
		_, ok := dbsvc.(ClientAPI)
		if !ok {
			t.Fatalf("expect %v implements interface", dbsvc)
		}

		t.Run("invalid constructor params", func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expect NewKeyEngine to panic")
				}
			}()
			_ = NewKeyEngine(nil, "")

		})

		t.Run("manage key lifecycle", func(t *testing.T) {
			gracePeriod := 3 * time.Millisecond
			nspace := "tnt-54R"

			eng := NewKeyEngine(dbsvc.(ClientAPI), table, func(ec *KeyEngineConfig) {
				ec.GracePeriod = gracePeriod
			}, nil)

			testutil.KeyEngineTestSuite(t, ctx, eng, func(keto *testutil.KeyEngineTestOption) {
				keto.GracePeriod = gracePeriod
				keto.Namespace = nspace
			})

			// extended behavior:
			// assert dynamodb engine can returns list of registred namespace
			// during keys management
			ns, err := eng.ListNamespace(ctx)
			if err != nil {
				t.Fatalf("expect err be nil, got: %v", err)
			}
			if want, got := 1, len(ns); want != got {
				t.Fatalf("expect %v and %v are equals", want, got)
			}
			if want, got := nspace, ns[0]; want != got {
				t.Fatalf("expect %v and %v are equals", want, got)
			}
		})

	})
}

func TestKeyEngine_createKeys(t *testing.T) {
	ctx := context.Background()

	db_testutil.WithDynamoDBTable(t, func(dbsvc interface{}, table string) {
		eng := NewKeyEngine(dbsvc.(ClientAPI), table).(*engine)

		nspace := "tenant-p1ds7"

		keys := []core.IDKey{
			core.NewIDKey("1", testutil.RandomID()),
			core.NewIDKey("2", testutil.RandomID()),
			core.NewIDKey("3", testutil.RandomID()),
		}

		disabledOrDeleted, freshNew, err := eng.createKeys(ctx, nspace, keys)
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		if want, got := 0, len(freshNew); want != got {
			t.Fatalf("expect %v and %v are equals", want, got)
		}
		if want, got := 0, len(disabledOrDeleted); want != got {
			t.Fatalf("expect %v and %v are equals", want, got)
		}

		// alter keys value and keep same IDs
		altered := []core.IDKey{
			core.NewIDKey("1", testutil.RandomID()),
			core.NewIDKey("2", testutil.RandomID()),
			core.NewIDKey("3", testutil.RandomID()),
		}

		// assert It fails if namespace is empty
		if _, _, err = eng.createKeys(ctx, "", altered); err == nil {
			t.Fatalf("expect err be not nil, got: %v", err)
		}

		// second createkeys call will not alter keys value.
		// It will returns original values instead
		disabledOrDeleted, freshNew, err = eng.createKeys(ctx, nspace, altered)
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}

		keyMap, err := eng.GetKeys(ctx, nspace, []string{"1", "2", "3"})
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		for _, k := range keys {
			if want, got := k.Key(), keyMap[k.ID()]; want != got {
				t.Fatalf("expect %v and %v are equals", want, got)
			}
		}

		if want, got := 3, len(freshNew); want != got {
			t.Fatalf("expect %v and %v are equals", want, got)
		}
		if want, got := 0, len(disabledOrDeleted); want != got {
			t.Fatalf("expect %v and %v are equals", want, got)
		}
		for _, k := range keys {
			if want, got := string(k.Key()), freshNew[k.ID()]; want != got {
				t.Fatalf("expect %v and %v are equals", want, got)
			}
		}

		// delete a key
		err = eng.DeleteKey(ctx, nspace, "1")
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}

		// assert createKeys returns the ID of the deleted key and do not create it again.
		disabledOrDeleted, freshNew, err = eng.createKeys(ctx, nspace, altered)
		if err != nil {
			t.Fatalf("expect err be nil, got: %v", err)
		}
		if want, got := 1, len(disabledOrDeleted); want != got {
			t.Fatalf("expect %v and %v are equals", want, got)
		}
		if want, got := 2, len(freshNew); want != got {
			t.Fatalf("expect %v and %v are equals", want, got)
		}
	})
}

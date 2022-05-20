package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/pii/core"
	"github.com/ln80/pii/testutil"
)

func TestKeyEngine(t *testing.T) {
	ctx := context.Background()
	nspace := "namespace"

	eng := NewKeyEngine()

	keys, err := eng.GetKeys(ctx, nspace)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expect keys map be empty, got: %v", keys)
	}

	subIDs := []string{
		"arl", "bac", "karl",
	}

	// KeysEqual := func(x, y []string) bool {
	// 	sort.Strings(x)
	// 	sort.Strings(y)
	// 	return reflect.DeepEqual(x, y)
	// }

	// Test get or create operation
	keys, err = eng.GetOrCreateKeys(ctx, nspace, subIDs, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}

	if want, got := subIDs, keys.IDs(); !testutil.KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test get a sub set of keys
	partial := subIDs[1:]
	keys, err = eng.GetKeys(ctx, nspace, partial...)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := partial, keys.IDs(); !testutil.KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Memory engine does not support disable key operation
	if want, err := core.ErrUnsupportedKeyOperation, eng.DisableKey(ctx, nspace, subIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	// Clear silently ignore clear if engine is acting as key store
	if want, err := error(nil), eng.(core.KeyCacheEngine).Clear(ctx, nspace, false); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, err = eng.GetKeys(ctx, nspace, subIDs...)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := subIDs, keys.IDs(); !testutil.KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test delete a key from store
	if want, err := error(nil), eng.DeleteKey(ctx, nspace, subIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, err = eng.GetKeys(ctx, nspace, subIDs[0])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := []string{}, keys.IDs(); !testutil.KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}
}

func TestCacheWrapper(t *testing.T) {

}

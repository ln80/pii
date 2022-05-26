package testutil

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/pii/core"
)

func KeyEngineTestSuite(t *testing.T, ctx context.Context, eng core.KeyEngine) {
	nspace := "tenant-kal34p"

	// t.Run("", func(t *testing.T) {})

	keys, err := eng.GetKeys(ctx, nspace)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expect keys map be empty, got: %v", keys)
	}

	keyIDs := []string{
		RandomID(),
		RandomID(),
		RandomID(),
	}

	// Test get or create operation
	keys, err = eng.GetOrCreateKeys(ctx, nspace, keyIDs, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs, keys.IDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test get a sub set of keys
	partial := keyIDs[1:]
	keys, err = eng.GetKeys(ctx, nspace, partial...)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := partial, keys.IDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test disable a key from store
	if want, err := error(nil), eng.DisableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, err = eng.GetKeys(ctx, nspace, keyIDs[0])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := []string{}, keys.IDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test renable a key from store
	if want, err := error(nil), eng.RenableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, err = eng.GetKeys(ctx, nspace, keyIDs[0])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs[:1], keys.IDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test delete a key from store
	if want, err := error(nil), eng.DeleteKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, err = eng.GetKeys(ctx, nspace, keyIDs[0])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := []string{}, keys.IDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

}

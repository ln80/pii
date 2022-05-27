package testutil

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/pii/core"
)

func KeyEngineTestSuite(t *testing.T, ctx context.Context, eng core.KeyEngine) {
	nspace := "tenant-kal34p"

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

	// Test GetOrCreate
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

	// // Test rotate keys if supported by given engine
	// if eng, ok := eng.(core.KeyRotatorEngine); ok {
	// 	// choose a key for rotation
	// 	keyToRotate := keyIDs[1]

	// 	// get current key values: plain & cypher
	// 	enckeys, err := eng.Origin().GetKeys(ctx, nspace, keyToRotate)
	// 	if err != nil {
	// 		t.Fatalf("expect err be nil, got: %v", err)
	// 	}
	// 	keys, err := eng.GetKeys(ctx, nspace, keyToRotate)
	// 	if err != nil {
	// 		t.Fatalf("expect err be nil, got: %v", err)
	// 	}
	// 	currEncKey, currKey := enckeys[keyToRotate], keys[keyToRotate]

	// 	// rotate key
	// 	if want, err := error(nil), eng.RotateKeys(ctx, nspace, keyToRotate); !errors.Is(err, want) {
	// 		t.Fatalf("expect err be %v, got: %v", want, err)
	// 	}

	// 	// get the new key values: plain & cypher
	// 	enckeys, err = eng.Origin().GetKeys(ctx, nspace, keyToRotate)
	// 	if err != nil {
	// 		t.Fatalf("expect err be nil, got: %v", err)
	// 	}
	// 	keys, err = eng.GetKeys(ctx, nspace, keyToRotate)
	// 	if err != nil {
	// 		t.Fatalf("expect err be nil, got: %v", err)
	// 	}
	// 	newEncKey, newKey := enckeys[keyToRotate], keys[keyToRotate]

	// 	// make sure that plain values are the same but cyphers are not
	// 	if currEncKey == newEncKey {
	// 		t.Fatalf("expect %v, %v not be equals", currKey, newKey)
	// 	}
	// 	if currKey != newKey {
	// 		t.Fatalf("expect %v, %v not be equals", currKey, newKey)
	// 	}
	// }
}

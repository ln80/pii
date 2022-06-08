package testutil

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/pii/core"
)

func KeyEngineTestSuite(t *testing.T, ctx context.Context, eng core.KeyEngine) {
	nspace := "tenant-kal34p"

	keys, err := eng.GetKeys(ctx, nspace, nil)
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

	nilErr := error(nil)
	empty := []string{}

	// Test GetOrCreate

	// First, a create a new key and return it
	keys, err = eng.GetOrCreateKeys(ctx, nspace, keyIDs[:1], nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs[:1], keys.KeyIDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Second, make sure to return an existing key while creating others.
	keys, err = eng.GetOrCreateKeys(ctx, nspace, keyIDs, nil)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs, keys.KeyIDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test get a sub set of keys
	partial := keyIDs[1:]
	keys, err = eng.GetKeys(ctx, nspace, partial)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := partial, keys.KeyIDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test disable key
	if want, err := nilErr, eng.DisableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// assert disable key idempotency
	if want, err := nilErr, eng.DisableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	keys, err = eng.GetKeys(ctx, nspace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := empty, keys.KeyIDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test renable key
	if want, err := nilErr, eng.RenableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// assert renable key idempotency
	if want, err := nilErr, eng.RenableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	keys, err = eng.GetKeys(ctx, nspace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := keyIDs[:1], keys.KeyIDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test delete key
	if want, err := nilErr, eng.DeleteKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	// assert delete key idempotency
	if want, err := nilErr, eng.DeleteKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
	keys, err = eng.GetKeys(ctx, nspace, keyIDs[0:1])
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := empty, keys.KeyIDs(); !KeysEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	// Test renable key after a hard delete
	if want, err := core.ErrKeyNotFound, eng.RenableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}

	// Test disable key after a hard delete
	if want, err := core.ErrKeyNotFound, eng.DisableKey(ctx, nspace, keyIDs[0]); !errors.Is(err, want) {
		t.Fatalf("expect err be %v, got: %v", want, err)
	}
}

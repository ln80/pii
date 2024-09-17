package testutil

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/ln80/pii/core"
)

type TokenEngineTestOption struct {
	Namespace string
}

func TokenEngineTestSuite(t *testing.T, ctx context.Context, eng core.TokenEngine, opts ...func(*TokenEngineTestOption)) {
	topt := &TokenEngineTestOption{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(topt)
	}
	nspace := "tenant-dcm30oI"
	if topt.Namespace != "" {
		nspace = topt.Namespace
	}

	values := []core.TokenData{
		core.TokenData(RandomID()),
		core.TokenData(RandomID()),
		core.TokenData(RandomID()),
	}

	result, err := eng.Tokenize(ctx, nspace, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if got, want := len(result), 3; got != want {
		t.Fatalf("expect result map length be %d, got %d", want, got)
	}

	// assert idempotency
	result_2, err := eng.Tokenize(ctx, nspace, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := result, result_2; !reflect.DeepEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	result_3, err := eng.Detokenize(ctx, nspace, result.Tokens())
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	values_3 := result_3.Values()

	// assert detokenized values are the same as original
	slices.Sort(values)
	slices.Sort(values_3)
	if want, got := values, values_3; !reflect.DeepEqual(want, got) {
		t.Fatalf("expect %v, %v be equals", want, got)
	}

	var tokenToDelete core.TokenRecord
	for _, value := range result {
		tokenToDelete = value
		break
	}
	if err := eng.DeleteToken(ctx, nspace, tokenToDelete.Token); err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}

	// assert tokenize a deleted token returns a new fresh one.
	result_4, err := eng.Tokenize(ctx, nspace, values)
	if err != nil {
		t.Fatalf("expect err be nil, got: %v", err)
	}
	if want, got := result, result_4; reflect.DeepEqual(want, got) {
		t.Fatalf("expect %v, %v not be equals", want, got)
	}
}

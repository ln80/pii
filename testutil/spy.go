package testutil

import (
	"testing"
	"time"
)

type FuncCalls map[string][]time.Time

func NewFuncCalls() FuncCalls {
	return make(FuncCalls)
}

func (calls FuncCalls) AssertCount(t *testing.T, fn string, min int) {
	fnCalls, ok := calls[fn]
	if !ok {
		t.Fatalf("%s calls not found", fn)
	}
	if got := len(fnCalls); got < min {
		t.Fatalf("expect %s called at least %d, got: %d", fn, min, got)
	}
}

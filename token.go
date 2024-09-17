package pii

import "github.com/ln80/pii/core"

// TokenDataSlice returns a the given values as a `core.TokenData` slice.
//
// It's mainly used as helper function to simplify the interaction with the Tokenizer service.
func TokenDataSlice(values ...string) []core.TokenData {
	tokenValues := make([]core.TokenData, len(values))
	for i, v := range values {
		tokenValues[i] = core.TokenData(v)
	}
	return tokenValues
}

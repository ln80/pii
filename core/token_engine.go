package core

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var (
	ErrTokenNotFound        = errors.New("token not found")
	ErrTokenGenFuncNotFound = errors.New("token gen function is not found")
	ErrDetokenizeFailure    = errors.New("failed to detokenize token(s)")
	ErrTokenizeFailure      = errors.New("failed to tokenize value(s)")
	ErrDeleteTokenFailure   = errors.New("failed to delete token")
)

// TokenData presents a sensitive data that should be tokenized.
type TokenData string

// String does redacts the token data. This enhance security when dealing with loggings libraries
func (t TokenData) String() string {
	return "**TOKEN DATA**"
}

// Reveal returns the string value of token data as the `String` method redacts
// data by default.
func (t TokenData) Reveal() string {
	return string(t)
}

// ValueTokenMap maps token data to tokens
type ValueTokenMap map[TokenData]TokenRecord

// Get the token of the given value
func (m ValueTokenMap) Get(v string) TokenRecord {
	return m[TokenData(v)]
}

func (m ValueTokenMap) Tokens() []string {
	tokens := []string{}
	for _, r := range m {
		tokens = append(tokens, r.Token)
	}
	return tokens
}

// ValueTokenMap maps token to token data
type TokenValueMap map[string]TokenRecord

// Get the value of the given token
func (m TokenValueMap) Get(t string) TokenRecord {
	return m[t]
}

func (m TokenValueMap) Values() []TokenData {
	values := []TokenData{}
	for _, r := range m {
		values = append(values, r.Value)
	}
	return values
}

// TokenRecord contains both the token and token data values
type TokenRecord struct {
	Token string
	Value TokenData
}

type TokenizeConfig struct {
	TokenGenFunc func(ctx context.Context, namespace string, data TokenData) (string, error)
}

// DefaultTokenGen generates and uses an `uuid` as token for the given data.
func DefaultTokenGen(ctx context.Context, namespace string, data TokenData) (string, error) {
	u := uuid.New()
	return u.String(), nil
}

type TokenEngine interface {
	Tokenize(ctx context.Context, namespace string, values []TokenData, opts ...func(*TokenizeConfig)) (valueTokens ValueTokenMap, err error)
	Detokenize(ctx context.Context, namespace string, tokens []string) (tokenValues TokenValueMap, err error)
	DeleteToken(ctx context.Context, namespace string, token string) error
}

// TokenEngineCache is a TokenEngine wrapper used for cache purposes.
type TokenEngineCache interface {
	TokenEngine

	ClearCache(ctx context.Context, namespace string, force bool) error
}

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

type TokenDataRedactFunc func(data TokenData) string

var (
	DefaultTokenDataRedactFunc TokenDataRedactFunc = func(data TokenData) string {
		return "TOKEN-DATA-*****"
	}
)

// TokenData presents a sensitive data that should tokenized.
type TokenData string

func (td TokenData) String() string {
	if DefaultTokenDataRedactFunc != nil {
		return DefaultTokenDataRedactFunc(td)
	}
	return string(td)
}

// ValueTokenMap maps token data to tokens
type ValueTokenMap map[TokenData]TokenRecord

// ValueTokenMap maps token to token data
type TokenValueMap map[string]TokenRecord

// TokenRecord contains both the token and token data values
type TokenRecord struct {
	Token string
	Value TokenData
}

type TokenizeConfig struct {
	TokenGenFunc func(ctx context.Context, namespace string, data TokenData) (string, error)
}

func DefaultTokenGen(ctx context.Context, namespace string, data TokenData) (string, error) {
	u := uuid.New()
	return u.String(), nil
}

type TokenEngine interface {
	Tokenize(ctx context.Context, namespace string, values []TokenData, opts ...func(*TokenizeConfig)) (valueTokens ValueTokenMap, err error)
	Detokenize(ctx context.Context, namespace string, tokens []string) (tokenValues TokenValueMap, err error)

	DeleteToken(ctx context.Context, namespace string, token string) error
}

// TokenEngineCache is a TokenEngine wrapper used for cache purpose.
type TokenEngineCache interface {
	TokenEngine

	ClearCache(ctx context.Context, namespace string, force bool) error
}

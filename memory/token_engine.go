package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ln80/pii/core"
)

type TokenEngine struct {
	origin core.TokenEngine

	cache map[string]*tokenCache
	mu    sync.RWMutex
	ttl   time.Duration
}

var _ core.TokenEngine = &TokenEngine{}
var _ core.TokenEngineCache = &TokenEngine{}

func NewTokenEngine() *TokenEngine {
	return &TokenEngine{
		cache: make(map[string]*tokenCache),
	}
}

func NewTokenCacheWrapper(origin core.TokenEngine, ttl time.Duration) *TokenEngine {
	if origin == nil {
		panic("invalid origin Token Engine, nil value found")
	}
	if ttl == 0 {
		ttl = cacheTTLDefault
	}

	return &TokenEngine{
		origin: origin,
		cache:  map[string]*tokenCache{},
		ttl:    ttl,
	}
}

// Detokenize implements core.TokenEngine.
func (t *TokenEngine) Detokenize(ctx context.Context, namespace string, tokens []string) (core.TokenValueMap, error) {
	cache := t.cacheOf(namespace)

	foundTokens := make(core.TokenValueMap)
	missedTokens := []string{}
	for _, token := range tokens {
		if v, ok := cache.value(token); ok {
			foundTokens[token] = core.TokenRecord{Token: token, Value: v}
		} else {
			missedTokens = append(missedTokens, token)
		}
	}

	if t.origin == nil {
		return foundTokens, nil
	}

	tokenValues, err := t.origin.Detokenize(ctx, namespace, missedTokens)
	if err != nil {
		return nil, err
	}
	for _, tokenValue := range tokenValues {
		cache.add(tokenValue)
		foundTokens[tokenValue.Token] = tokenValue
	}
	return foundTokens, nil
}

// Tokenize implements core.TokenEngine.
func (t *TokenEngine) Tokenize(ctx context.Context, namespace string, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (records core.ValueTokenMap, err error) {
	cache := t.cacheOf(namespace)

	foundValues := make(core.ValueTokenMap)
	missedValues := []core.TokenData{}
	for _, value := range values {
		if token, ok := cache.token(value); ok {
			foundValues[value] = core.TokenRecord{Token: token, Value: value}
		} else {
			missedValues = append(missedValues, value)
		}
	}

	if t.origin == nil {
		cfg := core.TokenizeConfig{
			TokenGenFunc: core.DefaultTokenGen,
		}
		for _, opt := range opts {
			if opt == nil {
				continue
			}
			opt(&cfg)
		}
		if cfg.TokenGenFunc == nil {
			return nil, core.ErrTokenGenFuncNotFound
		}

		for _, value := range missedValues {
			newToken, err := cfg.TokenGenFunc(ctx, namespace, value)
			if err != nil {
				return nil, err
			}
			record := core.TokenRecord{
				Token: newToken,
				Value: value,
			}
			cache.add(record)
			foundValues[value] = record
		}
		return foundValues, nil
	}

	valueTokens, err := t.origin.Tokenize(ctx, namespace, missedValues)
	if err != nil {
		return nil, err
	}
	for _, tokenValue := range valueTokens {
		cache.add(tokenValue)
		foundValues[tokenValue.Value] = tokenValue
	}
	return foundValues, nil
}

func (t *TokenEngine) DeleteToken(ctx context.Context, namespace string, token string) error {
	cache := t.cacheOf(namespace)
	if t.origin != nil {
		if err := t.origin.DeleteToken(ctx, namespace, token); err != nil {
			return err
		}
	}
	return cache.delete(token)
}

func (t *TokenEngine) ClearCache(ctx context.Context, namespace string, force bool) error {
	cache := t.cacheOf(namespace)
	return cache.clear(t.ttl, force)
}

func (e *TokenEngine) cacheOf(namespace string) *tokenCache {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.cache[namespace]; !ok {
		e.cache[namespace] = newTokenCache(namespace)
	}
	return e.cache[namespace]
}

type tokenCacheEntry struct {
	core.TokenRecord
	At int64
}

type tokenCache struct {
	namespace    string
	tokenToValue map[string]tokenCacheEntry
	valueToToken map[core.TokenData]tokenCacheEntry
	mutex        sync.RWMutex
}

func newTokenCache(namespace string) *tokenCache {
	return &tokenCache{
		namespace:    namespace,
		tokenToValue: make(map[string]tokenCacheEntry),
		valueToToken: make(map[core.TokenData]tokenCacheEntry),
	}
}

func (tc *tokenCache) value(token string) (core.TokenData, bool) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	entry, ok := tc.tokenToValue[token]
	return entry.Value, ok
}

func (tc *tokenCache) token(value core.TokenData) (string, bool) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	entry, ok := tc.valueToToken[value]
	return entry.Token, ok
}

func (tc *tokenCache) add(record core.TokenRecord) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	entry := tokenCacheEntry{
		TokenRecord: record,
		At:          time.Now().Unix(),
	}
	tc.tokenToValue[record.Token] = entry
	tc.valueToToken[record.Value] = entry
}

func (tc *tokenCache) clear(ttl time.Duration, force bool) error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	for token, entry := range tc.tokenToValue {
		if expired := entry.At+int64(ttl.Seconds()) < time.Now().Unix(); expired || force {
			delete(tc.tokenToValue, token)
			delete(tc.valueToToken, entry.Value)
		}
	}
	return nil
}

func (tc *tokenCache) delete(token string) error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	entry, exists := tc.tokenToValue[token]
	if !exists {
		return nil
	}

	// Delete from both maps
	delete(tc.tokenToValue, token)
	delete(tc.valueToToken, entry.Value)
	return nil
}

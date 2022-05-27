package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ln80/pii/aes"
	"github.com/ln80/pii/core"
)

const (
	cacheTTLDefault = 20 * time.Second
)

type keyCache struct {
	ID    string
	Key   core.Key
	At    int64
	State core.KeyState
}

func newKeyCache(id string, key core.Key) keyCache {
	return keyCache{
		ID:    id,
		Key:   key,
		At:    time.Now().Unix(),
		State: core.StateActive,
	}
}

type engine struct {
	origin core.KeyEngine

	cache map[string]map[string]keyCache

	mu sync.RWMutex

	ttl time.Duration
}

var _ core.KeyEngine = &engine{}
var _ core.KeyEngineCache = &engine{}

func NewKeyEngine() core.KeyEngine {
	return &engine{
		cache: make(map[string]map[string]keyCache),
	}
}

func NewCacheWrapper(origin core.KeyEngine, ttl time.Duration) core.KeyEngine {
	if origin == nil {
		panic("invalid origin Key Engine, nil value found")
	}
	if ttl == 0 {
		ttl = cacheTTLDefault
	}

	return &engine{
		cache:  make(map[string]map[string]keyCache),
		origin: origin,
		ttl:    ttl,
	}
}

func (e *engine) cacheOf(namespace string) map[string]keyCache {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.cache[namespace]; !ok {
		e.cache[namespace] = make(map[string]keyCache)
	}

	return e.cache[namespace]
}

func (e *engine) GetKeys(ctx context.Context, namespace string, keyIDs ...string) (core.KeyMap, error) {
	cache := e.cacheOf(namespace)

	foundKeys := core.NewKeyMap()
	missedKeys := []string{}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, keyID := range keyIDs {
		if key, ok := cache[keyID]; ok {
			if key.State != core.StateActive {
				continue
			}

			foundKeys[keyID] = key.Key
		} else {
			if e.origin != nil {
				missedKeys = append(missedKeys, keyID)
			}
		}
	}

	if e.origin != nil {
		keys, err := e.origin.GetKeys(ctx, namespace, missedKeys...)
		if err != nil {
			return nil, err
		}
		for keyID, k := range keys {
			foundKeys[keyID] = k
			cache[keyID] = newKeyCache(keyID, k)
		}
	}

	return foundKeys, nil
}

func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen core.KeyGen) (core.KeyMap, error) {
	if keyGen == nil {
		keyGen = aes.Key256GenFn
	}

	cache := e.cacheOf(namespace)

	if e.origin != nil {
		return func() (core.KeyMap, error) {
			e.mu.Lock()
			defer e.mu.Unlock()

			keys, err := e.origin.GetOrCreateKeys(ctx, namespace, keyIDs, keyGen)
			if err != nil {
				return nil, err
			}
			for keyID, k := range keys {
				cache[keyID] = newKeyCache(keyID, k)
			}
			return keys, nil
		}()
	}

	keys, err := e.GetKeys(ctx, namespace, keyIDs...)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, keyID := range keyIDs {
		if _, ok := keys[keyID]; !ok {
			// only add new entry if key is a fresh new one.
			// it may be disabled/deleted and still have record
			if _, ok := cache[keyID]; ok {
				continue
			}

			newKey, err := keyGen(ctx, namespace, keyID)
			if err != nil {
				return nil, err
			}
			keys[keyID] = core.Key(newKey)

			cache[keyID] = newKeyCache(keyID, core.Key(newKey))
		}
	}

	return keys, nil
}

func (e *engine) DisableKey(ctx context.Context, namespace, keyID string) error {
	if e.origin != nil {
		if err := e.origin.DisableKey(ctx, namespace, keyID); err != nil {
			// side note no need to wrap error:
			// origin is also an infra adapter & supposed to not propagate infra error
			return err
		}
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	keyCache, ok := cache[keyID]
	if !ok {
		return fmt.Errorf("%w: for %s: %v", core.ErrDisableKeyFailed, keyID, core.ErrKeyIDNotFound)
	}

	if keyCache.State == core.StateDeleted {
		return fmt.Errorf("%w: for %s: key already hard deleted", core.ErrDisableKeyFailed, keyID)
	}

	keyCache.State = core.StateDisabled
	cache[keyID] = keyCache

	return nil
}

func (e *engine) RenableKey(ctx context.Context, namespace, keyID string) error {
	if e.origin != nil {
		if err := e.origin.RenableKey(ctx, namespace, keyID); err != nil {
			return err
		}
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	keyCache, ok := cache[keyID]
	if !ok {
		return fmt.Errorf("%w: for %s: %v", core.ErrRenableKeyFailed, keyID, core.ErrKeyIDNotFound)
	}

	if keyCache.State == core.StateDeleted {
		return fmt.Errorf("%w: for %s: key already hard deleted", core.ErrDisableKeyFailed, keyID)
	}

	keyCache.State = core.StateActive
	cache[keyID] = keyCache

	return nil
}

func (e *engine) DeleteKey(ctx context.Context, namespace, keyID string) error {
	if e.origin != nil {
		if err := e.origin.DeleteKey(ctx, namespace, keyID); err != nil {
			return err
		}
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	keyCache, ok := cache[keyID]
	if !ok {
		return nil
	}

	keyCache.Key = ""
	keyCache.State = core.StateDeleted
	cache[keyID] = keyCache

	return nil
}

func (e *engine) ClearCache(ctx context.Context, namespace string, force bool) error {
	// If store is empty then engine is acting as a store aka basic key engine.
	// Therfore silently ignore clear cache operation.
	if e.origin == nil {
		return nil
	}

	cache := e.cacheOf(namespace)

	e.mu.Lock()
	defer e.mu.Unlock()

	if len(cache) == 0 {
		return nil
	}

	for keyID, k := range cache {
		if expired := k.At+int64(e.ttl.Seconds()) < time.Now().Unix(); expired || force {
			delete(cache, keyID)
		}
	}

	return nil
}

// Origin implements core.KeyRotatorEngine
func (e *engine) Origin() core.KeyEngine {
	return e.origin
}

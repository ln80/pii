package memory

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ln80/pii/aes"
	"github.com/ln80/pii/core"
)

type keyCache struct {
	ID  string
	Key core.Key
	At  int64
}

// func (kc keyCache) String() string {
// 	return fmt.Sprintf("{ID:%s,Key:****,At:%d}", kc.ID, kc.At)
// }

type engine struct {
	store core.KeyEngine

	cache map[string]map[string]keyCache

	mu  sync.RWMutex
	ttl int64
}

var _ core.KeyEngine = &engine{}
var _ core.KeyCacheEngine = &engine{}

func NewKeyEngine() core.KeyEngine {
	return &engine{
		cache: make(map[string]map[string]keyCache),
	}
}

func NewCacheWrapper(store core.KeyEngine, ttl int64) core.KeyEngine {
	if store == nil {
		panic("invalid embedded Key Engine store, nil value found")
	}
	if ttl == 0 {
		ttl = 30 * 60 // default value: 30 mins
	}

	return &engine{
		cache: make(map[string]map[string]keyCache),
		store: store,
		ttl:   ttl,
	}
}

func (e *engine) GetKeys(ctx context.Context, namespace string, subIDs ...string) (core.KeyMap, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.cache[namespace]; !ok {
		e.cache[namespace] = make(map[string]keyCache)
	}
	foundKeys := core.NewKeyMap()

	missedKeys := []string{}
	for _, subID := range subIDs {
		if key, ok := e.cache[namespace][subID]; ok {
			foundKeys[subID] = key.Key
		} else {
			if e.store != nil {
				missedKeys = append(missedKeys, subID)
			}
		}
	}

	if e.store != nil {
		keys, err := e.store.GetKeys(ctx, namespace, missedKeys...)
		if err != nil {
			return nil, err
		}
		for subID, k := range keys {
			foundKeys[subID] = k
			e.cache[namespace][subID] = keyCache{
				ID:  subID,
				Key: k,
				At:  time.Now().Unix(),
			}
		}
	}

	return foundKeys, nil
}

func (e *engine) GetOrCreateKeys(ctx context.Context, namespace string, subIDs []string, keyGen core.KeyGen) (core.KeyMap, error) {
	if keyGen == nil {
		keyGen = aes.Key256GenFn
	}

	e.mu.Lock()
	if _, ok := e.cache[namespace]; !ok {
		e.cache[namespace] = make(map[string]keyCache)
	}
	e.mu.Unlock()

	if e.store != nil {
		// keys, err := e.store.GetOrCreateKeys(ctx, namespace, subIDs, keyGen)
		// if err != nil {
		// 	return nil, err
		// }
		// for subID, k := range keys {
		// 	e.cache[namespace][subID] = keyCache{
		// 		Key: k,
		// 		At:  time.Now().Unix(),
		// 	}
		// }
		// return keys, nil

		return func() (core.KeyMap, error) {
			e.mu.Lock()
			defer e.mu.Unlock()

			keys, err := e.store.GetOrCreateKeys(ctx, namespace, subIDs, keyGen)
			if err != nil {
				return nil, err
			}
			for subID, k := range keys {
				e.cache[namespace][subID] = keyCache{
					ID:  subID,
					Key: k,
					At:  time.Now().Unix(),
				}
			}
			return keys, nil
		}()
	}
	// e.mu.Unlock()

	keys, err := e.GetKeys(ctx, namespace, subIDs...)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, subID := range subIDs {
		if _, ok := keys[subID]; !ok {
			newKey, err := keyGen(ctx, namespace, subID)
			if err != nil {
				return nil, err
			}
			keys[subID] = core.Key(newKey)

			e.cache[namespace][subID] = keyCache{
				ID:  subID,
				Key: core.Key(newKey),
				At:  time.Now().Unix(),
			}
		}
	}

	return keys, nil
}

func (e *engine) DeleteKey(ctx context.Context, namespace, subID string) error {
	if e.store != nil {
		if err := e.store.DeleteKey(ctx, namespace, subID); err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.cache[namespace]; !ok {
		return nil
	}

	delete(e.cache[namespace], subID)

	return nil
}

func (e *engine) DisableKey(ctx context.Context, namespace, subID string) error {
	return fmt.Errorf("%w: in-memory engine does not support disable key", core.ErrUnsupportedKeyOperation)
}

func (e *engine) Clear(ctx context.Context, namespace string, force bool) error {
	log.Println("engine clear start")

	e.mu.Lock()
	defer e.mu.Unlock()

	// log.Println("engine clear start", e.store)
	// If store is empty then engine is acting as a store (not as a cache wrapper).
	// Therfore, silently ignore clear operation.
	if e.store == nil {
		return nil
	}

	log.Printf("%p %+v", e.cache, e.cache)
	if _, ok := e.cache[namespace]; !ok {
		return nil
	}

	if force {
		e.cache[namespace] = make(map[string]keyCache)
	} else {
		for subID, k := range e.cache[namespace] {
			if expired := k.At+e.ttl < time.Now().Unix(); expired {
				delete(e.cache[namespace], subID)
			}
		}
	}

	return nil
}

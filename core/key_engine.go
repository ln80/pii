// Package core contains the encryption logic model and service interfaces.
package core

import (
	"context"
	"errors"
	"time"
)

// Errors returned by KeyEngine implementations
var (
	ErrPersistKeyFailure  = errors.New("failed to persist encryption key(s)")
	ErrGetKeyFailure      = errors.New("failed to get encryption key(s)")
	ErrReEnableKeyFailure = errors.New("failed to renable encryption key(s)")
	ErrDisableKeyFailure  = errors.New("failed to disable encryption key")
	ErrDeleteKeyFailure   = errors.New("failed to delete encryption key")
	ErrKeyNotFound        = errors.New("encryption key not found")
)

// Encryption key lifecycle states.
const (
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
	StateDeleted  = "DELETED"
)

// KeyState presents encryption key lifecycle states
type KeyState string

// Key presents the plain text value of an encryption key
type Key string

// String overwrites the default to string behavior to protect the key sensitive value.
func (k Key) String() string {
	return "KEY-*****"
}

// KeyMap presents a map of Keys indexed by keyID.
type KeyMap map[string]Key

// NewKeyMap returns a new empty KeyMap.
func NewKeyMap() KeyMap {
	return make(map[string]Key)
}

// KeyIDs returns Key IDs.
func (km KeyMap) KeyIDs() []string {
	subIDs := []string{}
	for subID := range km {
		subIDs = append(subIDs, subID)
	}
	return subIDs
}

// IDKey presents a pair to combine a Key and its ID.
type IDKey struct {
	id  string
	key Key
}

// NewIDKey returns new IdKey value of the given Key and ID.
func NewIDKey(id, key string) IDKey {
	return IDKey{
		id, Key(key),
	}
}

func (ik IDKey) ID() string {
	return ik.id
}

func (ik IDKey) Key() Key {
	return ik.key
}

// KeyGen presents a function used by Key engines to generate keys
type KeyGen func(ctx context.Context, namespace, keyID string) (string, error)

// KeyEngineConfig presents the basic configuration of KeyEngine
// Implementations may extend it and add specific configuration.
type KeyEngineConfig struct {
	GracePeriod time.Duration
}

// NewKeyEngineConfig returns a default KeyEngineConfig
// mainly to avoid an empty GracePeriod configuration which seems to be critical.
func NewKeyEngineConfig() KeyEngineConfig {
	return KeyEngineConfig{
		GracePeriod: 7 * 24 * time.Hour,
	}
}

// KeyEngine presents the service responsible for managing encryption keys.
type KeyEngine interface {

	// GetKeys returns a map of keys for the given keyIDs within the given namespace.
	// It doesn't return a key if it's disabled or deleted.
	// The total count of the result should be less or equal to keyIDs' count.
	// The returned map of keys is indexed by keyIDs.
	GetKeys(ctx context.Context, namespace string, keyIDs []string) (keys KeyMap, err error)

	// GetOrCreateKeys returns the existing keys for the given keyIDs
	// within the given namespace and creates new ones for the fresh new keyIDs.
	//
	// Note that it will not create a new key for a deleted keyID.
	GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen KeyGen) (KeyMap, error)

	// DisableKey disables the associated key of the given keyID.
	// It returns ErrKeyNotFound error if the key is already deleted.
	DisableKey(ctx context.Context, namespace, keyID string) error

	// ReEnableKey reenables the associated key of the given keyID.
	// It returns ErrKeyNotFound error if the key is already deleted.
	ReEnableKey(ctx context.Context, namespace, keyID string) error

	// DeleteKey deletes the associated key of the given keyID.
	DeleteKey(ctx context.Context, namespace, keyID string) error

	// DeleteUnusedKeys delete unused keys which were disabled
	// for longer or equal to the configured grace period.
	DeleteUnusedKeys(ctx context.Context, namespace string) error
}

// KeyEngineWrapper presents a wrapper on top of an existing Key engine.
// It overrides and enhances behaviors such as caching and
// client-side encryption of keys' values.
type KeyEngineWrapper interface {
	KeyEngine

	// Origin returns the wrapped Key engine.
	Origin() KeyEngine
}

// KeyEngineCache is a KetEngine wrapper used for cache purpose.
type KeyEngineCache interface {
	KeyEngineWrapper

	// ClearCache invalidates the cache of encryption keys based on a time-to-live configuration.
	// 'force' parameter allows to bypass the TTL check and immediately invalidates the cache.
	ClearCache(ctx context.Context, namespace string, force bool) error
}

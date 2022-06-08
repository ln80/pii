// Package core contains the encryption logic model and service interfaces.
package core

import (
	"context"
	"errors"
)

// Errors returned by KeyEngine implementations
var (
	ErrPeristKeyFailure  = errors.New("failed to persist encryption key(s)")
	ErrGetKeyFailure     = errors.New("failed to get encryption key(s)")
	ErrRenableKeyFailure = errors.New("failed to renable encryption key(s)")
	ErrDisableKeyFailure = errors.New("failed to disable encryption key")
	ErrDeleteKeyFailure  = errors.New("failed to delete encryption key")
	ErrKeyNotFound       = errors.New("encryption key not found")
)

// KeyGen presents a function used by Key engines to generate keys
type KeyGen func(ctx context.Context, namespace, keyID string) (string, error)

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

	// RenableKey renables the associated key of the given keyID.
	// It returns ErrKeyNotFound error if the key is already deleted.
	RenableKey(ctx context.Context, namespace, keyID string) error

	// DeleteKey deletes the associated key of the given keyID.
	DeleteKey(ctx context.Context, namespace, keyID string) error
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

// Errors returned by Encrypter implementations
var (
	ErrEnryptionFailure  = errors.New("failed to encrypt data")
	ErrDecryptionFailure = errors.New("failed to decrypt data")
)

// Encrypter presents a service responsible for implementing encryption logic
// based on a specific algorithm.
type Encrypter interface {

	// Encrypt encrypts the given plain text values and returns a cipher text.
	Encrypt(namespace string, key Key, plainTxt string) (cipherTxt string, err error)

	// Decrypt decrypts the given cipher text and return the original value.
	Decrypt(namespace string, key Key, cipherTxt string) (plainTxt string, err error)

	// KeyGen returns a function that generates a valid key
	// according to the implemented algorithm.
	KeyGen() KeyGen
}

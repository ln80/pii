package core

import (
	"context"
	"errors"
)

var (
	ErrPeristKeyFailure  = errors.New("failed to persist encryption key(s)")
	ErrGetKeyFailure     = errors.New("failed to get encryption key(s)")
	ErrRenableKeyFailure = errors.New("failed to renable encryption key(s)")
	ErrDisableKeyFailure = errors.New("failed to disable encryption key")
	ErrDeleteKeyFailure  = errors.New("failed to delete encryption key")
	ErrKeyNotFound       = errors.New("encryption key not found")
)

type KeyGen func(ctx context.Context, namespace, keyID string) (string, error)

type KeyEngine interface {
	GetKeys(ctx context.Context, namespace string, keyIDs ...string) (keys KeyMap, err error)

	GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen KeyGen) (KeyMap, error)

	DisableKey(ctx context.Context, namespace, keyID string) error

	RenableKey(ctx context.Context, namespace, keyID string) error

	DeleteKey(ctx context.Context, namespace, keyID string) error
}

type KeyEngineWrapper interface {
	KeyEngine
	Origin() KeyEngine
}

type KeyEngineCache interface {
	KeyEngineWrapper
	ClearCache(ctx context.Context, namespace string, force bool) error
}

var (
	ErrEnryptionFailure  = errors.New("failed to encrypt text")
	ErrDecryptionFailure = errors.New("failed to decrypt text")
)

type Encrypter interface {
	Encrypt(namespace string, key Key, plainTxt string) (cipherTxt string, err error)
	Decrypt(namespace string, key Key, cipherTxt string) (plainTxt string, err error)
	KeyGen() KeyGen
}

// type KeyUpdaterEngine interface {
// 	KeyEngine
// 	UpdateKeys(ctx context.Context, namespace string, keys []IDKey) error
// }

// type KeyRotatorEngine interface {
// 	KeyEngine
// 	RotateKeys(ctx context.Context, namespace, keyIDs string) error
// 	Origin() KeyEngine
// }

// type KeyCacheEngine interface {
// 	KeyEngine
// 	ClearCache(ctx context.Context, namespace string, force bool) error
// }

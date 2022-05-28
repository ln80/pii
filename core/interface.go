package core

import (
	"context"
	"errors"
)

var (
	ErrUnsupportedKeyOperation = errors.New("unsupported key operation")
)

var (
	ErrPersistKeyConflict  = errors.New("conflict error while persisting key(s)")
	ErrPeristKeyFailed     = errors.New("failed to persist key(s)")
	ErrRenableKeyFailed    = errors.New("failed to renable key(s)")
	ErrKeyIDNotFound       = errors.New("key ID not found")
	ErrDisableKeyFailed    = errors.New("failed to disable key")
	ErrHardDeleteKeyFailed = errors.New("failed to hard delete key")
)

var (
	ErrEnryptionFailed  = errors.New("failed to encrypt message")
	ErrDecryptionFailed = errors.New("failed to decrypt message")
)

type KeyGen func(ctx context.Context, namespace, keyID string) (string, error)

type KeyEngine interface {
	GetKeys(ctx context.Context, namespace string, keyIDs ...string) (keys KeyMap, err error)

	GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen KeyGen) (KeyMap, error)

	DisableKey(ctx context.Context, namespace, keyID string) error

	RenableKey(ctx context.Context, namespace, keyID string) error

	DeleteKey(ctx context.Context, namespace, keyID string) error
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

type KeyEngineWrapper interface {
	KeyEngine
	Origin() KeyEngine
}

type KeyEngineCache interface {
	KeyEngineWrapper
	ClearCache(ctx context.Context, namespace string, force bool) error
}

type Encrypter interface {
	Encrypt(key Key, plainTxt string) (cypherTxt string, err error)
	Decrypt(key Key, cypherTxt string) (plainTxt string, err error)
	// GenNewKey() string
}

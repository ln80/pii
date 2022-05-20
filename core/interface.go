package core

import (
	"context"
	"errors"
)

var (
	ErrUnsupportedKeyOperation = errors.New("unsupported key operation")
)

var (
	ErrPersistKeyConflict = errors.New("conflict error while persisting key(s)")
	ErrPeristKeyFailed    = errors.New("failed to persist key(s)")
)

type KeyGen func(ctx context.Context, namespace, subID string) (string, error)

type KeyEngine interface {
	DisableKey(ctx context.Context, namespace, subID string) error

	DeleteKey(ctx context.Context, namespace, subID string) error

	GetKeys(ctx context.Context, namespace string, subIDs ...string) (keys KeyMap, err error)

	GetOrCreateKeys(ctx context.Context, namespace string, subIDs []string, keyGen KeyGen) (KeyMap, error)
}

type KeyUpdaterEngine interface {
	KeyEngine
	UpdateKeys(ctx context.Context, namespace string, keys []IDKey) error
}

type KeyRotatorEngine interface {
	KeyEngine
	RotateKeys(ctx context.Context, namespace, subIDs string) error
}

type KeyCacheEngine interface {
	KeyEngine
	Clear(ctx context.Context, namespace string, force bool) error
}

type Encrypter interface {
	Encrypt(key Key, txt string) (ctxt string, err error)
	Decrypt(key Key, ctxt string) (txt string, err error)
	GenNewKey() string
}

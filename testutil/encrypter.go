package testutil

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ln80/pii/core"
)

var (
	ErrEncryptionMock = errors.New("encryption errors mock")
)

var _ core.Encrypter = &UnstableEncrypterMock{}

type UnstableEncrypterMock struct {
	PointOfFailure, counter int
	mu                      sync.RWMutex
}

func (e *UnstableEncrypterMock) ResetCounter() {
	e.counter = 0
}

// Decrypt implements core.Encrypter
func (e *UnstableEncrypterMock) Decrypt(namespace string, key core.Key, cipherTxt []byte) (plainTxt string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return "", fmt.Errorf("%w: %v", core.ErrDecryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	return string(cipherTxt[len("mock"):]), nil
}

// Encrypt implements core.Encrypter
func (e *UnstableEncrypterMock) Encrypt(namespace string, key core.Key, plainTxt string) (cipherTxt []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return nil, fmt.Errorf("%w: %v", core.ErrEncryptionFailure, ErrEncryptionMock)
	}
	e.counter++

	return []byte("mock" + plainTxt), nil
}

// KeyGen implements core.Encrypter
func (*UnstableEncrypterMock) KeyGen() core.KeyGen {
	return nil
}

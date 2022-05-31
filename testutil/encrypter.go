package testutil

import (
	"errors"
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
func (e *UnstableEncrypterMock) Decrypt(key core.Key, cypherTxt string) (plainTxt string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.counter >= e.PointOfFailure {
		return "", ErrEncryptionMock
	}
	e.counter++

	return cypherTxt[4:], nil
}

// Encrypt implements core.Encrypter
func (e *UnstableEncrypterMock) Encrypt(key core.Key, plainTxt string) (cypherTxt string, err error) {
	if e.counter >= e.PointOfFailure {
		return "", ErrEncryptionMock
	}
	e.counter++

	return "mock" + plainTxt, nil
}

package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/ln80/pii/core"
)

const (
	aES265KeySize = 32
)

var (
	// Key256GenFn returns a function that generates a 32 bytes key
	Key256GenFn core.KeyGen = func(ctx context.Context, namespace, subID string) (string, error) {
		return string(getRandomBytes(aES265KeySize)), nil
	}
)

type aes256gcm struct{}

var _ core.Encrypter = &aes256gcm{}

func New256GCMEncrypter() core.Encrypter {
	return &aes256gcm{}
}

func (e *aes256gcm) KeyGen() core.KeyGen {
	return Key256GenFn
}

func prepareAdditionalData(namespace string) []byte {
	if namespace == "" {
		return nil
	}
	return append([]byte("ns:"), []byte(namespace)...)
	// return []byte("ns:" + namespace)
}

func (e *aes256gcm) Encrypt(namespace string, key core.Key, plainTxt string) (cipherTxt string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %v", core.ErrEnryptionFailure, err)
		}
	}()

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := getRandomBytes(uint16(aesgcm.NonceSize()))
	aad := prepareAdditionalData(namespace)

	cTxt, err := aesgcm.Seal(nil, nonce, []byte(plainTxt), aad), nil
	if err != nil {
		return
	}

	cTxt = append(nonce, cTxt...)

	// cipherTxt = hex.EncodeToString(cTxt)
	cipherTxt = base64.StdEncoding.EncodeToString(cTxt)
	return
}

func (e *aes256gcm) Decrypt(namespace string, key core.Key, cipherTxt string) (plainTxt string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %v", core.ErrDecryptionFailure, err)
		}
	}()

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return
	}
	// cTxt, err := hex.DecodeString(cipherTxt)
	cTxt, err := base64.StdEncoding.DecodeString(cipherTxt)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonceSize := aesgcm.NonceSize()
	aad := prepareAdditionalData(namespace)

	plnTxt, err := aesgcm.Open(nil, cTxt[:nonceSize], cTxt[nonceSize:], aad)
	if err != nil {
		return
	}

	return string(plnTxt), nil
}

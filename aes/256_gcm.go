package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"

	"github.com/ln80/pii/core"
)

const (
	AES265KeySize = 32
)

var (
	Key256GenFn core.KeyGen = func(ctx context.Context, namespace, subID string) (string, error) {
		return string(GetRandomBytes(AES265KeySize)), nil
	}
)

type aes256gcm struct{}

var _ core.Encrypter = &aes256gcm{}

func New256GCMEncrypter() core.Encrypter {
	return &aes256gcm{}
}

func (e *aes256gcm) GenNewKey() string {
	return string(GetRandomBytes(AES265KeySize))
}

func (e *aes256gcm) Encrypt(key core.Key, plainTxt string) (string, error) {
	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := GetRandomBytes(uint16(aesgcm.NonceSize()))

	cipherText, err := aesgcm.Seal(nil, nonce, []byte(plainTxt), nil), nil
	if err != nil {
		return "", err
	}
	cipherText = append(nonce, cipherText...)

	return fmt.Sprintf("%x", cipherText), nil
}

func (e *aes256gcm) Decrypt(key core.Key, ctxt string) (string, error) {
	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		return "", err
	}
	cipherTxt, err := hex.DecodeString(ctxt)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesgcm.NonceSize()

	plainTxt, err := aesgcm.Open(nil, cipherTxt[:nonceSize], cipherTxt[nonceSize:], nil)
	if err != nil {
		return "", err
	}

	return string(plainTxt), nil
}

package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/google/tink/go/subtle/random"
	"github.com/ln80/pii/core"
)

const (
	AES265KeySize = 32
)

var (
	Key256GenFn core.KeyGen = func(ctx context.Context, namespace, subID string) (string, error) {
		return string(random.GetRandomBytes(AES265KeySize)), nil
	}
)

type aes256 struct{}

var _ core.Encrypter = &aes256{}

func New256CBCEncrypter() core.Encrypter {
	return &aes256{}
}

func (e *aes256) GenNewKey() string {
	return string(random.GetRandomBytes(AES265KeySize))
}

func (e *aes256) Encrypt(key core.Key, txt string) (string, error) {
	bkey := []byte(key)
	plainText := []byte(txt)
	plainText, err := pad(plainText, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf(`plainText: "%s" has error`, plainText)
	}
	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return "", err
	}

	block, err := aes.NewCipher(bkey)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return fmt.Sprintf("%x", cipherText), nil
}

func (e *aes256) Decrypt(key core.Key, ctxt string) (string, error) {
	bkey := []byte(key)
	cipherText, _ := hex.DecodeString(ctxt)

	block, err := aes.NewCipher(bkey)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = unpad(cipherText, aes.BlockSize)
	return string(cipherText), nil
}

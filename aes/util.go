// Package aes contains implementation and helper functions related
// specifically to "Advanced Encryption Standard" algorithm and cryptography in general.
package aes

import (
	"crypto/rand"
	"io"
)

func getRandomBytes(size uint16) []byte {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}

	return data
}

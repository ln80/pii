package aes

import (
	"crypto/rand"
	"io"
)

func GetRandomBytes(size uint16) []byte {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}

	return data
}

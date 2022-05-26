package testutil

import (
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"sort"
)

func KeysEqual(x, y []string) bool {
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y)
}

func RandomID() string {
	data := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", data)
}

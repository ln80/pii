package testutil

import (
	"reflect"
	"sort"
)

type Profile struct {
	UserID   string `pii:"subjectID"`
	Fullname string `pii:"data,replace=deleted user"`
	Gender   string `pii:"data"`
	Country  string
}

func KeysEqual(x, y []string) bool {
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y)
}

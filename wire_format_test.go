package pii

import (
	"encoding/base64"
	"strconv"
	"testing"
)

func TestWireFormat(t *testing.T) {

	base64 := func(str string) string {
		return base64.StdEncoding.EncodeToString([]byte(str))
	}
	tcs := []struct {
		input    string
		isPacked bool
	}{
		{
			"",
			false,
		},
		{
			"<pii::",
			false,
		},
		{
			"<pii:UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=",
			false,
		},
		{
			"<PII::UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=",
			false,
		},
		{
			"<pii::" + base64("abc") + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ_invalid_base64",
			false,
		},
		{
			"<pii::" + "" + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=",
			false,
		},
		{
			"<pii::" + "invalid_base64" + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=",
			false,
		},
		{
			"<pii::" + base64("abc") + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=",
			true,
		},
		{
			"<pii:" + "4" + ":" + base64("abc") + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=",
			true,
		},
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
			if tc.isPacked {
				if ok := isWireFormatted(tc.input); !ok {
					t.Fatal("expect input be wire formatted")
				}
				version, subjectID, cipher, err := parseWireFormat(tc.input)
				if err != nil {
					t.Fatal("expect err be nil, got", err)
				}

				if version < 1 {
					t.Fatal("expect version be greater than 1, got", version)
				}
				if subjectID == "" {
					t.Fatal("expect subjectID be not empty, got", subjectID)
				}
				if len(cipher) == 0 {
					t.Fatal("expect unpacked cipher be not empty")
				}

				if want, got := tc.input, wireFormat(subjectID, cipher, version); got != want {
					t.Fatalf("expect %s, %s be equals", want, got)
				}
			} else {
				if ok := isWireFormatted(tc.input); ok {
					t.Fatal("expect input not be wire formatted")
				}
			}
		})
	}
}

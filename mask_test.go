package pii

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestMask(t *testing.T) {
	type Device struct {
		IPAddr string `pii:"data,kind=ipv4_addr"`
	}

	type CreditCard struct {
		Number string `pii:"data,kind=credit_card"`
	}

	type Profile struct {
		Email       string       `pii:"data,kind=email"`
		Fullname    string       `pii:"data"`
		Device      Device       `pii:"dive"`
		CreditCards []CreditCard `pii:"dive"`
	}

	tcs := []struct {
		val  any
		want any
		ok   bool
		err  error
	}{
		{
			val:  nil,
			want: nil,
			ok:   false,
			err:  ErrUnsupportedType,
		},
		{
			val: &Profile{
				Email:    "invalid_email.com",
				Fullname: "Guadalupe Kemmer DDS",
				Device: Device{
					IPAddr: "169.251.207.194",
				},
				CreditCards: []CreditCard{{Number: "invalid_number"}},
			},
			// Mask fails if the predefined mask is incompatible with the PII value
			ok: false,
		},
		{
			val: &Profile{
				Email:    "email@example.com",
				Fullname: "Guadalupe Kemmer DDS",
				Device: Device{
					IPAddr: "169.251.207.194",
				},
				CreditCards: []CreditCard{{Number: "6706 7510 5149 0155"}},
			},
			want: &Profile{
				Email:    "*****@example.com",
				Fullname: "********************",
				Device: Device{
					IPAddr: "169.251.207.***",
				},
				CreditCards: []CreditCard{{Number: "**** **** **** 0155"}},
			},
			ok: true,
		},
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
			err := Mask(tc.val)
			if !tc.ok {
				if err == nil {
					t.Fatal("expect err not to be nil")
				}
				if tc.err != nil && !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal("expect err be nil, got", err)
			}
			if !reflect.DeepEqual(tc.want, tc.val) {
				t.Fatalf("expect %s, %s be equals", tc.want, tc.val)
			}
		})
	}

}

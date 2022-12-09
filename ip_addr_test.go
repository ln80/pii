package pii

import (
	"errors"
	"strconv"
	"testing"
)

var testcases_truncateIPv4Addr = []struct {
	ip   string
	ok   bool
	n    uint8
	want string
	err  error
}{
	{
		ip:  "192.0.2.521",
		ok:  false,
		err: ErrInvalidIPAddress,
		n:   0,
	},
	{
		ip:  "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		ok:  false,
		err: ErrInvalidIPAddress,
		n:   0,
	},
	{
		ip:  "",
		ok:  false,
		err: ErrInvalidIPAddress,
		n:   0,
	},
	{
		ip:   "192.0.2.40",
		ok:   true,
		n:    0,
		want: "192.0.2.40",
	},
	{
		ip:   "192.0.2.40",
		ok:   true,
		n:    1,
		want: "192.0.2.0",
	},
	{
		ip:   "192.0.2.40",
		ok:   true,
		n:    2,
		want: "192.0.0.0",
	},
	{
		ip:   "192.0.2.40",
		ok:   true,
		n:    3,
		want: "192.0.0.0",
	},
	{
		ip:   "192.0.2.40",
		ok:   true,
		n:    4,
		want: "0.0.0.0",
	},
	{
		ip:   "192.0.2.40",
		ok:   true,
		n:    10,
		want: "0.0.0.0",
	},
}

func TestTruncateIPAddr(t *testing.T) {
	for i, tc := range testcases_truncateIPv4Addr {
		t.Run("tc:"+strconv.Itoa(i), func(t *testing.T) {
			ip, err := TruncateIPv4Addr(tc.ip, tc.n)
			if tc.ok {
				if err != nil {
					t.Fatal("expect err be nil got:", err)
				}
				if tc.want != ip {
					t.Fatalf("expect %s, %s be equals", tc.want, ip)
				}
			} else {
				if !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %s, got %s", tc.err, err)
				}
			}

		})
	}
}

func TestMustTruncateIPAddr(t *testing.T) {
	for i, tc := range testcases_truncateIPv4Addr {
		t.Run("tc:"+strconv.Itoa(i), func(t *testing.T) {
			func() {
				var ip string
				defer func() {
					r := recover()
					if tc.ok {
						if r != nil {
							t.Fatal("expect err be nil got:", r)
						}
						if tc.want != ip {
							t.Fatalf("expect %s, %s be equals", tc.want, ip)
						}
					} else {
						if r == nil {
							t.Fatal("expect to panic recover to be not nil", r)
						}
						err, ok := r.(error)
						if !ok {
							t.Fatalf("expect to panic an error, got %T", r)
						}
						if !errors.Is(err, tc.err) {
							t.Fatalf("expect err is %s, got %s", tc.err, r)
						}
					}
				}()
				ip = MustTruncateIPv4Addr(tc.ip, tc.n)
			}()
		})
	}
}

//    zaaz go+build unit

package main

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	piidb "github.com/ln80/pii/dynamodb"
	pii_testutil "github.com/ln80/pii/testutil"
)

var _ = (func() interface{} {
	_unitTesting = true
	return nil
}())

func TestHandler(t *testing.T) {
	type tc struct {
		Eng piidb.KeyEngine
		Ok  bool
		Err error
	}

	tcs := []tc{
		{
			Eng: nil,
			Ok:  false,
			Err: errInvalidKeyEngine,
		},
		func() tc {
			err := errors.New("ListNamespace mock err")
			return tc{
				Eng: &pii_testutil.EngineMock{
					ListNamespaceErr: err,
				},
				Ok:  false,
				Err: err,
			}
		}(),
		func() tc {
			err := errors.New("DeleteKey mock err")
			return tc{
				Eng: &pii_testutil.EngineMock{
					ListNamespaceErr: nil,
					NamespaceList:    []string{"ns_1, ns_2"},
					DeleteKeyErr:     err,
				},
				Ok:  false,
				Err: err,
			}
		}(),
		func() tc {
			err := errors.New("DeleteKey mock err")
			return tc{
				Eng: &pii_testutil.EngineMock{
					ListNamespaceErr: nil,
					NamespaceList:    []string{}, // namespaces not found
					DeleteKeyErr:     err,
				},
				Ok: true,
			}
		}(),
		{
			Eng: &pii_testutil.EngineMock{
				ListNamespaceErr: nil,
				NamespaceList:    []string{"ns_1, ns_2"},
				DeleteKeyErr:     nil,
			},
			Ok: true,
		},
	}

	ctx := context.Background()

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
			h := makeHandler(tc.Eng)
			err := h(ctx, events.CloudWatchEvent{})
			if tc.Ok {
				if err != nil {
					t.Fatal("expect err be nil, got", err)
				}
			} else {
				if !errors.Is(err, tc.Err) {
					t.Fatalf("expect err be %v, got %v", tc.Err, err)
				}
			}
		})
	}
}

package pii

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestStruct(t *testing.T) {
	// replaceFn does empty PII fields. This particular behavior makes testing easier.
	replaceFn := func(rf ReplaceField, fieldIdx int, val string) (newVal string, err error) {
		return "", nil
	}

	// Helper structs:

	type Email string

	type Profile struct {
		ID    string  `pii:"subjectID"`
		Email Email   `pii:"data"`
		Phone *string `pii:"data"`
	}

	type Address struct {
		Street string `pii:"data"`
	}

	type tc struct {
		val  any
		want any
		ok   bool
		err  error
	}
	tcs := []tc{
		{
			val: &Profile{
				ID:    "abc",
				Email: "email@example.com",
			},
			want: &Profile{
				ID: "abc",
			},
			ok: true,
		},
		{
			val: &Profile{
				ID:    "abc",
				Email: "email@example.com",
				Phone: ptr("519-491-6780"),
			},
			want: &Profile{
				ID:    "abc",
				Phone: ptr(""),
			},
			ok: true,
		},
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address *Address `pii:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: nil,
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: nil,
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address *Address `pii:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: &Address{
						Street: "7234 Antone Springs",
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: &Address{
						Street: "",
					},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address []Address `pii:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: []Address{
						{
							Street: "7234 Antone Springs",
						},
						{
							Street: "90 Kerluke Pine DS",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: []Address{
						{},
						{},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address []Address `pii:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address []*Address `pii:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: []*Address{
						{
							Street: "7234 Antone Springs",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: []*Address{
						{},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address map[string]*Address `pii:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: map[string]*Address{
						"A": {
							Street: "7234 Antone Springs",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: map[string]*Address{
						"A": {
							Street: "",
						},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address map[string]*Address `pii:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: nil,
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: nil,
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Address map[string]Address `pii:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: map[string]Address{
						"A": {
							Street: "7234 Antone Springs",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: map[string]Address{
						"A": {
							Street: "",
						},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Child   *T `pii:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Child: &T{
						Profile: Profile{
							ID:    "abc",
							Email: "email.child@example.com",
						},
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Child: &T{
						Profile: Profile{
							ID: "abc",
						},
					},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `pii:"dive"`
				Child   *T `pii:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Child: &T{
						Profile: Profile{
							ID:    "abc_child",
							Email: "email.child@example.com",
						},
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},

					Child: &T{
						Profile: Profile{
							ID: "abc_child",
						},
					},
				},
				ok:  false,
				err: ErrMultipleNestedSubjectID,
				// err: ErrInvalidTagConfiguration,
			}
		}(),
		func() tc {
			type NestedAddress struct {
				Address `pii:"dive"`
				Sub     *Address `pii:"dive"`
			}
			type T struct {
				Profile `pii:"dive"`
				Address NestedAddress `pii:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: NestedAddress{
						Address: Address{
							Street: "7234 Antone Springs",
						},
						Sub: &Address{
							Street: "26559 Senger Crossing",
						},
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: NestedAddress{
						Address: Address{
							Street: "",
						},
						Sub: &Address{
							Street: "",
						},
					},
				},
				ok: true,
			}
		}(),
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {
			sm, err := scan(tc.val)
			if !tc.ok {
				if !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %v, got %v", tc.err, err)
				}
				return
			}

			if err != nil {
				t.Fatal("expect err be nil, got", err)
			}
			s := sm[0]

			_ = s.replace(replaceFn)

			if !reflect.DeepEqual(tc.want, tc.val) {
				t.Fatalf("expect %s, %s be equals", tc.want, tc.val)
			}
		})
	}
}

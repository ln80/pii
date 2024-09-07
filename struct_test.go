package pii

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

type Email string

type Profile struct {
	ID    string  `pii:"subjectID"`
	Email Email   `pii:"data"`
	Phone *string `pii:"data"`
}

type Address struct {
	Street string `pii:"data"`
}

func TestStruct_Redact(t *testing.T) {
	type tc struct {
		val  any
		want any
		fn   ReplaceFunc
		ok   bool
		err  error
	}

	tcs := []tc{
		{
			val: nil,
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: "070 a",
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: Address{Street: "07024 Quigley Trace"},
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val:  &Address{Street: "07024 Quigley Trace"},
			want: &Address{Street: "0****************ce"},
			ok:   true,
		},
		{
			val:  &Address{Street: "070 a"},
			want: &Address{Street: "****a"},
			ok:   true,
		},
		func() tc {
			testErr := errors.New("test replace error")
			return tc{
				val: &Address{Street: "070 a"},
				fn: func(rf ReplaceField, val string) (string, error) {
					return "", testErr
				},
				ok:  false,
				err: testErr,
			}
		}(),
		{
			val:  &Address{Street: "070 a"},
			want: &Address{Street: "*"},
			fn: func(rf ReplaceField, val string) (string, error) {
				return "*", nil
			},
			ok: true,
		},
		{
			val: &Profile{
				ID:    "", // Is not mandatory in the case of Redact
				Email: "Vernon_Parker21@gmail.com",
				Phone: ptr("250-308-0529"),
			},
			want: &Profile{
				ID:    "",
				Email: "V**********************om",
				Phone: ptr("2*********29"),
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
					Address: &Address{Street: "07024 Quigley Trace"},
				},
				want: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "e**************om",
					},
					Address: &Address{Street: "0****************ce"},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Value string
			}
			return tc{
				val: &T{
					Value: "abc",
				},
				want: &T{
					Value: "abc",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Email    Email  `pii:"data"`
				Fullname string `pii:"data"`
			}
			return tc{
				val: &T{
					Email:    "email@example.com",
					Fullname: "Sarah Turcotte",
				},
				want: &T{
					Email:    "****@****.com",
					Fullname: "S***********te",
				},
				fn: func(rf ReplaceField, val string) (string, error) {
					switch {
					case rf.RType == reflect.TypeOf(Email("")):
						return "****@****.com", nil
					default:
						return defaultRedactFunc(rf, val)
					}
				},
				ok: true,
			}
		}(),
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {
			err := Redact(tc.val, func(rc *RedactConfig) {
				if tc.fn != nil {
					rc.RedactFunc = tc.fn
				}
			})
			if !tc.ok {
				if !errors.Is(err, tc.err) {
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

func TestStruct_Check(t *testing.T) {
	type tc struct {
		val any
		ok  bool
		err error
	}

	tcs := []tc{
		{
			val: Email("email@example.com"),
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: struct{ Val string }{Val: "value"},
			ok:  false,
		},
		{
			val: Address{Street: "578 Abbott Viaduct"},
			ok:  true,
		},
		{
			val: struct {
				Address Address `pii:"dive"`
			}{Address: Address{Street: "578 Abbott Viaduct"}},
			ok: true,
		},
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {

			ok, err := Check(tc.val)

			if got, want := err, tc.err; !errors.Is(got, want) {
				t.Fatalf("expect %v, %v be equals", got, want)
			}

			if got, want := ok, tc.ok; got != want {
				t.Fatalf("expect %v, %v be equals", got, want)
			}
		})
	}
}

func TestStruct_Scan(t *testing.T) {
	// replaceFn does empty PII fields. This particular behavior makes testing easier.
	replaceFn := func(rf ReplaceField, val string) (newVal string, err error) {
		return "", nil
	}

	// Helper structs:

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
			s, err := scan(tc.val, true)
			if !tc.ok {
				if !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal("expect err be nil, got", err)
			}
			_ = s.replace(replaceFn)
			if !reflect.DeepEqual(tc.want, tc.val) {
				t.Fatalf("expect %s, %s be equals", tc.want, tc.val)
			}
		})
	}
}

// func TestStruct_Debug(t *testing.T) {

// 	pf1 := Profile{
// 		ID:    "abc 1",
// 		Email: "email@example.com",
// 	}
// 	pf2 := Profile{
// 		ID:    "abc 2",
// 		Email: "email@example.com",
// 	}

// 	pfs := []any{pf1, pf2}

// 	ps, err := scan(pfs, false)
// 	if err != nil {
// 		t.Fatal("expect err be nil, got", err)
// 	}
// 	t.Logf("--> %+v", pfs)

// 	err = ps.replace(func(rf ReplaceField, val string) (string, error) {

// 		return "hello", nil
// 	})

// 	if err != nil {
// 		t.Fatal("expect err be nil, got", err)
// 	}

// 	t.Logf("--> %+v", pfs)
// }

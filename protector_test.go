package pii

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ln80/pii/core"
	"github.com/ln80/pii/memory"
	"github.com/ln80/pii/testutil"
)

func TestProtector_EncryptDecrypt(t *testing.T) {
	ctx := context.Background()

	nspace := "tenant-d195kla"

	p := NewProtector(nspace, memory.NewKeyEngine())

	pf1 := testutil.Profile{
		UserID:   "kal5430",
		Fullname: "Idir Moore",
		Gender:   "M",
		Country:  "MA",
		Address: testutil.Address{
			Street: "56559 Von Divide",
		},
	}
	opf1 := pf1

	pf2 := testutil.Profile{
		UserID:   "aze6590",
		Fullname: "Anna Gibz",
		Gender:   "F",
		Country:  "GB",
	}
	opf2 := pf2

	t.Run("encrypt-decrypt personal data with nonsense values", func(t *testing.T) {
		if err := p.Encrypt(ctx); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		ignored := testutil.IgnoredStruct{Val: "value"}
		oignored := ignored

		if err := p.Encrypt(ctx, &ignored); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := ignored, oignored; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		if err := p.Encrypt(ctx, &ignored); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := ignored, oignored; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt unsupported type value", func(t *testing.T) {
		tcs := []any{
			nil, pf1, pf2, make(map[string]any),
			[]byte(""), "primitive txt", 23, func() {}, make(chan int),
		}

		want := ErrUnsupportedType
		for _, value := range tcs {
			if err := p.Encrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
			if err := p.Decrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
		}
	})

	t.Run("encrypt-decrypt unsupported field type", func(t *testing.T) {
		tcs := []any{
			&testutil.InvalidStruct3{Val1: "id", Val2: 30},
		}

		want := ErrUnsupportedFieldType
		for _, value := range tcs {
			if err := p.Encrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
			if err := p.Decrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be %v, got %v", want, err)
			}
		}
	})

	t.Run("encrypt-decrypt personal data with invalid tag configuration", func(t *testing.T) {
		tcs := []struct {
			val        any
			encryptErr error
			decryptErr error
		}{
			{
				val:        &testutil.InvalidStruct1{},
				encryptErr: ErrInvalidTagConfiguration,
			},
			{
				val:        &testutil.InvalidStruct2{Val1: "id", Val2: "otherId"},
				encryptErr: ErrInvalidTagConfiguration,
				decryptErr: ErrInvalidTagConfiguration,
			},
		}

		for _, tc := range tcs {
			if err := p.Encrypt(ctx, tc.val); !errors.Is(err, tc.encryptErr) {
				t.Errorf("expect err be '%v', got '%v'", tc.encryptErr, err)
			}
			if err := p.Decrypt(ctx, tc.val); !errors.Is(err, tc.decryptErr) {
				t.Errorf("expect err be '%v', got '%v'", tc.decryptErr, err)
			}
		}
	})

	t.Run("encrypt-decrypt personal data with success", func(t *testing.T) {
		if err := p.Encrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert personal data are mutated (to a cipher text)
		if want, got := opf1.Fullname, pf1.Fullname; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf1.Address, pf1.Address; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf2.Fullname, pf2.Fullname; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}

		// assert personal data are mutated back to their plain text values
		if err := p.Decrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := opf1.Fullname, pf1.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf1.Address, pf1.Address; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf2.Fullname, pf2.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt atomicity", func(t *testing.T) {

		t.Skip("skipping this test as atomicity support has been dropped by now.")

		enc := &testutil.UnstableEncrypterMock{
			PointOfFailure: 2,
		}

		p := NewProtector(nspace, memory.NewKeyEngine(), func(pc *ProtectorConfig) {
			pc.Encrypter = enc
		})

		pf1 := testutil.Profile{
			UserID:   "kal5430",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}
		opf1 := pf1

		pf2 := testutil.Profile{
			UserID:   "hjl5a00",
			Fullname: "Jav Koelpin",
			Gender:   "M",
			Country:  "DE",
		}
		opf2 := pf2

		if want, err := core.ErrEncryptionFailure, p.Encrypt(ctx, &pf1, &pf2); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got %v", want, err)
		}

		// expect pii structs to be different from originals
		if want, got := opf1, pf1; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf2, pf2; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// make sure not to fail encryption
		enc.PointOfFailure = 1000
		enc.ResetCounter()

		if err := p.Encrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		enc.PointOfFailure = 2
		enc.ResetCounter()

		err := p.Decrypt(ctx, &pf1, &pf2)
		if err == nil {
			t.Fatal("expect err be not nil")
		}

		// expect none of pii structs to be decrypted back to normal
		if want, got := opf1, pf1; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf2, pf2; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt idempotency", func(t *testing.T) {
		p := NewProtector(nspace, memory.NewKeyEngine())

		pf1 := testutil.Profile{
			UserID:   "kal5430",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}

		// successfully encrypt pii struct & save a copy of encrypted struct
		if err := p.Encrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		encpf1 := pf1

		// try to re-encrypt & make sure that pii field values remain the same
		if err := p.Encrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := encpf1, pf1; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// same logic applies to decrypt...
		if err := p.Decrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		decpf1 := pf1

		if err := p.Decrypt(ctx, &pf1); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := decpf1, pf1; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("crypto-erase personal data", func(t *testing.T) {
		pf := testutil.Profile{
			UserID:   "dal5431",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}
		opf := pf

		// assert personal data are encrypted and changed (to a cipher text)
		if err := p.Encrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := opf.Fullname, pf.Fullname; reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if val := pf.Fullname; !isWireFormatted(val) {
			t.Fatalf("expect %s be wire formatted and encrypted", val)
		}

		// forget subjectID i.e, forget subjectID's encryption key
		if err := p.Forget(ctx, pf.TEST_PII_SubjectID()); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert personal data can't be decrypted and PIIs are replaced with fallback values
		if err := p.Decrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := pf.TEST_PII_Replacement("Fullname"), pf.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := pf.TEST_PII_Replacement("Gender"), pf.Gender; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// assert we can't encrypt new PIIs for a forgotten subjectID
		if want, err := ErrSubjectForgotten, p.Encrypt(ctx, &pf); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got %v", want, err)
		}

		// succefully recover a subjectID encryption material (optional, Key engine may not support it)
		if err := p.Recover(ctx, pf.TEST_PII_SubjectID()); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert we are back to normal
		if err := p.Encrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if err := p.Decrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := pf.TEST_PII_Replacement("Fullname"), pf.Fullname; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := pf.TEST_PII_Replacement("Gender"), pf.Gender; !reflect.DeepEqual(want, got) {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		// forget subject for real, and assert we are unable to recover it
		// p2 := NewProtector(nspace, func(pc *ProtectorConfig) {
		// 	pc.Engine = memory.NewKeyEngine()
		// 	pc.GracefulMode = false
		// })

		p.(*protector).GracefulMode = false

		if err := p.Forget(ctx, pf.TEST_PII_SubjectID()); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, err := ErrCannotRecoverSubject, p.Recover(ctx, pf.TEST_PII_SubjectID()); !errors.Is(err, want) {
			t.Fatalf("expect err be %v, got %v", want, err)
		}
	})
}

func BenchmarkProtector(b *testing.B) {
	nspace := "tenant-d195kla"

	ctx := context.Background()

	p := NewProtector(nspace, memory.NewKeyEngine())

	b.Run("encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pfs := []any{
				&testutil.Profile{
					UserID:   "xal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
				&testutil.Profile{
					UserID:   "kal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
			}
			err := p.Encrypt(ctx, pfs...)
			if err != nil {
				b.Fatal("expect err be nil, got", err)
			}

		}
	})

	b.Run("decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			pfs := []any{
				&testutil.Profile{
					UserID:   "xal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
				&testutil.Profile{
					UserID:   "kal5430",
					Fullname: "Idir Moore",
					Gender:   "M",
					Country:  "MA",
				},
			}
			err := p.Encrypt(ctx, pfs...)
			if err != nil {
				b.Fatal("expect err be nil, got", err)
			}
			b.StartTimer()

			if err := p.Decrypt(ctx, pfs...); err != nil {
				b.Fatal("expect err be nil, got", err)
			}
		}
	})
}

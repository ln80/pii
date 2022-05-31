package pii

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/ln80/pii/testutil"
)

func TestProtector_PackUnpackCypher(t *testing.T) {

	tcs := []struct {
		cypher      string
		isEncrypted bool
	}{
		{
			"",
			false,
		},
		{
			"<pii::>",
			false,
		},
		{
			"<pii::f3:25:7e:44:3f:65",
			false,
		},
		{
			"<PII::f3:25:7e:44:3f:65",
			false,
		},
		{
			"<pii::>f3:25:7e:44:3f:65",
			true,
		},
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
			if tc.isEncrypted {
				if ok := isEncryptedPII(tc.cypher); !ok {
					t.Fatal("expect cypher be encrypted")
				}
				cypher := unpackEncryptedPII(tc.cypher)
				if len(cypher) == 0 {
					t.Fatal("expect unpacked cypher be not empty")
				}
			} else {
				if ok := isEncryptedPII(tc.cypher); ok {
					t.Fatal("expect cypher not be packed")
				}
			}
		})
	}
}
func TestProtector(t *testing.T) {
	ctx := context.Background()

	nspace := "tenantID"

	p := NewProtector(nspace, func(pc *ProtectorConfig) {
		// setup a default protector service backed by an in-memory key engine
	})

	pf1 := testutil.Profile{
		UserID:   "kal5430",
		Fullname: "Idir Moore",
		Gender:   "M",
		Country:  "MA",
	}
	opf1 := pf1

	pf2 := testutil.Profile{
		UserID:   "aze6590",
		Fullname: "Anna Gibz",
		Gender:   "F",
		Country:  "GB",
	}
	opf2 := pf2

	t.Run("encrypt-decrypt personal data with nonsence values", func(t *testing.T) {
		if err := p.Encrypt(ctx); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		ignored := testutil.IgnoredStruct{Val: "value"}
		oignored := ignored

		if err := p.Encrypt(ctx, &ignored); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := ignored, oignored; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}

		if err := p.Encrypt(ctx, &ignored); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := ignored, oignored; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt unsupported type value", func(t *testing.T) {
		tcs := []interface{}{
			nil, pf1, pf2, make(map[string]interface{}),
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

	t.Run("encrypt-decrypt personal data with invalid PII tags", func(t *testing.T) {
		tcs := []interface{}{
			&testutil.InvalidStruct1{},
			&testutil.InvalidStruct2{Val1: "id", Val2: "otherId"},
		}

		want := ErrInvalidTagConfiguration
		for _, value := range tcs {
			err := p.Encrypt(ctx, value)
			if !errors.Is(err, want) {
				t.Errorf("expect err be '%v', got '%v'", want, err)
			}
			if err := p.Decrypt(ctx, value); !errors.Is(err, want) {
				t.Errorf("expect err be '%v', got '%v'", want, err)
			}
		}
	})

	t.Run("encrypt-decrypt personal data with success", func(t *testing.T) {
		if err := p.Encrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert personal data are mutated (to a cypher text)
		if want, got := opf1.Fullname, pf1.Fullname; want == got {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf2.Fullname, pf2.Fullname; want == got {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}

		// assert personal data are mutated back to their plain text values
		if err := p.Decrypt(ctx, &pf1, &pf2); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := opf1.Fullname, pf1.Fullname; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf2.Fullname, pf2.Fullname; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt atomicity", func(t *testing.T) {
		enc := &testutil.UnstableEncrypterMock{
			PointOfFailure: 2,
		}

		p := NewProtector(nspace, func(pc *ProtectorConfig) {
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

		if err := p.Encrypt(ctx, &pf1, &pf2); err == nil {
			t.Fatal("expect err be not nil")
		}

		// expect pii structs to be different from originals
		if want, got := opf1, pf1; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := opf2, pf2; want != got {
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

		if err := p.Decrypt(ctx, &pf1, &pf2); err == nil {
			t.Fatal("expect err be not nil")
		}

		// expect none of pii structs to be decrypted back to normal
		if want, got := opf1, pf1; want == got {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
		if want, got := opf2, pf2; want == got {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}
	})

	t.Run("encrypt-decrypt idempotency", func(t *testing.T) {
		p := NewProtector(nspace)

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
		if want, got := encpf1, pf1; want != got {
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
		if want, got := decpf1, pf1; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})

	t.Run("crypto-shred personal data", func(t *testing.T) {
		pf := testutil.Profile{
			UserID:   "dal5431",
			Fullname: "Idir Moore",
			Gender:   "M",
			Country:  "MA",
		}
		opf := pf

		// assert personal data are ecnrypted & mutated (to a cypher text)
		if err := p.Encrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := opf.Fullname, pf.Fullname; want == got {
			t.Fatalf("expect %v, %v not be equals", want, got)
		}

		// forget subjectID i.e, forget subjectID's encryption key
		if err := p.Forget(ctx, pf.TEST_PII_SubjectID()); err != nil {
			t.Fatal("expect err be nil, got", err)
		}

		// assert personal data can't be decrypted and PIIs are replaced with fallback values
		if err := p.Decrypt(ctx, &pf); err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if want, got := pf.TEST_PII_Replacement("Fullname"), pf.Fullname; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := pf.TEST_PII_Replacement("Gender"), pf.Gender; want != got {
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
		if want, got := pf.TEST_PII_Replacement("Fullname"), pf.Fullname; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
		if want, got := pf.TEST_PII_Replacement("Gender"), pf.Gender; want != got {
			t.Fatalf("expect %v, %v be equals", want, got)
		}
	})
}

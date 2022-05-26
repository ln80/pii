package pii

import (
	"context"
	"errors"
	"testing"

	"github.com/ln80/pii/testutil"
)

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

	t.Run("encrypt-decrypt personal data with non-sence values", func(t *testing.T) {
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

	t.Run("encrypt-decrypt personal data with invalid PII tag's configuration", func(t *testing.T) {
		tcs := []interface{}{
			&testutil.InvalidStruct1{},
			&testutil.InvalidStruct2{Val1: "id", Val2: "otherId"},
		}

		want := ErrInvalidTagConfiguration
		for _, value := range tcs {
			err := p.Encrypt(ctx, value)
			t.Log("err", err)
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

		// assert personal data are mutated back to their original values
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

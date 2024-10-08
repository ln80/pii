package testutil

type Address struct {
	Street string `pii:"data"`
}

type Profile struct {
	UserID   string  `pii:"subjectID"`
	Fullname string  `pii:"data,replace=deleted pii"`
	Gender   string  `pii:"data"`
	Address  Address `pii:"dive"`
	Country  string
}

func (p Profile) TEST_PII_SubjectID() string {
	return p.UserID
}

func (p Profile) TEST_PII_Replacement(piiField string) string {
	switch piiField {
	case "Fullname":
		return "deleted pii"
	}

	return ""
}

type InvalidStruct1 struct {
	Val1 string
	Val2 string `pii:"data"`
}

type InvalidStruct2 struct {
	Val1 string `pii:"subjectID"`
	Val2 string `pii:"subjectID"`
}

type InvalidStruct3 struct {
	Val1 interface{} `pii:"subjectID"`
	Val2 int         `pii:"data"`
}

type IgnoredStruct struct {
	Val string
}

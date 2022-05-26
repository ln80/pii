package testutil

type Profile struct {
	UserID   string `pii:"subjectID"`
	Fullname string `pii:"data,replace=deleted pii"`
	Gender   string `pii:"data"`
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

type IgnoredStruct struct {
	Val string
}

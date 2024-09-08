package pii

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrInvalidWireFormat = errors.New("invalid PII wire format")
)

var (
	wireFormatRegex = regexp.MustCompile(`^<pii:\d*:[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$`)
)

func CheckFormat(str string) error {
	if valid := isWireFormatted(str); !valid {
		return ErrInvalidWireFormat
	}
	return nil
}

func isWireFormatted(str string) bool {
	// return true
	if !strings.HasPrefix(str, "<pii:") {
		return false
	}
	return wireFormatRegex.Match([]byte(str))
}

func wireFormat(subjectID, cipherText string, version ...int) string {
	v := ""
	if len(version) > 0 && version[0] > 1 {
		v = strconv.Itoa(version[0])
	}

	base64SubjectID := base64.StdEncoding.EncodeToString([]byte(subjectID))

	return "<pii:" + v + ":" + base64SubjectID + ":" + cipherText
}

func parseWireFormat(str string) (version int, subjectID string, cipherText string, err error) {
	if err = CheckFormat(str); err != nil {
		// err = fmt.Errorf("%w: %s", err, str)
		// err = fmt.Errorf("%w: %s", err, str)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(str, "<pii:"), ":", 3)

	version = 1
	if len(parts[0]) > 0 {
		version, err = strconv.Atoi(parts[0])
		if err != nil {
			err = errors.Join(ErrInvalidWireFormat, err)
			return
		}
	}
	var subjectBytes []byte
	subjectBytes, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		err = errors.Join(ErrInvalidWireFormat, err)
		return
	}
	subjectID = string(subjectBytes)

	cipherText = parts[2]

	return
}

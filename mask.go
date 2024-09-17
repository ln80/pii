package pii

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
)

// Mask does partially redact PII data using a set of pre defined masks
// for different PII kinds such as `email`, `ipv4_addr`, `credit_card`.
func Mask(structPtr any) error {
	option := func(rc *RedactConfig) {
		rc.RedactFunc = func(fr FieldReplace, val string) (string, error) {
			switch fr.Kind {
			case "email":
				return MaskEmail(val)
			case "credit_card":
				return MaskCreditCard(val)
			case "ipv4_addr":
				return MaskIPv4Addr(val, 1)
			default:
				return defaultRedactFunc(fr, val)
			}
		}
	}
	return Redact(structPtr, option)
}

// MaskEmail redacts the local part of an email address
func MaskEmail(email string) (string, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", errors.New("invalid email format")
	}

	maskedLocal := strings.Repeat("*", len(parts[0]))

	return maskedLocal + "@" + parts[1], nil
}

// MaskCreditCard redacts all digits except the last four in a credit card number
func MaskCreditCard(cardNumber string) (string, error) {
	var digits []rune
	for _, char := range cardNumber {
		if unicode.IsDigit(char) {
			digits = append(digits, char)
		}
	}
	if len(digits) < 4 {
		return "", errors.New("invalid credit card length")
	}

	redacted := strings.Repeat("*", len(digits)-4) + string(digits[len(digits)-4:])

	var result strings.Builder
	nonDigitIndex := 0
	for _, char := range cardNumber {
		if unicode.IsDigit(char) {
			if nonDigitIndex < len(redacted) {
				result.WriteRune(rune(redacted[nonDigitIndex]))
				nonDigitIndex++
			}
		} else {
			result.WriteRune(char)
		}
	}
	return result.String(), nil
}

// maskIPv4 masks the last `n` octets of an IPv4 address with "***".
func MaskIPv4Addr(ip string, octetsToMask int) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || strings.Contains(ip, ":") {
		return "", fmt.Errorf("invalid IPv4 address")
	}

	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", fmt.Errorf("invalid IPv4 address format")
	}

	for i := 4 - octetsToMask; i < 4; i++ {
		octets[i] = "***"
	}

	return strings.Join(octets, "."), nil
}

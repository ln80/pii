package pii

import (
	"errors"
	"net"
)

var (
	ErrInvalidIPAddress = errors.New("invalid IP address")
)

// TruncateIPv4Addr takes an IP v4 address and a number "n" of least bytes to remove and replace with zeros.
//
// It returns the truncated IP address or returns an error if the given IPv4 address is invalid.
//
// It helps to partially pseudonymize the IP address while preserving a prefix.
func TruncateIPv4Addr(ip string, n uint8) (string, error) {
	parsedIP := net.ParseIP(ip).To4()
	if parsedIP == nil {
		return "", ErrInvalidIPAddress
	}

	if n == 0 {
		return ip, nil
	}
	for i := uint8(1); i <= 4 && i <= n; i++ {
		parsedIP[4-i] = byte(0)
	}

	return parsedIP.String(), nil
}

// MustTruncateIPv4Addr ,similar to TruncateIPv4Addr function, truncates the last "n" bytes from the IP v4 address,
// but it panics in case of error instead.
func MustTruncateIPv4Addr(ip string, n uint8) string {
	truncatedIP, err := TruncateIPv4Addr(ip, n)
	if err != nil {
		panic(err)
	}
	return truncatedIP
}

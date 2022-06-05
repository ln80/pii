package pii

import (
	"github.com/Masterminds/semver/v3"
)

type Version string

// VERSION is the current version of the PII Go Module.
const VERSION Version = "v0.1.0"

// Semver parses and returns semver struct.
func (v Version) Semver() *semver.Version {
	return semver.MustParse(string(v))
}

var _ = VERSION.Semver()

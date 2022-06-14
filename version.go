package pii

import (
	"github.com/Masterminds/semver/v3"
)

type version string

// VERSION is the current version of the PII Go Module.
const VERSION version = "v0.2.0"

// Semver parses and returns semver struct.
func (v version) Semver() *semver.Version {
	return semver.MustParse(string(v))
}

var _ = VERSION.Semver()

package options

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Build attestations.
	VerifyBuildAttestation(digests intoto.DigestSet, publishName, builderID, sourceName string) error
}

// BuildVerification defines the configuration to verify
// build attestations.
type BuildVerification struct {
	Verifier AttestationVerifier
}

// Request is metadata about the caller request.
type Request struct {
	Environment *string
}

// ValidationPackage defines the structure holding
// package information to be validated.
type ValidationPackage struct {
	Name        string
	Environment ValidationEnvironment
}

// ValidationEnvironment defines the structure containing
// the policy environment to validate.
type ValidationEnvironment struct {
	AnyOf []string
}

// PolicyValidator defines an interface to validate
// certain fields in the policy.
type PolicyValidator interface {
	ValidatePackage(pkg ValidationPackage) error
}

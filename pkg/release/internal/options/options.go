package options

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Build attestations.
	VerifyBuildAttestation(digests intoto.DigestSet, releaseName, builderID, sourceName string) error
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

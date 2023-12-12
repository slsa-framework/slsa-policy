package options

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Build attestations.
	VerifyBuildAttestation(digests intoto.DigestSet, releaseURI, builderID, sourceURI string) error
}

// BuildVerification defines the configuration to verify
// build attestations.
type BuildVerification struct {
	Verifier    AttestationVerifier
	Environment *string
}

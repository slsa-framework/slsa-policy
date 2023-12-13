package options

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Release attestations.
	VerifyReleaseAttestation(digests intoto.DigestSet, releaseURI, releaserID string) error
}

// ReleaseVerification defines the configuration to verify
// release attestations.
type ReleaseVerification struct {
	Verifier AttestationVerifier
}

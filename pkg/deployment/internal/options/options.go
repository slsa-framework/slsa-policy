package options

import "github.com/laurentsimon/slsa-policy/pkg/utils/intoto"

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Release attestations. The string returned contains the value of the environment, if present.
	VerifyReleaseAttestation(digests intoto.DigestSet, packageName string, environment []string, releaserID string, buildLevel int) (*string, error)
}

// ReleaseVerification defines the configuration to verify
// release attestations.
type ReleaseVerification struct {
	Verifier AttestationVerifier
}

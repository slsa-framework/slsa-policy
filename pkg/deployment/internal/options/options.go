package options

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Release attestations. The string returned contains the value of the environment, if present.
	VerifyReleaseAttestation(packageURI string, environment []string, releaserID string) (*string, error)
}

// ReleaseVerification defines the configuration to verify
// release attestations.
type ReleaseVerification struct {
	Verifier AttestationVerifier
}

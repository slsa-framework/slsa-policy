package options

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Build attestations.
	VerifyBuildAttestation(publicationURI, builderID, sourceURI string) error
}

// BuildVerification defines the configuration to verify
// build attestations.
type BuildVerification struct {
	Verifier    AttestationVerifier
	Environment *string
}

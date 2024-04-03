package options

import "github.com/slsa-framework/slsa-policy/pkg/utils/intoto"

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Publish attestations. The string returned contains the value of the environment, if present.
	VerifyPublishAttestation(digests intoto.DigestSet, packageName string, environment []string, publishrID string, buildLevel int) (*string, error)
}

// PublishVerification defines the configuration to verify
// publish attestations.
type PublishVerification struct {
	Verifier AttestationVerifier
}

// ValidationPackage defines the structure holding
// package information to be validated.
type ValidationPackage struct {
	Name        string
	Environment struct {
		AnyOf []string
	}
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

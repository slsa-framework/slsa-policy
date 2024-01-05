package deployment

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// AttestationVerifierReleaseOptions defines options for
// verifying a release attestation.
type AttestationVerifierReleaseOptions struct {
	// One of ReleaserID or ReleaserIDRegex must be set.
	ReleaserID, ReleaserIDRegex string
	BuildLevel                  int
}

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Release attestation verification. The string returned contains the value of the environment, if present.
	VerifyReleaseAttestation(digests intoto.DigestSet, packageURI string, environment []string, opts AttestationVerifierReleaseOptions) (*string, error)
}

// AttestationVerificationOption defines the configuration to verify
// release attestations.
type AttestationVerificationOption struct {
	Verifier AttestationVerifier
}

// Policy defines the deployment policy.
type Policy struct {
	policy    *internal.Policy
	validator options.PolicyValidator
}

// PolicyOption defines a policy option.
type PolicyOption func(*Policy) error

// This is a helpder class to forward calls between the internal
// classes and the caller.
type internal_verifier struct {
	opts AttestationVerificationOption
}

func (i *internal_verifier) VerifyReleaseAttestation(digests intoto.DigestSet, packageURI string,
	environment []string, releaserID string, buildLevel int) (*string, error) {
	if i.opts.Verifier == nil {
		return nil, fmt.Errorf("%w: verifier is nil", errs.ErrorInvalidInput)
	}
	opts := AttestationVerifierReleaseOptions{
		ReleaserID: releaserID,
		BuildLevel: buildLevel,
	}
	return i.opts.Verifier.VerifyReleaseAttestation(digests, packageURI, environment, opts)
}

// This is a class to forward calls between internal
// classes and the caller for the PolicyValidator interface.
type internal_validator struct {
	validator PolicyValidator
}

func (i *internal_validator) ValidatePackage(pkg options.ValidationPackage) error {
	if i.validator == nil {
		return nil
	}
	return i.validator.ValidatePackage(ValidationPackage{
		Name: pkg.Name,
		Environment: ValidationEnvironment{
			// NOTE: make a copy of the array.
			AnyOf: append([]string{}, pkg.Environment.AnyOf...),
		},
	})
}

// New creates a deployment policy.
func PolicyNew(org io.ReadCloser, projects iterator.NamedReadCloserIterator, opts ...PolicyOption) (*Policy, error) {
	// Initialize a policy with caller options.
	p := new(Policy)
	for _, option := range opts {
		err := option(p)
		if err != nil {
			return nil, err
		}
	}
	policy, err := internal.PolicyNew(org, projects, p.validator)
	if err != nil {
		return nil, err
	}
	p.policy = policy
	return p, nil
}

// SetValidator sets a custom validator.
func SetValidator(validator PolicyValidator) PolicyOption {
	return func(p *Policy) error {
		return p.setValidator(validator)
	}
}

func (p *Policy) setValidator(validator PolicyValidator) error {
	// Construct an internal validator
	// using the caller's public validator interface.
	p.validator = &internal_validator{
		validator: validator,
	}
	return nil
}

// Evaluate evalues the deployment policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, policyPackageName string, policyID string, opts AttestationVerificationOption) PolicyEvaluationResult {
	principal, err := p.policy.Evaluate(digests, policyPackageName, policyID,
		options.ReleaseVerification{
			Verifier: &internal_verifier{
				opts: opts,
			},
		},
	)
	return PolicyEvaluationResult{
		err:       err,
		digests:   digests,
		principal: principal,
	}
}

// Utility function for cosign integration.
func PredicateType() string {
	return predicateType
}

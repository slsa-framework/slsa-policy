package release

import (
	"fmt"
	"io"
	"path"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Build attestations.
	VerifyBuildAttestation(digests intoto.DigestSet, packageName, builderID, sourceURI string) error
}

// BuildVerificationOption defines the configuration to verify
// build attestations.
type BuildVerificationOption struct {
	Verifier AttestationVerifier
}

// RequestOption contains options from the caller.
type RequestOption struct {
	Environment *string
}

// Policy defines the release policy.
type Policy struct {
	policy    *internal.Policy
	validator options.PolicyValidator
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

// PolicyOption defines a policy option.
type PolicyOption func(*Policy) error

// PolicyEvaluationResult defines the result of policy evaluation.
type PolicyEvaluationResult struct {
	level           int
	err             error
	packageName     string
	packageRegistry string
	digests         intoto.DigestSet
	environment     *string
}

// This is a helpder class to forward calls between the internal
// classes and the caller.
type internal_verifier struct {
	buildOpts BuildVerificationOption
}

func (i *internal_verifier) VerifyBuildAttestation(digests intoto.DigestSet, packageName, builderID, sourceURI string) error {
	if i.buildOpts.Verifier == nil {
		return fmt.Errorf("%w: verifier is nil", errs.ErrorInvalidInput)
	}
	return i.buildOpts.Verifier.VerifyBuildAttestation(digests, packageName, builderID, sourceURI)
}

// This is a helper class to forward calls between internal
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

// New creates a release policy.
func PolicyNew(org io.ReadCloser, projects iterator.ReadCloserIterator, opts ...PolicyOption) (*Policy, error) {
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

// Evaluate evalues the release policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageName string, reqOpts RequestOption,
	buildOpts BuildVerificationOption) PolicyEvaluationResult {
	level, err := p.policy.Evaluate(digests, packageName,
		options.Request{
			Environment: reqOpts.Environment,
		},
		options.BuildVerification{
			Verifier: &internal_verifier{
				buildOpts: buildOpts,
			},
		},
	)
	return PolicyEvaluationResult{
		level:       level,
		err:         err,
		packageName: packageName,
		digests:     digests,
		environment: reqOpts.Environment,
	}
}

// Attestation creates a release attestation.
func (r PolicyEvaluationResult) AttestationNew(creatorID string, options ...AttestationCreationOption) (*Creation, error) {
	if r.Error() != nil {
		return nil, fmt.Errorf("%w: evaluation failed. Cannot create attestation", errs.ErrorInternal)
	}
	if err := r.isValid(); err != nil {
		return nil, err
	}
	subject := intoto.Subject{
		Digests: r.digests,
	}
	uri := r.packageName
	if r.packageRegistry != "" {
		uri = path.Join(r.packageRegistry, r.packageName)
	}
	packageDesc := intoto.ResourceDescriptor{
		URI: uri,
		// Version.
	}
	// Set environment if not empty.
	if r.environment != nil {
		packageDesc.Annotations = map[string]interface{}{
			environmentAnnotation: *r.environment,
		}
	}
	// Create the options.
	opts := []AttestationCreationOption{
		// Set SLSA build level.
		SetSlsaBuildLevel(r.level),
	}
	// Enter safe mode.
	opts = append(opts, EnterSafeMode())
	// Add caller options.
	opts = append(opts, options...)
	att, err := CreationNew(creatorID, subject, packageDesc, opts...)
	if err != nil {
		return nil, err
	}
	return att, err
}

func (r PolicyEvaluationResult) Error() error {
	return r.err
}

func (r PolicyEvaluationResult) isValid() error {
	if r.packageName == "" {
		return fmt.Errorf("%w: empty package URI", errs.ErrorInternal)
	}
	return nil
}

// API required by cosign.
func PredicateType() string {
	return predicateType
}

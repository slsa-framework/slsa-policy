package release

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// AttestationVerifier defines an interface to verify attestations.
type AttestationVerifier interface {
	// Build attestations.
	VerifyBuildAttestation(digests intoto.DigestSet, packageURI, builderID, sourceURI string) error
}

// BuildVerificationOption defines the configuration to verify
// build attestations.
type BuildVerificationOption struct {
	Verifier    AttestationVerifier
	Environment *string
}

// Policy defines the release policy.
type Policy struct {
	policy *internal.Policy
}

// PolicyEvaluationResult defines the result of policy evaluation.
type PolicyEvaluationResult struct {
	level       int
	err         error
	packageURI  string
	digests     intoto.DigestSet
	environment *string
}

// This is a helpder class to forward calls between the internal
// classes and the caller.
type internal_verifier struct {
	buildOpts BuildVerificationOption
}

func (i *internal_verifier) VerifyBuildAttestation(digests intoto.DigestSet, packageURI, builderID, sourceURI string) error {
	return i.buildOpts.Verifier.VerifyBuildAttestation(digests, packageURI, builderID, sourceURI)
}

// New creates a release policy.
func PolicyNew(org io.ReadCloser, projects iterator.ReadCloserIterator) (*Policy, error) {
	policy, err := internal.PolicyNew(org, projects)
	if err != nil {
		return nil, err
	}
	return &Policy{
		policy: policy,
	}, nil
}

// Evaluate evalues the release policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageURI string, buildOpts BuildVerificationOption) PolicyEvaluationResult {
	level, err := p.policy.Evaluate(digests, packageURI,
		options.BuildVerification{
			Verifier: &internal_verifier{
				buildOpts: buildOpts,
			},
			Environment: buildOpts.Environment,
		},
	)
	return PolicyEvaluationResult{
		level:       level,
		err:         err,
		packageURI:  packageURI,
		digests:     digests,
		environment: buildOpts.Environment,
	}
}

// TODO: Support safe options: AuthorVersion, Policy, release version.
// Attestation creates a release attestation.
func (r PolicyEvaluationResult) AttestationNew(authorID string, options ...AttestationCreationOption) (*Creation, error) {
	if r.Error() != nil {
		return nil, fmt.Errorf("%w: evaluation failed. Cannot create attestation", errs.ErrorInternal)
	}
	if err := r.isValid(); err != nil {
		return nil, err
	}
	subject := intoto.Subject{
		Digests: r.digests,
	}
	packageDesc := intoto.ResourceDescriptor{
		URI: r.packageURI,
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
	att, err := CreationNew(authorID, subject, packageDesc, opts...)
	if err != nil {
		return nil, err
	}
	return att, err
}

func (r PolicyEvaluationResult) Error() error {
	return r.err
}

func (r PolicyEvaluationResult) isValid() error {
	if r.packageURI == "" {
		return fmt.Errorf("%w: empty package URI", errs.ErrorInternal)
	}
	return nil
}

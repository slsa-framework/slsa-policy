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
	VerifyBuildAttestation(digests intoto.DigestSet, releaseURI, builderID, sourceURI string) error
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
	releaseURI  string
	digests     intoto.DigestSet
	environment *string
}

type internal_verifier struct {
	buildOpts BuildVerificationOption
}

func (i *internal_verifier) VerifyBuildAttestation(digests intoto.DigestSet, releaseURI, builderID, sourceURI string) error {
	return i.buildOpts.Verifier.VerifyBuildAttestation(digests, releaseURI, builderID, sourceURI)
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
func (p *Policy) Evaluate(digests intoto.DigestSet, releaseURI string, buildOpts BuildVerificationOption) PolicyEvaluationResult {
	level, err := p.policy.Evaluate(digests, releaseURI,
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
		releaseURI:  releaseURI,
		digests:     digests,
		environment: buildOpts.Environment,
	}
}

// TODO: Support safe options: AuthorVersion, Policy, release version.
// Attestation creates a release attestation.
func (r PolicyEvaluationResult) AttestationNew(authorID string, options ...AttestationCreationOption) (*Creation, error) {
	if err := r.isValid(); err != nil {
		return nil, err
	}
	subject := intoto.Subject{
		URI:     r.releaseURI,
		Digests: r.digests,
		// Version.
	}
	result, err := r.result()
	if err != nil {
		return nil, err
	}
	// Set SLSA build level.
	var opts []AttestationCreationOption
	if r.IsAllow() {
		opts = append(opts, SetSlsaBuildLevel(r.level))
	}
	// Set environment if not empty.
	if r.environment != nil {
		opts = append(opts, SetEnvironment(*r.environment))
	}
	// Disable editing unsafe fields.
	opts = append(opts, SetSafeMode())
	// Add caller options.
	opts = append(opts, options...)
	att, err := CreationNew(subject, authorID, result, opts...)
	if err != nil {
		return nil, err
	}
	return att, err
}

func (r PolicyEvaluationResult) Error() error {
	return r.err
}

func (r PolicyEvaluationResult) IsAllow() bool {
	return r.err == nil
}

func (r PolicyEvaluationResult) IsDeny() bool {
	return r.err != nil
}

func (r PolicyEvaluationResult) result() (ReleaseResult, error) {
	if err := r.isValid(); err != nil {
		return ReleaseResult(""), err
	}
	if r.IsAllow() {
		return ReleaseResultAllow, nil
	}
	return ReleaseResultDeny, nil
}

func (r PolicyEvaluationResult) isValid() error {
	if r.releaseURI == "" {
		return fmt.Errorf("%w: empty release URI", errs.ErrorInternal)
	}
	if r.environment == nil {
		return fmt.Errorf("%w: empty build options", errs.ErrorInternal)
	}
	return nil
}

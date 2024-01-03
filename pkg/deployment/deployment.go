package deployment

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/project"
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
	// Release attestations. The string returned contains the value of the environment, if present.
	VerifyReleaseAttestation(digests intoto.DigestSet, packageURI string, environment []string, opts AttestationVerifierReleaseOptions) (*string, error)
}

// ReleaseVerificationOption defines the configuration to verify
// release attestations.
type ReleaseVerificationOption struct {
	Verifier AttestationVerifier
}

// Policy defines the deployment policy.
type Policy struct {
	policy *internal.Policy
}

// PolicyEvaluationResult defines the result of policy evaluation.
type PolicyEvaluationResult struct {
	err       error
	digests   intoto.DigestSet
	principal *project.Principal
}

// This is a helpder class to forward calls between the internal
// classes and the caller.
type internal_verifier struct {
	releaseOpts ReleaseVerificationOption
}

func (i *internal_verifier) VerifyReleaseAttestation(digests intoto.DigestSet, packageURI string,
	environment []string, releaserID string, buildLevel int) (*string, error) {
	if i.releaseOpts.Verifier == nil {
		return nil, fmt.Errorf("%w: verifier is nil", errs.ErrorInvalidInput)
	}
	opts := AttestationVerifierReleaseOptions{
		ReleaserID: releaserID,
		BuildLevel: buildLevel,
	}
	return i.releaseOpts.Verifier.VerifyReleaseAttestation(digests, packageURI, environment, opts)
}

// New creates a deployment policy.
func PolicyNew(org io.ReadCloser, projects iterator.NamedReadCloserIterator) (*Policy, error) {
	policy, err := internal.PolicyNew(org, projects)
	if err != nil {
		return nil, err
	}
	return &Policy{
		policy: policy,
	}, nil
}

// Evaluate evalues the deployment policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageURI string, policyID string, releaseOpts ReleaseVerificationOption) PolicyEvaluationResult {
	principal, err := p.policy.Evaluate(digests, packageURI, policyID,
		options.ReleaseVerification{
			Verifier: &internal_verifier{
				releaseOpts: releaseOpts,
			},
		},
	)
	return PolicyEvaluationResult{
		err:       err,
		digests:   digests,
		principal: principal,
	}
}

// Attestation creates a deployment attestation.
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
	// Create the options.
	opts := []AttestationCreationOption{}
	// Enter safe mode.
	opts = append(opts, EnterSafeMode())
	// Add caller options.
	opts = append(opts, options...)
	context := map[string]string{
		contextPrincipal: r.principal.URI,
	}
	att, err := CreationNew(creatorID, subject, contextTypePrincipal, context, opts...)
	if err != nil {
		return nil, err
	}
	return att, err
}

func (r PolicyEvaluationResult) Error() error {
	return r.err
}

func (r PolicyEvaluationResult) isValid() error {
	if r.principal == nil {
		return fmt.Errorf("%w: nil principal", errs.ErrorInternal)
	}
	if r.principal.URI == "" {
		return fmt.Errorf("%w: empty principal URI", errs.ErrorInternal)
	}
	return nil
}

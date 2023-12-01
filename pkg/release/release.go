package release

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/attestation"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal"
	"github.com/laurentsimon/slsa-policy/pkg/release/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

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
func (p *Policy) Evaluate(releaseURI string, buildOpts options.BuildVerification) PolicyEvaluationResult {
	level, digests, err := p.policy.Evaluate(releaseURI, buildOpts)
	return PolicyEvaluationResult{
		level:       level,
		err:         err,
		releaseURI:  releaseURI,
		digests:     digests,
		environment: buildOpts.Environment,
	}
}

// Attestation creates a release attestation.
func (r PolicyEvaluationResult) AttestationNew(authorID string, options ...attestation.CreationOptions) (*attestation.Creation, error) {
	if err := r.isValid(); err != nil {
		return nil, err
	}
	subject := intoto.Subject{
		URI:     r.releaseURI,
		Digests: r.digests,
	}
	result, err := r.result()
	if err != nil {
		return nil, err
	}
	att, err := attestation.CreationNew(subject, authorID, result, options...)
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

func (r PolicyEvaluationResult) result() (attestation.ReleaseResult, error) {
	if err := r.isValid(); err != nil {
		return attestation.ReleaseResult(""), err
	}
	if r.IsAllow() {
		return attestation.ReleaseResultAllow, nil
	}
	return attestation.ReleaseResultDeny, nil
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

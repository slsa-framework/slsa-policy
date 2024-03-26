package deployment

import (
	"fmt"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// PolicyEvaluationResult defines the result of policy evaluation.
type PolicyEvaluationResult struct {
	err       error
	digests   intoto.DigestSet
	principal *project.Principal
}

// AttestationNew creates a deployment attestation.
func (r PolicyEvaluationResult) AttestationNew(options ...AttestationCreationOption) (*Creation, error) {
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
	att, err := CreationNew(subject, contextTypePrincipal, context, opts...)
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

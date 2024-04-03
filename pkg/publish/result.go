package publish

import (
	"fmt"

	"github.com/slsa-framework/slsa-policy/pkg/errs"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
)

// PolicyEvaluationResult defines the result of policy evaluation.
type PolicyEvaluationResult struct {
	level       int
	err         error
	packageDesc intoto.PackageDescriptor
	digests     intoto.DigestSet
	environment *string
	evaluated   bool
}

// Attestation creates a publish attestation.
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
	// Set environment if not empty.
	if r.environment != nil {
		r.packageDesc.Environment = *r.environment
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
	att, err := CreationNew(subject, r.packageDesc, opts...)
	if err != nil {
		return nil, err
	}
	return att, err
}

func (r PolicyEvaluationResult) Error() error {
	return r.err
}

func (r PolicyEvaluationResult) isValid() error {
	if !r.evaluated {
		return fmt.Errorf("%w: evaluation result not ready", errs.ErrorInternal)
	}
	return nil
}

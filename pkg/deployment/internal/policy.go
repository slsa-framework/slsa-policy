package internal

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

type Policy struct {
	orgPolicy       organization.Policy
	projectPolicies map[string]project.Policy
}

func PolicyNew(org io.ReadCloser, projects iterator.NamedReadCloserIterator) (*Policy, error) {
	orgPolicy, err := organization.FromReader(org)
	if err != nil {
		return nil, err
	}
	projectPolicies, err := project.FromReaders(projects, *orgPolicy)
	if err != nil {
		return nil, err
	}
	return &Policy{
		orgPolicy:       *orgPolicy,
		projectPolicies: projectPolicies,
	}, nil
}

func (p *Policy) Evaluate(packageURI, policyID string, releaseOpts options.ReleaseVerification) error {
	if packageURI == "" {
		return fmt.Errorf("%w: package uri is empty", errs.ErrorInvalidInput)
	}
	if policyID == "" {
		return fmt.Errorf("%w: policy id is empty", errs.ErrorInvalidInput)
	}
	// Get the project policy for the artifact.
	projectPolicy, exists := p.projectPolicies[policyID]
	if !exists {
		return fmt.Errorf("%w: policy id (%q) not present in project policies", errs.ErrorNotFound, policyID)
	}

	// Evaluate the org policy.
	err := p.orgPolicy.Evaluate(packageURI, releaseOpts)
	if err != nil {
		return err
	}

	// Evaluate the project policy.
	if err := projectPolicy.Evaluate(packageURI, p.orgPolicy, releaseOpts); err != nil {
		return err
	}
	return nil
}

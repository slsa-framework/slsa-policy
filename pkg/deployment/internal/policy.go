package internal

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

type Policy struct {
	orgPolicy       organization.Policy
	projectPolicies map[string]project.Policy
}

func PolicyNew(org io.ReadCloser, projects iterator.NamedReadCloserIterator, validator options.PolicyValidator) (*Policy, error) {
	orgPolicy, err := organization.FromReader(org)
	if err != nil {
		return nil, err
	}
	projectPolicies, err := project.FromReaders(projects, *orgPolicy, validator)
	if err != nil {
		return nil, err
	}
	return &Policy{
		orgPolicy:       *orgPolicy,
		projectPolicies: projectPolicies,
	}, nil
}

func (p *Policy) Evaluate(digests intoto.DigestSet, packageName, policyID string, releaseOpts options.ReleaseVerification) (*project.Protection, error) {
	if packageName == "" {
		return nil, fmt.Errorf("%w: package name is empty", errs.ErrorInvalidInput)
	}
	if policyID == "" {
		return nil, fmt.Errorf("%w: policy id is empty", errs.ErrorInvalidInput)
	}
	if err := digests.Validate(); err != nil {
		return nil, err
	}
	// Get the project policy for the artifact.
	projectPolicy, exists := p.projectPolicies[policyID]
	if !exists {
		return nil, fmt.Errorf("%w: policy id (%q) not present in project policies", errs.ErrorNotFound, policyID)
	}

	// Evaluate the org policy.
	err := p.orgPolicy.Evaluate(digests, packageName, releaseOpts)
	if err != nil {
		return nil, err
	}

	// Evaluate the project policy.
	protection, err := projectPolicy.Evaluate(digests, packageName, p.orgPolicy, releaseOpts)
	if err != nil {
		return nil, err
	}
	return protection, nil
}

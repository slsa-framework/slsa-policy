package internal

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

type Policy struct {
	orgPolicy       organization.Policy
	projectPolicies map[string]project.Policy
}

func PolicyNew(org io.ReadCloser, projects iterator.ReadCloserIterator, validator options.PolicyValidator) (*Policy, error) {
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

func (p *Policy) Evaluate(digests intoto.DigestSet, packageName string, reqOpts options.Request, buildOpts options.BuildVerification) (int, error) {
	if packageName == "" {
		return -1, fmt.Errorf("%w: package name is empty", errs.ErrorInvalidInput)
	}
	return p.evaluateBuildPolicy(digests, packageName, reqOpts, buildOpts)
}

func (p *Policy) evaluateBuildPolicy(digests intoto.DigestSet, packageName string, reqOpts options.Request, buildOpts options.BuildVerification) (int, error) {
	// Get the project policy for the artifact.
	projectPolicy, exists := p.projectPolicies[packageName]
	if !exists {
		return -1, fmt.Errorf("%w: package's name (%q) not present in project policies", errs.ErrorNotFound, packageName)
	}

	// Evaluate the org policy.
	err := p.orgPolicy.Evaluate(digests, packageName, reqOpts, buildOpts)
	if err != nil {
		return -1, err
	}

	// Evaluate the project policy.
	level, err := projectPolicy.Evaluate(digests, packageName, p.orgPolicy, reqOpts, buildOpts)
	if err != nil {
		return -1, err
	}
	return level, nil
}

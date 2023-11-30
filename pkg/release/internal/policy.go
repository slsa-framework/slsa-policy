package internal

import (
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/release/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

type Policy struct {
	orgPolicy       organization.Policy
	projectPolicies map[string]project.Policy
}

func PolicyNew(org io.ReadCloser, projects iterator.ReadCloserIterator) (*Policy, error) {
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

func (p *Policy) Evaluate(releaseURI string, buildOpts options.BuildVerification) (int, error) {
	if releaseURI == "" {
		return -1, fmt.Errorf("%w: release URI is empty", errs.ErrorInvalidInput)
	}
	return p.evaluateBuildPolicy(releaseURI, buildOpts)
}

func (p *Policy) evaluateBuildPolicy(releaseURI string, buildOpts options.BuildVerification) (int, error) {
	// Get the project policy for the artifact.
	projectPolicy, exists := p.projectPolicies[releaseURI]
	if !exists {
		return -1, fmt.Errorf("%w: release's uri (%q) not present in project policies", errs.ErrorNotFound, releaseURI)
	}

	// Evaluate the org policy first.
	err := p.orgPolicy.Evaluate(releaseURI, buildOpts)
	if err != nil {
		return -1, err
	}

	// Evaluate the project policy first.
	level, err := projectPolicy.Evaluate(releaseURI, p.orgPolicy, buildOpts)
	if err != nil {
		return -1, err
	}

	return level, nil
}

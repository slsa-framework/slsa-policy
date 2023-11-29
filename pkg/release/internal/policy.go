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

func New(org io.ReadCloser, projects iterator.ReadCloserIterator) (*Policy, error) {
	orgPolicy, err := organization.FromReader(org)
	if err != nil {
		return nil, err
	}
	projectPolicies, err := project.FromReaders(projects, *orgPolicy)
	return &Policy{
		orgPolicy:       *orgPolicy,
		projectPolicies: projectPolicies,
	}, nil
}

func (p *Policy) Evaluate(publicationURI string, buildConfig options.BuildVerificationConfig) error {
	if publicationURI == "" {
		return fmt.Errorf("%w: publication URI is empty", errs.ErrorInvalidInput)
	}
	return p.evaluateBuildPolicy(publicationURI, buildConfig)
}

func (p *Policy) evaluateBuildPolicy(publicationURI string, buildConfig options.BuildVerificationConfig) error {
	if buildConfig.SourceURI == "" {
		return fmt.Errorf("%w: build config's source URI is empty", errs.ErrorInvalidInput)
	}
	if buildConfig.BuilderID == "" {
		return fmt.Errorf("%w: build config's builder ID is empty", errs.ErrorInvalidInput)
	}
	if buildConfig.Environment != nil && *buildConfig.Environment == "" {
		return fmt.Errorf("%w: build config's environment is empty", errs.ErrorInvalidInput)
	}

	// Get the project policy for the artifact.
	projectPolicy, exists := p.projectPolicies[publicationURI]
	if !exists {
		return fmt.Errorf("%w: publication's uri (%q) not present in project policies", errs.ErrorNotFound, publicationURI)
	}

	// Evaluate the org policy first.
	err := p.orgPolicy.Evaluate(publicationURI)
	if err != nil {
		return err
	}

	// Evaluate the project policy first.
	err = projectPolicy.Evaluate(publicationURI, p.orgPolicy, buildConfig.Verifier)
	if err != nil {
		return err
	}

	return nil
}

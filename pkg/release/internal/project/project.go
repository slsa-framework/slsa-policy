package project

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/exp/slices"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// Repository defines the repository.
type Repository struct {
	URI string `json:"require_slsa_builder"`
}

// BuildRequirements defines the build requirements.
type BuildRequirements struct {
	RequireSlsaBuilder string     `json:"require_slsa_builder"`
	Repository         Repository `json:"repository"`
}

// Environment defines the target environment.
type Environment struct {
	AnyOf []string `json:"any_of"`
}

// Publication defines pubication metadata, such as
// the URI and the target environment.
type Publication struct {
	URI         string      `json:"uri"`
	Environment Environment `json:"environment"`
}

// Policy defines the policy.
type Policy struct {
	Format            int               `json:"format"`
	Publication       Publication       `json:"publication"`
	BuildRequirements BuildRequirements `json:"build"`
}

func fromReader(reader io.ReadCloser, builderNames []string) (*Policy, error) {
	// NOTE: see https://yourbasic.org/golang/io-reader-interface-explained.
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	defer reader.Close()
	var project Policy
	if err := json.Unmarshal(content, &project); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if err := project.validate(builderNames); err != nil {
		return nil, err
	}
	return &project, nil
}

// validate validates the format of the policy.
func (p *Policy) validate(builderNames []string) error {
	if err := p.validateFormat(); err != nil {
		return err
	}
	if err := p.validatePublication(); err != nil {
		return err
	}
	if err := p.validateBuildRequirements(builderNames); err != nil {
		return err
	}
	return nil
}

func (p *Policy) validateFormat() error {
	// Format must be 1.
	if p.Format != 1 {
		return fmt.Errorf("%w: invalid format (%q). Must be 1", errs.ErrorInvalidField, p.Format)
	}
	return nil
}

func (p *Policy) validatePublication() error {
	// Publication must have a non-empty URI.
	if p.Publication.URI == "" {
		return fmt.Errorf("%w: publication's uri is empty", errs.ErrorInvalidField)
	}
	// Environment field, if set, must contain non-empty values.
	for i := range p.Publication.Environment.AnyOf {
		val := &p.Publication.Environment.AnyOf[i]
		if *val == "" {
			return fmt.Errorf("%w: publication's any_of value has an empty field", errs.ErrorInvalidField)
		}
	}
	return nil
}

func (p *Policy) validateBuildRequirements(builderNames []string) error {
	// SLSA builder
	//	1) must be set
	//	2) must contain one the builders configued by the organization-level policy
	//	3) must contain a repository URI.
	if len(builderNames) == 0 {
		return fmt.Errorf("%w: builder names are empty", errs.ErrorInvalidInput)
	}
	if p.BuildRequirements.RequireSlsaBuilder == "" {
		return fmt.Errorf("%w: build's require_slsa_builder is not defined", errs.ErrorInvalidField)
	}
	if !slices.Contains(builderNames, p.BuildRequirements.RequireSlsaBuilder) {
		return fmt.Errorf("%w: build's require_slsa_builder has unexpected value (%q). Must be one of %q",
			errs.ErrorInvalidField, p.BuildRequirements.RequireSlsaBuilder, builderNames)
	}
	if p.BuildRequirements.Repository.URI == "" {
		return fmt.Errorf("%w: build's repository URI is not defined", errs.ErrorInvalidField)
	}
	return nil
}

// FromReaders creates a set of policies keyed by their publication URI (and if present, the environment).
func FromReaders(readers iterator.ReadCloserIterator, orgPolicy organization.Policy) (map[string]Policy, error) {
	policies := make(map[string]Policy)
	for readers.HasNext() {
		reader := readers.Next()
		// NOTE: fromReader() calls validates that the builder used are consistent
		// with the org policy.
		policy, err := fromReader(reader, orgPolicy.RootBuilderNames())
		if err != nil {
			return nil, err
		}
		// TODO: Re-visit what we consider unique. It maye require some tweaks to support
		// different environments in different files.
		uri := policy.Publication.URI
		if _, exists := policies[uri]; exists {
			return nil, fmt.Errorf("%w: publication's uri (%q) is defined more than once", errs.ErrorInvalidField, uri)
		}
		policies[uri] = *policy

	}
	//TODO: add test for this.
	if readers.Error() != nil {
		return nil, fmt.Errorf("failed to read policy: %w", readers.Error())
	}
	return policies, nil
}

// Evaluate evaluates the policy.
func (p *Policy) Evaluate(publicationURI string, orgPolicy organization.Policy,
	buildConfig options.BuildVerificationConfig) error {
	// Nothing to do.
	return nil
}

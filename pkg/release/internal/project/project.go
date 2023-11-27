package project

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/exp/slices"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
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

func FromFile(fn string, builderNames []string) (*Policy, error) {
	content, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to read organization policy: %w", err)
	}
	return FromBytes(content, builderNames)
}

// FromBytes creates a new instance of a Policy from bytes.
func FromBytes(content []byte, builderNames []string) (*Policy, error) {
	var project Policy
	if err := json.Unmarshal(content, &project); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if err := project.Validate(builderNames); err != nil {
		return nil, err
	}
	return &project, nil
}

// Validate validates the format of the policy.
func (p *Policy) Validate(builderNames []string) error {
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

// // TODO
// func FromDir(dir, orgFile string) ([]Policy, error) {
// 	// TODO: list files
// 	// validate for unique artifact across all files.
// 	return nil, nil
// }

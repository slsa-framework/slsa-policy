package organization

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
)

// Root defines a trusted root.
type Root struct {
	ID        *string `json:"id"`
	Name      *string `json:"name"`
	SlsaLevel *int    `json:"slsa_level"`
}

// Roots defines a set of truted roots.
type Roots struct {
	Build []Root `json:"build"`
}

// BuildRequirements defines the build requirements.
type BuildRequirements struct {
	RequireSlsaLevel *int `json:"require_slsa_level"`
}

// Policy defines the policy.
type Policy struct {
	Format            int               `json:"format"`
	Roots             Roots             `json:"roots"`
	BuildRequirements BuildRequirements `json:"build"`
}

// New creates a new instance of a Policy.
func New(fn string) (*Policy, error) {
	var org Policy
	content, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to read organization policy: %w", err)
	}
	if err := json.Unmarshal(content, &org); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if err := org.Validate(); err != nil {
		return nil, err
	}
	return &org, nil
}

// Validate validates the format of the policy.
func (p *Policy) Validate() error {
	if err := p.validateFormat(); err != nil {
		return err
	}
	if err := p.validateBuildRoots(); err != nil {
		return err
	}
	if err := p.validateBuildRequirements(); err != nil {
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

func (p *Policy) validateBuildRoots() error {
	// There must be at least one build root.
	if len(p.Roots.Build) == 0 {
		return fmt.Errorf("%w: build's roots are not defined", errs.ErrorInvalidField)
	}
	// Each root must have all its fields defined.
	// Also validate that
	//  1) the names given to builders are unique
	//  2) the ids do not repeat
	names := make(map[string]bool)
	ids := make(map[string]bool)
	for i := range p.Roots.Build {
		build := &p.Roots.Build[i]
		// ID must be defined and non-empty.
		if build.ID == nil || *build.ID == "" {
			return fmt.Errorf("%w: build's id is not defined or is empty", errs.ErrorInvalidField)
		}
		// ID must be unique.
		if _, exists := ids[*build.ID]; exists {
			return fmt.Errorf("%w: build's name (%q) is defined more than once", errs.ErrorInvalidField, *build.ID)
		}
		ids[*build.ID] = true
		// Name must be defined and non-empty.
		if build.Name == nil || *build.Name == "" {
			return fmt.Errorf("%w: build's name is not defined or is empty", errs.ErrorInvalidField)
		}
		// Name must be unique.
		if _, exists := names[*build.Name]; exists {
			return fmt.Errorf("%w: build's name (%q) is defined more than once", errs.ErrorInvalidField, *build.Name)
		}
		names[*build.Name] = true
		// Level must be defined.
		if build.SlsaLevel == nil {
			return fmt.Errorf("%w: build's slsa_level is not defined", errs.ErrorInvalidField)
		}
		// Level must be in the corre range.
		if *build.SlsaLevel < 0 || *build.SlsaLevel > 4 {
			return fmt.Errorf("%w: build's slsa_level is invalid (%d). Must satisfy 0 <= slsa_level <= 4",
				errs.ErrorInvalidField, *build.SlsaLevel)
		}
	}
	return nil
}

func (p *Policy) validateBuildRequirements() error {
	// Build requirements must be defined.
	if p.BuildRequirements.RequireSlsaLevel == nil {
		return fmt.Errorf("%w: build's require_slsa_level is not defined", errs.ErrorInvalidField)
	}
	// Level must be in the corre range.
	if *p.BuildRequirements.RequireSlsaLevel < 0 || *p.BuildRequirements.RequireSlsaLevel > 4 {
		return fmt.Errorf("%w: build requirements's require_slsa_level is invalid (%d). Must satisfy 0 <= slsa_level <= 4",
			errs.ErrorInvalidField, *p.BuildRequirements.RequireSlsaLevel)
	}
	return nil
}

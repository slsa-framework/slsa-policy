package organization

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// Root defines a trusted root.
type Root struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SlsaLevel *int   `json:"slsa_level"`
	// TODO: list of repositories the builder is allowed to attest to:
	// example: GitHub can attest to github.com/* only, GCB can attest to github.com/*
	// gitlab.com/*, etc.
}

// Roots defines a set of truted roots.
type Roots struct {
	Build []Root `json:"build"`
}

// Policy defines the policy.
type Policy struct {
	Format int   `json:"format"`
	Roots  Roots `json:"roots"`
}

// FromReader creates a new instance of a Policy from an IO reader.
func FromReader(reader io.ReadCloser) (*Policy, error) {
	// NOTE: see https://yourbasic.org/golang/io-reader-interface-explained.
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("[organization] failed to read: %w", err)
	}
	defer reader.Close()
	var org Policy
	if err := json.Unmarshal(content, &org); err != nil {
		return nil, fmt.Errorf("[organization] failed to unmarshal: %w", err)
	}
	if err := org.validate(); err != nil {
		return nil, err
	}
	return &org, nil
}

// validate validates the format of the policy.
func (p *Policy) validate() error {
	if err := p.validateFormat(); err != nil {
		return err
	}
	if err := p.validateBuildRoots(); err != nil {
		return err
	}
	return nil
}

func (p *Policy) validateFormat() error {
	// Format must be 1.
	if p.Format != 1 {
		return fmt.Errorf("[organization] %w: invalid format (%q). Must be 1", errs.ErrorInvalidField, p.Format)
	}
	return nil
}

func (p *Policy) validateBuildRoots() error {
	// There must be at least one build root.
	if len(p.Roots.Build) == 0 {
		return fmt.Errorf("[organization] %w: build's roots are not defined", errs.ErrorInvalidField)
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
		if build.ID == "" {
			return fmt.Errorf("[organization] %w: build's id is empty", errs.ErrorInvalidField)
		}
		// ID must be unique.
		if _, exists := ids[build.ID]; exists {
			return fmt.Errorf("[organization] %w: build's name (%q) is defined more than once", errs.ErrorInvalidField, build.ID)
		}
		ids[build.ID] = true
		// Name must be defined and non-empty.
		if build.Name == "" {
			return fmt.Errorf("[organization] %w: build's name is empty", errs.ErrorInvalidField)
		}
		// Name must be unique.
		if _, exists := names[build.Name]; exists {
			return fmt.Errorf("[organization] %w: build's name (%q) is defined more than once", errs.ErrorInvalidField, build.Name)
		}
		names[build.Name] = true
		// Level must be defined.
		if build.SlsaLevel == nil {
			return fmt.Errorf("[organization] %w: build's slsa_level is not defined", errs.ErrorInvalidField)
		}
		// Level must be in the corre range.
		if *build.SlsaLevel < 0 || *build.SlsaLevel > 4 {
			return fmt.Errorf("[organization] %w: build's slsa_level is invalid (%d). Must satisfy 0 <= slsa_level <= 4",
				errs.ErrorInvalidField, *build.SlsaLevel)
		}
	}
	return nil
}

// BuilderNames returns the list of trusted builder names.
func (p *Policy) RootBuilderNames() []string {
	var names []string
	for i := range p.Roots.Build {
		builder := &p.Roots.Build[i]
		names = append(names, builder.Name)
	}
	return names
}

func (p *Policy) BuilderID(builderName string) (string, error) {
	for i := range p.Roots.Build {
		builder := &p.Roots.Build[i]
		if builderName == builder.Name {
			return builder.ID, nil
		}
	}
	return "", fmt.Errorf("[organization] %w: builder ID (%q) is not defined", errs.ErrorMismatch, builderName)
}

func (p *Policy) BuilderSlsaLevel(builderName string) int {
	for i := range p.Roots.Build {
		builder := &p.Roots.Build[i]
		if builderName == builder.Name {
			return *builder.SlsaLevel
		}
	}
	// This should never happen.
	return -1
}

// Evaluate evaluates the policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageName string, reqOpts options.Request, buildOpts options.BuildVerification) error {
	// Nothing to do.
	return nil
}

package organization

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// Root defines a trusted root.
type Root struct {
	ID    string `json:"id"`
	Build Build  `json:"build"`
	// TODO: Have a field to indicate which package Names the publishr is allowed to
	// attest to. This assumes every organization has a central registry to make their
	// publishs accessible.
}

// Build defines the build metadata.
type Build struct {
	MaxSlsaLevel *int `json:"max_slsa_level"`
}

// Roots defines a set of truted roots.
type Roots struct {
	Publish []Root `json:"publish"`
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
	if err := p.validatePublishRoots(); err != nil {
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

func (p *Policy) validatePublishRoots() error {
	// There must be at least one publish root.
	if len(p.Roots.Publish) == 0 {
		return fmt.Errorf("[organization] %w: publish's roots are not defined", errs.ErrorInvalidField)
	}
	// Each root must have all its fields defined.
	// Also validate that
	//  2) the ids do not repeat
	ids := make(map[string]bool)
	for i := range p.Roots.Publish {
		publish := &p.Roots.Publish[i]
		// ID must be defined and non-empty.
		if publish.ID == "" {
			return fmt.Errorf("[organization] %w: publish's id is empty", errs.ErrorInvalidField)
		}
		// ID must be unique.
		if _, exists := ids[publish.ID]; exists {
			return fmt.Errorf("[organization] %w: publish's name (%q) is defined more than once", errs.ErrorInvalidField, publish.ID)
		}
		ids[publish.ID] = true
		// Build Level must be defined.
		if publish.Build.MaxSlsaLevel == nil {
			return fmt.Errorf("[organization] %w: publish's max_slsa_level is not defined", errs.ErrorInvalidField)
		}
		// Level must be in the corre range.
		if *publish.Build.MaxSlsaLevel < 0 || *publish.Build.MaxSlsaLevel > 4 {
			return fmt.Errorf("[organization] %w: publish's max_slsa_level is invalid (%d). Must satisfy 0 <= slsa_level <= 4",
				errs.ErrorInvalidField, *publish.Build.MaxSlsaLevel)
		}
	}
	return nil
}

func (p *Policy) MaxBuildSlsaLevel() int {
	max := -1
	for i := range p.Roots.Publish {
		publishr := &p.Roots.Publish[i]
		if *publishr.Build.MaxSlsaLevel > max {
			max = *publishr.Build.MaxSlsaLevel
		}
	}
	return max
}

// Evaluate evaluates the policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageName string, publishOpts options.PublishVerification) error {
	// Nothing to do.
	return nil
}

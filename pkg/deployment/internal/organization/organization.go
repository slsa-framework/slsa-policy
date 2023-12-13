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
	Name  string `json:"name"`
	Build Build  `json:"build"`
}

// Build defines the build metadata.
type Build struct {
	MaxSlsaLevel *int `json:"max_slsa_level"`
}

// Roots defines a set of truted roots.
type Roots struct {
	Release []Root `json:"release"`
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
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	defer reader.Close()
	var org Policy
	if err := json.Unmarshal(content, &org); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
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
	if err := p.validateReleaseRoots(); err != nil {
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

func (p *Policy) validateReleaseRoots() error {
	// There must be at least one release root.
	if len(p.Roots.Release) == 0 {
		return fmt.Errorf("%w: release's roots are not defined", errs.ErrorInvalidField)
	}
	// Each root must have all its fields defined.
	// Also validate that
	//  1) the names given to releaseers are unique
	//  2) the ids do not repeat
	names := make(map[string]bool)
	ids := make(map[string]bool)
	for i := range p.Roots.Release {
		release := &p.Roots.Release[i]
		// ID must be defined and non-empty.
		if release.ID == "" {
			return fmt.Errorf("%w: release's id is empty", errs.ErrorInvalidField)
		}
		// ID must be unique.
		if _, exists := ids[release.ID]; exists {
			return fmt.Errorf("%w: release's name (%q) is defined more than once", errs.ErrorInvalidField, release.ID)
		}
		ids[release.ID] = true
		// Name must be defined and non-empty.
		if release.Name == "" {
			return fmt.Errorf("%w: release's name is empty", errs.ErrorInvalidField)
		}
		// Name must be unique.
		if _, exists := names[release.Name]; exists {
			return fmt.Errorf("%w: release's name (%q) is defined more than once", errs.ErrorInvalidField, release.Name)
		}
		names[release.Name] = true
		// Build Level must be defined.
		if release.Build.MaxSlsaLevel == nil {
			return fmt.Errorf("%w: release's max_slsa_level is not defined", errs.ErrorInvalidField)
		}
		// Level must be in the corre range.
		if *release.Build.MaxSlsaLevel < 0 || *release.Build.MaxSlsaLevel > 4 {
			return fmt.Errorf("%w: release's max_slsa_level is invalid (%d). Must satisfy 0 <= slsa_level <= 4",
				errs.ErrorInvalidField, *release.Build.MaxSlsaLevel)
		}
	}
	return nil
}

// ReleaseerNames returns the list of trusted releaseer names.
func (p *Policy) RootReleaserNames() []string {
	var names []string
	for i := range p.Roots.Release {
		releaser := &p.Roots.Release[i]
		names = append(names, releaser.Name)
	}
	return names
}

func (p *Policy) ReleaserID(releaserName string) (string, error) {
	for i := range p.Roots.Release {
		releaseer := &p.Roots.Release[i]
		if releaserName == releaseer.Name {
			return releaseer.ID, nil
		}
	}
	return "", fmt.Errorf("%w: releaseer ID (%q) is not defined", errs.ErrorMismatch, releaserName)
}

func (p *Policy) ReleaserBuildMaxSlsaLevel(releaserName string) int {
	for i := range p.Roots.Release {
		releaser := &p.Roots.Release[i]
		if releaserName == releaser.Name {
			return *releaser.Build.MaxSlsaLevel
		}
	}
	// This should never happen.
	return -1
}

// Evaluate evaluates the policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageURI string, releaseOpts options.ReleaseVerification) error {
	// Nothing to do.
	return nil
}

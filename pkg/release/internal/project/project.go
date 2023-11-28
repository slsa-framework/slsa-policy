package project

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/exp/slices"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
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

func fromReader(reader io.Reader, builderNames []string) (*Policy, error) {
	// NOTE: see https://yourbasic.org/golang/io-reader-interface-explained.
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
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

// FromReaders creates a set of policies keyed by their publication URI (and if present, the environment).
func FromReaders(readers iterator.ReaderIterator, orgPolicy organization.Policy) (map[string]Policy, error) {
	policies := make(map[string]Policy)
	for readers.HasNext() {
		reader := readers.Next()
		// NOTE: fromReader() calls validates that the builder used are consistent
		// with the org policy.
		policy, err := fromReader(reader, orgPolicy.RootBuilderNames())
		if err != nil {
			return nil, err
		}
		// Publication URI must be defined only once.
		for i := range policy.Publication.Environment.AnyOf {
			env := &policy.Publication.Environment.AnyOf[i]
			uri := fmt.Sprintf("%s_%s", policy.Publication.URI, *env)
			if _, exists := policies[uri]; exists {
				return nil, fmt.Errorf("%w: publication's uri (%q) is defined more than once", errs.ErrorInvalidField, uri)
			}
			policies[uri] = *policy
		}
		if len(policy.Publication.Environment.AnyOf) == 0 {
			uri := policy.Publication.URI
			if _, exists := policies[uri]; exists {
				return nil, fmt.Errorf("%w: publication's uri (%q) is defined more than once", errs.ErrorInvalidField, uri)
			}
			policies[uri] = *policy
		}
	}
	if readers.Error() != nil {
		return nil, fmt.Errorf("failed to read policy: %w", readers.Error())
	}
	return policies, nil
	// TODO: use URI + environment to key the structure:
	// URI_env1, URI_env2, etc. Look up will be faster.
	// And we can easily tell if there's overlap or not.
	// if env is empty, we'll...
	// need a map[URI_env] = policy
	// TODO: artifact + dev must come frm the same folder?
	// I think we only want once, taht's it. if use env,
	// must be in a sigle file anyway.
	// var policies []Policy
	// err := filepath.Walk(".",
	// 	func(path string, info os.FileInfo, err error) error {
	// 		if err != nil {
	// 			return err
	// 		}
	// 		absPath, err := filepath.Abs(path)
	// 		if err != nil {
	// 			return fmt.Errorf("failed to read absolute policy path: %w", err)
	// 		}
	// 		if absPath == orgPolicy.Path() {
	// 			return nil
	// 		}
	//		files = append(files, absPath)
	// 		fmt.Println(path, info.Size())

	// 		return nil
	// 	})
	// validate for unique artifact across all files.
	// use orgPolicy.Path()
	// use RootBuilderNames()
	//return nil, nil
}

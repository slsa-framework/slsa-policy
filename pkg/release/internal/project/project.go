package project

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"slices"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// Repository defines the repository.
type Repository struct {
	URI string `json:"uri"`
}

// BuildRequirements defines the build requirements.
type BuildRequirements struct {
	RequireSlsaBuilder string     `json:"require_slsa_builder"`
	Repository         Repository `json:"repository"`
}

// Environment defines the target environment.
type Environment struct {
	AnyOf []string `json:"any_of,omitempty"`
}

// Package defines publication metadata, such as
// the URI and the target environment.
type Package struct {
	URI         string      `json:"uri"`
	Environment Environment `json:"environment,omitempty"`
}

// Policy defines the policy.
type Policy struct {
	Format            int               `json:"format"`
	Package           Package           `json:"package"`
	BuildRequirements BuildRequirements `json:"build"`
}

func fromReader(reader io.ReadCloser, builderNames []string) (*Policy, error) {
	// NOTE: see https://yourbasic.org/golang/io-reader-interface-explained.
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("[projects] failed to read: %w", err)
	}
	defer reader.Close()
	var project Policy
	if err := json.Unmarshal(content, &project); err != nil {
		return nil, fmt.Errorf("[projects] failed to unmarshal: %w", err)
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
	if err := p.validatePackage(); err != nil {
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
		return fmt.Errorf("[projects] %w: invalid format (%q). Must be 1", errs.ErrorInvalidField, p.Format)
	}
	return nil
}

func (p *Policy) validatePackage() error {
	// Package must have a non-empty URI.
	if p.Package.URI == "" {
		return fmt.Errorf("[projects] %w: package's uri is empty", errs.ErrorInvalidField)
	}
	// Environment field, if set, must contain non-empty values.
	for i := range p.Package.Environment.AnyOf {
		val := &p.Package.Environment.AnyOf[i]
		if *val == "" {
			return fmt.Errorf("[projects] %w: package's any_of value has an empty field", errs.ErrorInvalidField)
		}
	}
	return nil
}

func (p *Policy) validateBuildRequirements(builderNames []string) error {
	// SLSA builder
	//	1) must be set
	//	2) must contain one the builders configured by the organization-level policy
	//	3) must contain a repository URI.
	if len(builderNames) == 0 {
		return fmt.Errorf("[projects] %w: builder names are empty", errs.ErrorInvalidInput)
	}
	if p.BuildRequirements.RequireSlsaBuilder == "" {
		return fmt.Errorf("[projects] %w: build's require_slsa_builder is not defined", errs.ErrorInvalidField)
	}
	if !slices.Contains(builderNames, p.BuildRequirements.RequireSlsaBuilder) {
		return fmt.Errorf("[projects] %w: build's require_slsa_builder has unexpected value (%q). Must be one of %q",
			errs.ErrorInvalidField, p.BuildRequirements.RequireSlsaBuilder, builderNames)
	}
	if p.BuildRequirements.Repository.URI == "" {
		return fmt.Errorf("[projects] %w: build's repository URI is not defined", errs.ErrorInvalidField)
	}
	return nil
}

// FromReaders creates a set of policies keyed by their package URI (and if present, the environment).
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
		// If we want to support multiple files, they should all have the environment defined or none
		// should.
		uri := policy.Package.URI
		if _, exists := policies[uri]; exists {
			return nil, fmt.Errorf("[projects] %w: package's uri (%q) is defined more than once", errs.ErrorInvalidField, uri)
		}
		policies[uri] = *policy

	}
	//TODO: add test for this.
	if readers.Error() != nil {
		return nil, fmt.Errorf("[projects] failed to read policy: %w", readers.Error())
	}
	return policies, nil
}

// Evaluate evaluates the policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageURI string,
	orgPolicy organization.Policy, buildOpts options.BuildVerification) (int, error) {
	if buildOpts.Verifier == nil {
		return -1, fmt.Errorf("[projects] %w: verifier is empty", errs.ErrorInvalidInput)
	}
	// If the policy has environment defined, the request must contain an environment.
	if len(p.Package.Environment.AnyOf) > 0 && (buildOpts.Environment == nil || *buildOpts.Environment == "") {
		return -1, fmt.Errorf("[projects] %w: build config's environment is empty but the policy has it defined (%q)",
			errs.ErrorInvalidInput, p.Package.Environment.AnyOf)
	}
	// If the policy has no environment defined, the request must not contain an environment.
	if len(p.Package.Environment.AnyOf) == 0 && buildOpts.Environment != nil {
		return -1, fmt.Errorf("[projects] %w: build config's environment is set (%q) but the policy has none defined",
			errs.ErrorInvalidInput, *buildOpts.Environment)
	}
	// Verify the environment and request match.
	if buildOpts.Environment != nil {
		if *buildOpts.Environment == "" {
			return -1, fmt.Errorf("[projects] %w: build config's environment is empty", errs.ErrorInvalidInput)
		}
		if !slices.Contains(p.Package.Environment.AnyOf, *buildOpts.Environment) {
			return -1, fmt.Errorf("[projects] %w: failed to verify artifact (%q) for environment (%q): not defined in policy",
				errs.ErrorNotFound, packageURI, *buildOpts.Environment)
		}
	}
	// Validate digests.
	if err := digests.Validate(); err != nil {
		return -1, err
	}
	// Verify build attestations.
	builderID, err := orgPolicy.BuilderID(p.BuildRequirements.RequireSlsaBuilder)
	if err != nil {
		return -1, err
	}
	err = buildOpts.Verifier.VerifyBuildAttestation(digests, packageURI, builderID, p.BuildRequirements.Repository.URI)
	if err != nil {
		return -1, fmt.Errorf("[projects] %w: failed to verify artifact (%q) with builder ID (%q) source URI (%q) digests (%q): %w",
			errs.ErrorVerification, packageURI, p.BuildRequirements.RequireSlsaBuilder,
			p.BuildRequirements.Repository.URI, digests, err)
	}

	return orgPolicy.BuilderSlsaLevel(p.BuildRequirements.RequireSlsaBuilder), nil
}

package project

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"slices"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// BuildRequirements defines the build requirements.
type BuildRequirements struct {
	RequireSlsaLevel *int `json:"require_slsa_level"`
}

// Environment defines the target environment.
type Environment struct {
	AnyOf []string `json:"any_of"`
}

// Package defines publication metadata, such as
// the name and the target environment.
type Package struct {
	Name        string      `json:"name"`
	Environment Environment `json:"environment"`
}

type Protection struct {
	ServiceAccount string `json:"service_account"`
}

// Policy defines the policy.
type Policy struct {
	Format            int                     `json:"format"`
	Protection        Protection              `json:"protection"`
	Packages          []Package               `json:"packages"`
	BuildRequirements BuildRequirements       `json:"build"`
	validator         options.PolicyValidator `json:"-"`
}

// PolicyOption defines a policy option.
type PolicyOption func(*Policy) error

func fromReader(reader io.ReadCloser, maxBuildLevel int, validator options.PolicyValidator) (*Policy, error) {
	// NOTE: see https://yourbasic.org/golang/io-reader-interface-explained.
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("[project] failed to read: %w", err)
	}
	defer reader.Close()
	var project Policy
	if err := json.Unmarshal(content, &project); err != nil {
		return nil, fmt.Errorf("[project] failed to unmarshal: %w", err)
	}
	project.validator = validator
	if err := project.validate(maxBuildLevel); err != nil {
		return nil, err
	}
	return &project, nil
}

// validate validates the format of the policy.
func (p *Policy) validate(maxBuildLevel int) error {
	if err := p.validateFormat(); err != nil {
		return err
	}
	if err := p.validateProtection(); err != nil {
		return err
	}
	if err := p.validatePackages(); err != nil {
		return err
	}
	if err := p.validateBuildRequirements(maxBuildLevel); err != nil {
		return err
	}
	return nil
}

func (p *Policy) validateFormat() error {
	// Format must be 1.
	if p.Format != 1 {
		return fmt.Errorf("[project] %w: invalid format (%q). Must be 1", errs.ErrorInvalidField, p.Format)
	}
	return nil
}

func (p *Policy) validateProtection() error {
	if p.Protection.ServiceAccount == "" {
		return fmt.Errorf("[project] %w: empty protection service_account", errs.ErrorInvalidField)
	}
	return nil
}

func (p *Policy) validatePackages() error {
	if len(p.Packages) == 0 {
		return fmt.Errorf("[project] %w: no packages", errs.ErrorInvalidField)
	}
	packages := make(map[string]bool, len(p.Packages))
	for i := range p.Packages {
		pkg := &p.Packages[i]
		// Package must have a non-empty Name.
		if pkg.Name == "" {
			return fmt.Errorf("[project] %w: package's name is empty", errs.ErrorInvalidField)
		}
		if _, exists := packages[pkg.Name]; exists {
			return fmt.Errorf("[project] %w: package's name (%q) is present multiple times", errs.ErrorInvalidField, pkg.Name)
		}
		packages[pkg.Name] = true
		// Environment field, if set, must contain non-empty values.
		for i := range pkg.Environment.AnyOf {
			val := &pkg.Environment.AnyOf[i]
			if *val == "" {
				return fmt.Errorf("[project] %w: package's any_of value has an empty field", errs.ErrorInvalidField)
			}
		}
		// TODO: validate the packages are defined in a non-overlapping way.

		// Validate the package using the custom validator.
		if p.validator != nil {
			pkg := options.ValidationPackage{
				Name: pkg.Name,
				Environment: options.ValidationEnvironment{
					AnyOf: append([]string{}, pkg.Environment.AnyOf...), // NOTE: Make a copy of the array.
				},
			}
			if err := p.validator.ValidatePackage(pkg); err != nil {
				return fmt.Errorf("%w: failed to validate package: %w", errs.ErrorInvalidField, err)
			}
		}
	}

	return nil
}

func (p *Policy) validateBuildRequirements(maxBuildLevel int) error {
	// SLSA releaser
	//	1) must be set
	//	2) must contain one a level that is satisfiable by the releasers defined in the org-policy.
	if maxBuildLevel < 0 || maxBuildLevel > 4 {
		return fmt.Errorf("[project] %w: build's level is invalid (%d). Must satisfy 0 <= slsa_level <= 4",
			errs.ErrorInvalidField, maxBuildLevel)
	}
	if p.BuildRequirements.RequireSlsaLevel == nil ||
		*p.BuildRequirements.RequireSlsaLevel < 0 ||
		*p.BuildRequirements.RequireSlsaLevel > 4 {
		return fmt.Errorf("[project] %w: build's require_slsa_level is invalid. Must satisfy 0 <= slsa_level <= 4", errs.ErrorInvalidField)
	}
	if *p.BuildRequirements.RequireSlsaLevel > maxBuildLevel {
		return fmt.Errorf("[project] %w: build's level (%d) cannot be satisfied by org policy's max level (%d)",
			errs.ErrorInvalidField, *p.BuildRequirements.RequireSlsaLevel, maxBuildLevel)
	}
	return nil
}

// FromReaders creates a set of policies indexed by their unique id.
func FromReaders(readers iterator.NamedReadCloserIterator, orgPolicy organization.Policy, validator options.PolicyValidator) (map[string]Policy, error) {
	policies := make(map[string]Policy)
	protections := make(map[string]bool)
	for readers.HasNext() {
		id, reader := readers.Next()
		// NOTE: fromReader()validates that the required levels is achievable.
		policy, err := fromReader(reader, orgPolicy.MaxBuildSlsaLevel(), validator)
		if err != nil {
			return nil, err
		}
		// The policy ID must be unique across all projects.
		if _, exists := policies[id]; exists {
			return nil, fmt.Errorf("[project] %w: policy id (%q) is defined more than once", errs.ErrorInvalidField, id)
		}
		policies[id] = *policy

		// The protection must be unique across all projects.
		name := policy.Protection.ServiceAccount
		if _, exists := protections[name]; exists {
			return nil, fmt.Errorf("[project] %w: protection's serivce_account (%q) is defined more than once", errs.ErrorInvalidField, name)
		}
		protections[name] = true
	}
	//TODO: add test for this.
	if readers.Error() != nil {
		return nil, fmt.Errorf("[project] failed to read policy: %w", readers.Error())
	}
	return policies, nil
}

// Evaluate evaluates a policy.
func (p *Policy) Evaluate(digests intoto.DigestSet, packageName string,
	orgPolicy organization.Policy, releaseOpts options.ReleaseVerification) (*Protection, error) {
	if releaseOpts.Verifier == nil {
		return nil, fmt.Errorf("[project] %w: verifier is empty", errs.ErrorInvalidInput)
	}

	// Validate the digest.
	if err := digests.Validate(); err != nil {
		return nil, err
	}
	// Get the package for protection Name.
	pkg, err := p.getPackage(packageName)
	if err != nil {
		return nil, err
	}

	env := pkg.Environment.AnyOf

	// Verify with each releaser.
	// WARNING: the hidden assumption is that the verifier is aware of which
	// package Names can be attested to by which releaser.
	// TODO: Instead of iterating thru all releasers, the org policy may contain
	// a trusted mapping.
	var allErrs []error
	for i := range orgPolicy.Roots.Release {
		releaser := &orgPolicy.Roots.Release[i]
		// Filter out the releasers that don't match the SLSA build level requirement
		// in the policy.
		if *releaser.Build.MaxSlsaLevel < *p.BuildRequirements.RequireSlsaLevel {
			continue
		}
		// We have a candidate.
		verifiedEnv, err := releaseOpts.Verifier.VerifyReleaseAttestation(digests, packageName, env, releaser.ID, *p.BuildRequirements.RequireSlsaLevel)
		if err != nil {
			// Verification failed, continue.
			allErrs = append(allErrs, err)
			continue
		}

		// Verification of release attestation succeeded.

		// Sanity check.
		if err := validateEnv(env, verifiedEnv); err != nil {
			return nil, err
		}
		// The target Name of the policy.
		cpy := p.Protection
		return &cpy, nil
	}
	return nil, fmt.Errorf("[project] %w: cannot verify: %v", errs.ErrorVerification, allErrs)
}

func validateEnv(env []string, verifiedEnv *string) error {
	if len(env) > 0 {
		if verifiedEnv == nil {
			return fmt.Errorf("[project] %w: mismatch environment (%q) and verified environment (nil)", errs.ErrorInternal, env)
		}
		if *verifiedEnv == "" {
			return fmt.Errorf("[project] %w: mismatch environment (%q) and verified environment (%q)", errs.ErrorInternal, env, *verifiedEnv)
		}
		if !slices.Contains(env, *verifiedEnv) {
			return fmt.Errorf("[project] %w: mismatch value environment (%q) and verified environment (%q)", errs.ErrorInternal, env, *verifiedEnv)
		}
		return nil
	}
	if verifiedEnv != nil {
		return fmt.Errorf("[project] %w: mismatch environment (%q) and verified environment (%q)", errs.ErrorInternal, env, *verifiedEnv)
	}
	return nil
}

func (p *Policy) getPackage(packageName string) (*Package, error) {
	for i := range p.Packages {
		pkg := &p.Packages[i]
		if pkg.Name == packageName {
			return pkg, nil
		}
	}
	return nil, fmt.Errorf("[project] %w: package name(%q)", errs.ErrorNotFound, packageName)
}

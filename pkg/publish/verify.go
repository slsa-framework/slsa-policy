package publish

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/slsa-framework/slsa-policy/pkg/errs"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
)

type Verification struct {
	attestation
	packageHelper PackageHelper
}

type VerificationOption func(*Verification) error

func VerificationNew(reader io.ReadCloser, packageHelper PackageHelper) (*Verification, error) {
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	defer reader.Close()
	var att attestation
	if err := json.Unmarshal(content, &att); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if packageHelper == nil {
		return nil, fmt.Errorf("%w: package hepler is nil", errs.ErrorInvalidInput)
	}
	return &Verification{
		attestation:   att,
		packageHelper: packageHelper,
	}, nil
}

func (v *Verification) Verify(digests intoto.DigestSet, policyPackageName string, options ...VerificationOption) error {
	// Statement type.
	if v.attestation.Header.Type != statementType {
		return fmt.Errorf("%w: attestation type (%q) != intoto type (%q)", errs.ErrorMismatch,
			v.attestation.Header.Type, statementType)
	}
	// Predicate type.
	if v.attestation.Header.PredicateType != predicateType {
		return fmt.Errorf("%w: attestation predicate type (%q) != publish type (%q)", errs.ErrorMismatch,
			v.attestation.Header.PredicateType, predicateType)
	}
	// Subjects and digests.
	if len(v.attestation.Header.Subjects) == 0 {
		return fmt.Errorf("%w: no subjects in attestation", errs.ErrorInvalidField)
	}
	if err := verifyDigests(v.attestation.Header.Subjects[0].Digests, digests); err != nil {
		return err
	}

	// Package.
	if err := v.verifyPackage(policyPackageName); err != nil {
		return err
	}
	// TODO: verify time. Use default margin, but allow passing
	// a custom one.

	// Other options.
	for _, option := range options {
		err := option(v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (v *Verification) verifyPackage(policyPackageName string) error {
	if policyPackageName == "" {
		return fmt.Errorf("%w: empty URI", errs.ErrorInvalidField)
	}
	if err := v.attestation.Predicate.Package.Validate(); err != nil {
		return err
	}

	packageDesc, err := v.packageHelper.PackageDescriptor(policyPackageName)
	if err != nil {
		return fmt.Errorf("%w: failed to create package descriptor: %v", errs.ErrorInternal, err.Error())
	}

	if packageDesc.Name != v.attestation.Predicate.Package.Name || packageDesc.Registry != v.attestation.Predicate.Package.Registry {
		return fmt.Errorf("%w: package (%q) != attestation package (%q)", errs.ErrorMismatch,
			policyPackageName, v.attestation.Predicate.Package.Name+"/"+v.attestation.Predicate.Package.Registry)
	}
	return nil
}

func verifyDigests(ds intoto.DigestSet, digests intoto.DigestSet) error {
	if err := ds.Validate(); err != nil {
		return err
	}
	if err := digests.Validate(); err != nil {
		return err
	}
	for name, value := range digests {
		val, exists := ds[name]
		if !exists {
			return fmt.Errorf("%w: subject with digest (%q:%q) is not present in attestation", errs.ErrorMismatch,
				name, value)
		}
		if val != value {
			return fmt.Errorf("%w: subject with digest (%q:%q) != attestation (%q:%q)", errs.ErrorMismatch,
				name, value, name, val)
		}
	}
	return nil
}

func IsPackageEnvironment(env string) VerificationOption {
	return func(v *Verification) error {
		return v.isPackageEnvironment(env)
	}
}

func (v *Verification) isPackageEnvironment(env string) error {
	if v.attestation.Predicate.Package.Environment != env {
		return fmt.Errorf("%w: environment (%q) != attestation environment (%q)", errs.ErrorMismatch,
			env, v.attestation.Predicate.Package.Environment)
	}
	return nil
}

func IsPackageVersion(version string) VerificationOption {
	return func(v *Verification) error {
		return v.isPackageVersion(version)
	}
}

func (v *Verification) isPackageVersion(version string) error {
	if v.attestation.Predicate.Package.Version != version {
		return fmt.Errorf("%w: version (%q) != attestation version (%q)", errs.ErrorMismatch,
			version, v.attestation.Predicate.Package.Version)
	}
	return nil
}

func IsSlsaBuildLevel(level int) VerificationOption {
	return func(v *Verification) error {
		return v.isSlsaBuildLevel(level)
	}
}

func (v *Verification) isSlsaBuildLevel(level int) error {
	if err := validateLevel(level); err != nil {
		return err
	}
	attLevel, err := v.attestationLevel()
	if err != nil {
		return err
	}
	if attLevel != level {
		return fmt.Errorf("%w: level (%v) != attestation (%v)", errs.ErrorMismatch,
			level, attLevel)
	}
	return nil
}

func IsSlsaBuildLevelOrAbove(level int) VerificationOption {
	return func(v *Verification) error {
		return v.isSlsaBuildLevelOrAbove(level)
	}
}

func (v *Verification) isSlsaBuildLevelOrAbove(level int) error {
	if err := validateLevel(level); err != nil {
		return err
	}
	attLevel, err := v.attestationLevel()
	if err != nil {
		return err
	}
	if attLevel < level {
		return fmt.Errorf("%w: level (%v) > attestation (%v)", errs.ErrorMismatch,
			level, attLevel)
	}
	return nil
}

func validateLevel(level int) error {
	if level < 0 {
		return fmt.Errorf("%w: level (%v) is negative", errs.ErrorInvalidInput, level)
	}
	if level > 4 {
		return fmt.Errorf("%w: level (%v) is too large", errs.ErrorInvalidInput, level)
	}
	return nil
}

func (v *Verification) attestationLevel() (int, error) {
	if v.attestation.Predicate.Properties == nil {
		return 0, fmt.Errorf("%w: publish properties are empty", errs.ErrorMismatch)
	}
	value, exists := v.attestation.Predicate.Properties[buildLevelProperty]
	if !exists {
		return 0, fmt.Errorf("%w: (%q) field not present in properties", errs.ErrorMismatch,
			buildLevelProperty)
	}
	vv, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("%w: attestation level (%T:%v) is not an int", errs.ErrorMismatch, value, value)
	}
	return int(vv), nil
}

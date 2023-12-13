package release

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type Verification struct {
	attestation
}

type AttestationVerificationOption func(*Verification) error

func VerificationNew(reader io.ReadCloser) (*Verification, error) {
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	defer reader.Close()
	var att attestation
	if err := json.Unmarshal(content, &att); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	return &Verification{
		attestation: att,
	}, nil
}

func (v *Verification) Verify(creatorID string, digests intoto.DigestSet, packageURI string, options ...AttestationVerificationOption) error {
	// Statement type.
	if v.attestation.Header.Type != statementType {
		return fmt.Errorf("%w: attestation type (%q) != intoto type (%q)", errs.ErrorMismatch,
			v.attestation.Header.Type, statementType)
	}
	// Predicate type.
	if v.attestation.Header.PredicateType != predicateType {
		return fmt.Errorf("%w: attestation predicate type (%q) != release type (%q)", errs.ErrorMismatch,
			v.attestation.Header.PredicateType, predicateType)
	}
	// Subjects and digests.
	if len(v.attestation.Header.Subjects) == 0 {
		return fmt.Errorf("%w: no subjects in attestation", errs.ErrorInvalidField)
	}
	if err := verifyDigests(v.attestation.Header.Subjects[0].Digests, digests); err != nil {
		return err
	}
	// Creator ID.
	if creatorID == "" {
		return fmt.Errorf("%w: creator ID is empty", errs.ErrorInvalidField)
	}
	if creatorID != v.attestation.Predicate.Creator.ID {
		return fmt.Errorf("%w: creator ID (%q) != attestation creator id (%q)", errs.ErrorMismatch,
			creatorID, v.attestation.Predicate.Creator.ID)
	}
	// Package.
	if err := v.verifyPackage(packageURI); err != nil {
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

func (v *Verification) verifyPackage(packageURI string) error {
	if packageURI == "" {
		return fmt.Errorf("%w: empty URI", errs.ErrorInvalidField)
	}
	if err := v.attestation.Predicate.Package.Validate(); err != nil {
		return fmt.Errorf("input package: %w", err)
	}
	if packageURI != v.attestation.Predicate.Package.URI {
		return fmt.Errorf("%w: package URI (%q) != attestation package URI (%q)", errs.ErrorMismatch,
			packageURI, v.attestation.Predicate.Package.URI)
	}
	return nil
}

func (v *Verification) verifyAnnotation(anno map[string]interface{}, name string) error {
	inputValue, err := intoto.GetAnnotationValue(anno, name)
	if err != nil {
		return err
	}
	attValue, err := intoto.GetAnnotationValue(v.attestation.Predicate.Package.Annotations, name)
	if err != nil {
		return err
	}
	if inputValue != attValue {
		return fmt.Errorf("%w: package annotation (%q: %q) != attestation package annotation (%q: %q)", errs.ErrorMismatch,
			name, inputValue, name, attValue)
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

func IsPackageEnvironment(env string) AttestationVerificationOption {
	return func(v *Verification) error {
		return v.isPackageEnvironment(env)
	}
}

func (v *Verification) isPackageEnvironment(env string) error {
	attEnv, err := intoto.GetAnnotationValue(v.attestation.Predicate.Package.Annotations, environmentAnnotation)
	if err != nil {
		return err
	}
	if attEnv != env {
		return fmt.Errorf("%w: environment (%q) != attestation environment (%q)", errs.ErrorMismatch,
			env, attEnv)
	}
	return nil
}

func IsPackageVersion(version string) AttestationVerificationOption {
	return func(v *Verification) error {
		return v.isPackageVersion(version)
	}
}

func (v *Verification) isPackageVersion(version string) error {
	attVersion, err := intoto.GetAnnotationValue(v.attestation.Predicate.Package.Annotations, versionAnnotation)
	if err != nil {
		return err
	}
	if attVersion != version {
		return fmt.Errorf("%w: version (%q) != attestation version (%q)", errs.ErrorMismatch,
			version, attVersion)
	}
	return nil
}

func IsCreatorVersion(version string) AttestationVerificationOption {
	return func(v *Verification) error {
		return v.isCreatorVersion(version)
	}
}

func (v *Verification) isCreatorVersion(version string) error {
	if version != v.attestation.Predicate.Creator.Version {
		return fmt.Errorf("%w: version (%q) != attestation version (%q)", errs.ErrorMismatch,
			version, v.attestation.Predicate.Creator.Version)
	}
	return nil
}

func HasPolicy(name, uri string, digests intoto.DigestSet) AttestationVerificationOption {
	return func(v *Verification) error {
		return v.hasPolicy(name, uri, digests)
	}
}

func (v *Verification) hasPolicy(name, uri string, digests intoto.DigestSet) error {
	policy, exists := v.attestation.Predicate.Policy[name]
	if !exists {
		return fmt.Errorf("%w: policy (%q) does not exist in attestation", errs.ErrorMismatch,
			name)
	}
	if policy.URI != uri {
		return fmt.Errorf("%w: policy (%q) with URI (%q) != attestation (%q)", errs.ErrorMismatch,
			name, uri, policy.URI)
	}
	if err := verifyDigests(digests, policy.Digests); err != nil {
		return err
	}
	return nil
}

func IsSlsaBuildLevel(level int) AttestationVerificationOption {
	return func(v *Verification) error {
		return v.isSlsaBuildLevel(level)
	}
}

func (v *Verification) isSlsaBuildLevel(level int) error {
	if level < 0 {
		return fmt.Errorf("%w: level (%v) is negative", errs.ErrorInvalidInput, level)
	}
	if level > 4 {
		return fmt.Errorf("%w: level (%v) is too large", errs.ErrorInvalidInput, level)
	}
	if v.attestation.Predicate.Properties == nil {
		return fmt.Errorf("%w: release properties are empty", errs.ErrorMismatch)
	}
	value, exists := v.attestation.Predicate.Properties[buildLevelProperty]
	if !exists {
		return fmt.Errorf("%w: (%q) field not present in properties", errs.ErrorMismatch,
			buildLevelProperty)
	}
	vv, ok := value.(float64)
	if !ok {
		return fmt.Errorf("%w: attestation level (%T:%v) is not an int", errs.ErrorMismatch, value, value)
	}
	if int(vv) != level {
		return fmt.Errorf("%w: level (%v) != attestation (%v)", errs.ErrorMismatch,
			level, int(vv))
	}
	return nil
}

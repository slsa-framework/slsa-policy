package attestation

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

type VerificationOption func(*Verification) error

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

func (v *Verification) Verify(authorID string, subject intoto.Subject, environment string, result ReleaseResult, options ...VerificationOption) error {
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
	if err := verifySubject(v.attestation.Header.Subjects[0], subject); err != nil {
		return err
	}
	// Author ID.
	if authorID == "" {
		return fmt.Errorf("%w: author ID is empty", errs.ErrorInvalidInput)
	}
	if authorID != v.attestation.Predicate.Author.ID {
		return fmt.Errorf("%w: author ID (%q) != attestation author id (%q)", errs.ErrorMismatch,
			authorID, v.attestation.Predicate.Author.Version)
	}
	// Environment.
	if err := v.verifyEnvironment(environment); err != nil {
		return err
	}
	// Result.
	if result != v.attestation.Predicate.ReleaseResult {
		return fmt.Errorf("%w: release result (%q) != attestation result result (%q)", errs.ErrorMismatch,
			result, v.attestation.Predicate.ReleaseResult)
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

func verifySubject(ds, subject intoto.Subject) error {
	// Validate the subjects.
	if err := ds.Validate(); err != nil {
		return fmt.Errorf("attestation subjects: %w", err)
	}
	if err := subject.Validate(); err != nil {
		return fmt.Errorf("input subjects: %w", err)
	}
	// Compare the digests.
	if err := verifyDigests(ds.Digests, subject.Digests); err != nil {
		return err
	}
	// Compare the URI.
	if ds.URI != subject.URI {
		return fmt.Errorf("%w: subject URI (%q) != attestation subject URI (%q)", errs.ErrorMismatch,
			ds.URI, subject.URI)
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

func IsAuthorVersion(version string) VerificationOption {
	return func(v *Verification) error {
		return v.isAuthorVersion(version)
	}
}

func (v *Verification) isAuthorVersion(version string) error {
	if version != v.attestation.Predicate.Author.Version {
		return fmt.Errorf("%w: version (%q) != attestation version (%q)", errs.ErrorMismatch,
			version, v.attestation.Predicate.Author.Version)
	}
	return nil
}

func (v *Verification) verifyEnvironment(env string) error {
	// The New() function ensures there are subjects.
	// We only support a single subject.
	return v.verifyAnnotation(environmentAnnotation, env)
}

func (v *Verification) verifyAnnotation(anno, value string) error {
	if value == "" {
		if v.attestation.Header.Subjects[0].Annotations == nil {
			return nil
		}
		val, exists := v.attestation.Header.Subjects[0].Annotations[anno]
		if !exists || val == value {
			return nil
		}
		return fmt.Errorf("%w: %s (%q) != attestation %s (%q)", errs.ErrorMismatch,
			anno, value, anno, v.attestation.Header.Subjects[0].Annotations[anno])
	}

	// value is not empty.
	if v.attestation.Header.Subjects[0].Annotations == nil {
		return fmt.Errorf("%w: %s (%q) != attestation %s (%q)", errs.ErrorMismatch,
			anno, value, anno, "")
	}
	_, exists := v.attestation.Header.Subjects[0].Annotations[anno]
	if !exists {
		return fmt.Errorf("%w: %s (%q) != attestation %s (%q)", errs.ErrorMismatch,
			anno, value, anno, "")
	}
	if v.attestation.Header.Subjects[0].Annotations[anno] != value {
		return fmt.Errorf("%w: %s (%q) != attestation %s (%q)", errs.ErrorMismatch,
			anno, value, anno, v.attestation.Header.Subjects[0].Annotations[anno])
	}
	return nil
}

func HasPolicy(name, uri string, digests intoto.DigestSet) VerificationOption {
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

func IsSlsaBuildLevel(level int) VerificationOption {
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
	if v.attestation.Predicate.ReleaseProperties == nil {
		return fmt.Errorf("%w: release properties are empty", errs.ErrorMismatch)
	}
	value, exists := v.attestation.Predicate.ReleaseProperties[buildLevelProperty]
	if !exists {
		return fmt.Errorf("%w: (%q) field not present in release properties", errs.ErrorMismatch,
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

func IsReleaseVersion(version string) VerificationOption {
	return func(v *Verification) error {
		return v.isReleaseVersion(version)
	}
}

func (v *Verification) isReleaseVersion(version string) error {
	return v.verifyAnnotation(versionAnnotation, version)
}

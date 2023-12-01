package attestation

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/attestation"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type Verification struct {
	attestation.Attestation
}

func New(reader io.ReadCloser) (*Verification, error) {
	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	defer reader.Close()
	var att attestation.Attestation
	if err := json.Unmarshal(content, &att); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	return &Verification{
		Attestation: att,
	}, nil
}

func (v *Verification) Verify(authorID string, subject intoto.Subject, environment string, result intoto.AttestationResult, options ...func(*Verification) error) error {
	// Statement type.
	if v.Attestation.Header.Type != attestation.StatementType {
		return fmt.Errorf("%w: attestation type (%q) != intoto type (%q)", errs.ErrorMismatch,
			v.Attestation.Header.Type, attestation.StatementType)
	}
	// Predicate type.
	if v.Attestation.Header.PredicateType != attestation.PredicateType {
		return fmt.Errorf("%w: attestation predicate type (%q) != release type (%q)", errs.ErrorMismatch,
			v.Attestation.Header.PredicateType, attestation.PredicateType)
	}
	// Subjects and digests.
	if len(v.Attestation.Header.Subjects) == 0 {
		return fmt.Errorf("%w: no subjects in attestation", errs.ErrorInvalidField)
	}
	if err := verifySubject(v.Attestation.Header.Subjects[0], subject); err != nil {
		return err
	}
	// Author ID.
	if authorID == "" {
		return fmt.Errorf("%w: author ID is empty", errs.ErrorInvalidInput)
	}
	if authorID != v.Attestation.Predicate.Author.ID {
		return fmt.Errorf("%w: author ID (%q) != attestation author id (%q)", errs.ErrorMismatch,
			authorID, v.Attestation.Predicate.Author.Version)
	}
	// Environment.
	if err := v.verifyEnvironment(environment); err != nil {
		return err
	}
	// Result.
	if result != v.Attestation.Predicate.ReleaseResult {
		return fmt.Errorf("%w: release result (%q) != attestation result result (%q)", errs.ErrorMismatch,
			result, v.Attestation.Predicate.ReleaseResult)
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

func WithAuthorVersion(version string) func(*Verification) error {
	return func(v *Verification) error {
		return v.isAuthorVersion(version)
	}
}

func (v *Verification) isAuthorVersion(version string) error {
	if version != v.Attestation.Predicate.Author.Version {
		return fmt.Errorf("%w: version (%q) != attestation version (%q)", errs.ErrorMismatch,
			version, v.Attestation.Predicate.Author.Version)
	}
	return nil
}

func (v *Verification) verifyEnvironment(env string) error {
	// The New() function ensures there are subjects.
	// We only support a single subject.
	if env == "" {
		if v.Attestation.Header.Subjects[0].Annotations == nil {
			return nil
		}
		val, exists := v.Attestation.Header.Subjects[0].Annotations[attestation.EnvironmentAnnotation]
		if !exists || val == env {
			return nil
		}
		return fmt.Errorf("%w: environment (%q) != attestation environment (%q)", errs.ErrorMismatch,
			env, v.Attestation.Header.Subjects[0].Annotations[attestation.EnvironmentAnnotation])
	}

	// env is not empty.
	if v.Attestation.Header.Subjects[0].Annotations == nil {
		return fmt.Errorf("%w: environment (%q) != attestation environment (%q)", errs.ErrorMismatch,
			env, "")
	}
	if v.Attestation.Header.Subjects[0].Annotations[attestation.EnvironmentAnnotation] != env {
		return fmt.Errorf("%w: environment (%q) != attestation environment (%q)", errs.ErrorMismatch,
			env, v.Attestation.Header.Subjects[0].Annotations[attestation.EnvironmentAnnotation])
	}
	return nil
}

func WithPolicy(name, uri string, digests intoto.DigestSet) func(*Verification) error {
	return func(v *Verification) error {
		return v.isPolicyURI(name, uri, digests)
	}
}

func (v *Verification) isPolicyURI(name, uri string, digests intoto.DigestSet) error {
	policy, exists := v.Attestation.Predicate.Policy[name]
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

func WithSlsaBuildLevel(level int) func(*Verification) error {
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
	if v.Attestation.Predicate.ReleaseProperties == nil {
		return fmt.Errorf("%w: release properties are empty", errs.ErrorMismatch)
	}
	value, exists := v.Attestation.Predicate.ReleaseProperties[attestation.BuildLevelProperty]
	if !exists {
		return fmt.Errorf("%w: (%q) field not present in release properties", errs.ErrorMismatch,
			attestation.BuildLevelProperty)
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

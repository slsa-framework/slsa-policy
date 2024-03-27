package deployment

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type Verification struct {
	attestation
}

type VerificationOption func(*Verification) error

func VerificationNew(reader io.ReadCloser) (*Verification, error) {
	content, err := io.ReadAll(reader)
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

func (v *Verification) Verify(digests intoto.DigestSet, scopes map[string]string, options ...VerificationOption) error {
	// Statement type.
	if v.attestation.Header.Type != statementType {
		return fmt.Errorf("%w: attestation type (%q) != intoto type (%q)", errs.ErrorMismatch,
			v.attestation.Header.Type, statementType)
	}
	// Predicate type.
	if v.attestation.Header.PredicateType != predicateType {
		return fmt.Errorf("%w: attestation predicate type (%q) != deployment type (%q)", errs.ErrorMismatch,
			v.attestation.Header.PredicateType, predicateType)
	}
	// Subjects and digests.
	if len(v.attestation.Header.Subjects) == 0 {
		return fmt.Errorf("%w: no subjects in attestation", errs.ErrorInvalidField)
	}
	if err := verifyDigests(v.attestation.Header.Subjects[0].Digests, digests); err != nil {
		return err
	}
	// Scopes.
	if err := v.verifyScopes(scopes); err != nil {
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

func (v *Verification) verifyScopes(scopes map[string]string) error {
	if !reflect.DeepEqual(v.attestation.Predicate.Scopes, scopes) {
		return fmt.Errorf("%w: scopes (%q) != attestation scopes (%q)", errs.ErrorMismatch,
			scopes, v.attestation.Predicate.Scopes)
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

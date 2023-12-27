package deployment

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"

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

func (v *Verification) Verify(creatorID string, digests intoto.DigestSet, contextType string, context interface{}, options ...AttestationVerificationOption) error {
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
	// Creator ID.
	if err := v.verifyCreatorID(creatorID); err != nil {
		return err
	}
	// Context and context type.
	if err := v.verifyContext(contextType, context); err != nil {
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

func (v *Verification) verifyContext(contextType string, context interface{}) error {
	if contextType == "" {
		return fmt.Errorf("%w: context type is empty", errs.ErrorInvalidField)
	}
	if v.attestation.Predicate.ContextType == "" {
		return fmt.Errorf("%w: attestation context type is empty", errs.ErrorInvalidField)
	}
	if contextType != v.attestation.Predicate.ContextType {
		return fmt.Errorf("%w: context type (%q) != attestation context type (%q)", errs.ErrorMismatch,
			contextType, v.attestation.Predicate.ContextType)
	}

	// Marshall and unmarshal to get an interface{}.
	contextInt, err := asInterface(context)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(contextInt, v.attestation.Predicate.Context) {
		return fmt.Errorf("%w: context (%q) != attestation context (%q)", errs.ErrorMismatch,
			contextInt, v.attestation.Predicate.Context)
	}
	return nil
}

func asInterface(context interface{}) (interface{}, error) {
	var contextInt interface{}
	contextBytes, err := json.Marshal(context)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal context (%q): %w", context, err)
	}
	if err := json.Unmarshal(contextBytes, &contextInt); err != nil {
		return nil, fmt.Errorf("cannot unmarshal context (%q): %w", context, err)
	}
	return contextInt, nil
}

func (v *Verification) verifyCreatorID(creatorID string) error {
	if creatorID == "" {
		return fmt.Errorf("%w: creator ID is empty", errs.ErrorInvalidField)
	}
	if creatorID != v.attestation.Predicate.Creator.ID {
		return fmt.Errorf("%w: creator ID (%q) != attestation creator id (%q)", errs.ErrorMismatch,
			creatorID, v.attestation.Predicate.Creator.ID)
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

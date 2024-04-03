package publish

import (
	"encoding/json"
	"fmt"

	"github.com/slsa-framework/slsa-policy/pkg/errs"

	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
)

type Creation struct {
	attestation
	safeMode bool
}

type AttestationCreationOption func(*Creation) error

// NOTE: See https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
func CreationNew(subject intoto.Subject, packageDesc intoto.PackageDescriptor,
	options ...AttestationCreationOption) (*Creation, error) {
	if err := subject.Validate(); err != nil {
		return nil, err
	}
	if err := packageDesc.Validate(); err != nil {
		return nil, err
	}
	att := Creation{
		attestation: attestation{
			Header: intoto.Header{
				Type:          statementType,
				PredicateType: predicateType,
				Subjects:      []intoto.Subject{subject},
			},
			Predicate: predicate{
				CreationTime: intoto.Now(),
				Package:      packageDesc,
			},
		},
	}
	for _, option := range options {
		err := option(&att)
		if err != nil {
			return nil, err
		}
	}
	return &att, nil
}

func (a *Creation) ToBytes() ([]byte, error) {
	content, err := json.Marshal(a.attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %v", err)
	}
	return content, nil
}

func EnterSafeMode() AttestationCreationOption {
	return func(a *Creation) error {
		return a.enterSafeMode()
	}
}

func (a *Creation) enterSafeMode() error {
	a.safeMode = true
	return nil
}

func (a *Creation) isSafeMode() bool {
	return a.safeMode
}

func SetPackageVersion(version string) AttestationCreationOption {
	return func(a *Creation) error {
		return a.setPackageVersion(version)
	}
}

func (a *Creation) setPackageVersion(version string) error {
	a.attestation.Predicate.Package.Version = version
	return nil
}

func SetSlsaBuildLevel(level int) AttestationCreationOption {
	return func(a *Creation) error {
		return a.setSlsaBuildLevel(level)
	}
}

func (a *Creation) setSlsaBuildLevel(level int) error {
	if a.isSafeMode() {
		return fmt.Errorf("%w: safe mode enabled, cannot edit SLSA build level", errs.ErrorInternal)
	}
	if level < 0 {
		return fmt.Errorf("%w: level (%v) is negative", errs.ErrorInvalidInput, level)
	}
	if level > 4 {
		return fmt.Errorf("%w: level (%v) is too large", errs.ErrorInvalidInput, level)
	}
	if a.attestation.Predicate.Properties == nil {
		a.attestation.Predicate.Properties = make(map[string]interface{})
	}
	a.attestation.Predicate.Properties[buildLevelProperty] = level
	return nil
}

// Utility functions needed by cosign APIs.
func (a *Creation) PredicateType() string {
	return predicateType
}

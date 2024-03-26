package deployment

import (
	"encoding/json"
	"fmt"

	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type Creation struct {
	attestation
	safeMode bool
}

type AttestationCreationOption func(*Creation) error

func CreationNew(subject intoto.Subject, contextType string,
	context interface{}, options ...AttestationCreationOption) (*Creation, error) {
	if err := subject.Validate(); err != nil {
		return nil, err
	}

	// Validate the digests.
	att := Creation{
		attestation: attestation{
			Header: intoto.Header{
				Type:          statementType,
				PredicateType: predicateType,
				Subjects:      []intoto.Subject{subject},
			},
			Predicate: predicate{
				CreationTime: intoto.Now(),
				ContextType:  contextType,
				Context:      context,
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
	content, err := json.Marshal(*&a.attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %v", err)
	}
	return content, nil
}

func SetPolicy(policy map[string]intoto.Policy) AttestationCreationOption {
	return func(a *Creation) error {
		return a.setPolicy(policy)
	}
}

func (a *Creation) setPolicy(policy map[string]intoto.Policy) error {
	a.attestation.Predicate.Policy = policy
	return nil
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

// Utility functions needed by cosign APIs.
func (a *Creation) PredicateType() string {
	return predicateType
}

package deployment

import (
	"encoding/json"
	"fmt"

	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type Creation struct {
	attestation
}

type AttestationCreationOption func(*Creation) error

func CreationNew(creatorID string, subject intoto.Subject, contextType string,
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
				Creator: intoto.Creator{
					ID: creatorID,
				},
				ContextType: contextType,
				Context:     context,
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

func SetCreatorVersion(version string) AttestationCreationOption {
	return func(a *Creation) error {
		return a.setCreatorVersion(version)
	}
}

func (a *Creation) setCreatorVersion(version string) error {
	a.attestation.Predicate.Creator.Version = version
	return nil
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

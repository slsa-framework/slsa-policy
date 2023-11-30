package attestation

import (
	"fmt"
	"time"

	"github.com/laurentsimon/slsa-policy/pkg/errs"

	"github.com/laurentsimon/slsa-policy/pkg/release/internal/attestation"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type Creation struct {
	attestation.Attestation
}

// NOTE: See https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
func New(subject intoto.ResourceDescriptor, authorID string, result intoto.AttestationResult, options ...func(*Creation) error) (*Creation, error) {
	attestation := Creation{
		Attestation: attestation.Attestation{
			Header: intoto.Header{
				Type:          attestation.StatementType,
				PredicateType: attestation.PredicateType,
				Subjects:      []intoto.ResourceDescriptor{subject},
			},
			Predicate: attestation.Predicate{
				ReleaseResult: result,
				CreationTime:  time.Now(),
				Author: intoto.Author{
					ID: authorID,
				},
			},
		},
	}
	for _, option := range options {
		err := option(&attestation)
		if err != nil {
			return nil, err
		}
	}
	return &attestation, nil
}

func (a *Creation) isResultAllowed() bool {
	return a.Attestation.Predicate.ReleaseResult == intoto.AttestationResultAllow
}

func WithAuthorVersion(version string) func(*Creation) error {
	return func(a *Creation) error {
		return a.setAuthorVersion(version)
	}
}

func (a *Creation) setAuthorVersion(version string) error {
	a.Attestation.Predicate.Author.Version = version
	return nil
}

func WithEnvironment(env string) func(*Creation) error {
	return func(a *Creation) error {
		return a.setEnvironment(env)
	}
}

func (a *Creation) setEnvironment(env string) error {
	if a.Attestation.Header.Subjects[0].Annotations == nil {
		a.Attestation.Header.Subjects[0].Annotations = make(map[string]interface{})
	}
	a.Attestation.Header.Subjects[0].Annotations[attestation.EnvironmentAnnotation] = env
	return nil
}

func WithPolicy(policy map[string]intoto.Policy) func(*Creation) error {
	return func(a *Creation) error {
		return a.setPolicy(policy)
	}
}

func (a *Creation) setPolicy(policy map[string]intoto.Policy) error {
	a.Attestation.Predicate.Policy = policy
	return nil
}

func WithSlsaBuildLevel(level int) func(*Creation) error {
	return func(a *Creation) error {
		return a.setSlsaBuildLevel(level)
	}
}

func (a *Creation) setSlsaBuildLevel(level int) error {
	if !a.isResultAllowed() {
		return fmt.Errorf("%w: level cannot be set for %q result", errs.ErrorInvalidInput, a.Attestation.Predicate.ReleaseResult)
	}
	if level < 0 {
		return fmt.Errorf("%w: level (%v) is negative", errs.ErrorInvalidInput, level)
	}
	if level > 4 {
		return fmt.Errorf("%w: level (%v) is too large", errs.ErrorInvalidInput, level)
	}
	if a.Attestation.Predicate.ReleaseProperties == nil {
		a.Attestation.Predicate.ReleaseProperties = make(map[string]interface{})
	}
	a.Attestation.Predicate.ReleaseProperties[attestation.BuildLevelProperty] = level
	return nil
}

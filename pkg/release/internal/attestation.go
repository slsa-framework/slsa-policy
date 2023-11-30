package internal

import (
	"fmt"
	"time"

	"github.com/laurentsimon/slsa-policy/pkg/errs"

	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// Predicate is the custom predicate.
type Predicate struct {
	Author intoto.Author `json:"author"`
	// TODO: formating https://stackoverflow.com/questions/23695479/how-to-format-timestamp-in-outgoing-json
	CreationTime         time.Time                `json:"creationTime"`
	Policy               map[string]intoto.Policy `json:"policy,omitempty"`
	ReleaseResult        intoto.AttestationResult `json:"releaseResult"`
	ReleaseProperties    intoto.Properties        `json:"releaseProperties"`
	DependencyProperties map[string]intoto.Properties
}

// Attestation defines a release attestation.
type Attestation struct {
	intoto.Header
	Predicate Predicate `json:"predicate"`
}

const (
	levelProperty         = "slsa.dev/build/level"
	environmentAnnotation = "environment"
)

// NOTE: See https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
func AttestationNew(authorID string, result intoto.AttestationResult, options ...func(*Attestation) error) (*Attestation, error) {
	attestation := Attestation{
		Predicate: Predicate{
			ReleaseResult: result,
			CreationTime:  time.Now(),
			Author: intoto.Author{
				ID: authorID,
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

func (a *Attestation) isResultAllowed() bool {
	return a.Predicate.ReleaseResult == intoto.AttestationResultAllow
}

func WithAuthorVersion(version string) func(*Attestation) error {
	return func(a *Attestation) error {
		return a.setAuthorVersion(version)
	}
}

func (a *Attestation) setAuthorVersion(version string) error {
	a.Predicate.Author.Version = version
	return nil
}

func WithEnvironment(env string) func(*Attestation) error {
	return func(a *Attestation) error {
		return a.setEnvironment(env)
	}
}

func (a *Attestation) setEnvironment(env string) error {
	if a.Header.Resource.Annotations == nil {
		a.Header.Resource.Annotations = make(map[string]interface{})
	}
	a.Header.Resource.Annotations[environmentAnnotation] = env
	return nil
}

func WithPolicy(policy map[string]intoto.Policy) func(*Attestation) error {
	return func(a *Attestation) error {
		return a.setPolicy(policy)
	}
}

func (a *Attestation) setPolicy(policy map[string]intoto.Policy) error {
	a.Predicate.Policy = policy
	return nil
}

func WithSlsaBuildLevel(level int) func(*Attestation) error {
	return func(a *Attestation) error {
		return a.setSlsaBuildLevel(level)
	}
}

func (a *Attestation) setSlsaBuildLevel(level int) error {
	if !a.isResultAllowed() {
		return fmt.Errorf("%w: level cannot be set for %q result", errs.ErrorInvalidInput, a.Predicate.ReleaseResult)
	}
	if level < 0 {
		return fmt.Errorf("%w: level (%v) is negative", errs.ErrorInvalidInput, level)
	}
	if level > 4 {
		return fmt.Errorf("%w: level (%v) is too large", errs.ErrorInvalidInput, level)
	}
	if a.Predicate.ReleaseProperties == nil {
		a.Predicate.ReleaseProperties = make(map[string]interface{})
	}
	a.Predicate.ReleaseProperties[levelProperty] = level
	return nil
}

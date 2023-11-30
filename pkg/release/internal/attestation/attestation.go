package attestation

import (
	"time"

	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// Predicate is the custom predicate.
type Predicate struct {
	Author intoto.Author `json:"author"`
	// TODO: formating https://stackoverflow.com/questions/23695479/how-to-format-timestamp-in-outgoing-json
	CreationTime         time.Time                    `json:"creationTime"`
	Policy               map[string]intoto.Policy     `json:"policy,omitempty"`
	ReleaseResult        intoto.AttestationResult     `json:"releaseResult"`
	ReleaseProperties    intoto.Properties            `json:"releaseProperties,omitempty"`
	DependencyProperties map[string]intoto.Properties `json:"dependencyProperties,omitempty"`
}

// Attestation defines a release attestation.
type Attestation struct {
	intoto.Header
	Predicate Predicate `json:"predicate"`
}

const (
	StatementType         = "https://in-toto.io/Statement/v1"
	PredicateType         = "https://slsa.dev/release_attestation/v1"
	BuildLevelProperty    = "slsa.dev/build/level"
	EnvironmentAnnotation = "environment"
)

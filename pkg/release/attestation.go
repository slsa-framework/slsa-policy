package release

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type predicate struct {
	Creator              intoto.Creator            `json:"creator"`
	CreationTime         string                    `json:"creationTime"`
	Policy               map[string]intoto.Policy  `json:"policy,omitempty"`
	Package              intoto.ResourceDescriptor `json:"package"`
	Properties           properties                `json:"properties,omitempty"`
	DependencyProperties map[string]properties     `json:"dependencyProperties,omitempty"`
	// TODO: add inputs as a list of intoto.ResourceDescriptor, so that we can
	// indicate which attestations were used.
}

type attestation struct {
	intoto.Header
	Predicate predicate `json:"predicate"`
}

type properties map[string]interface{}

const (
	statementType      = "https://in-toto.io/Statement/v1"
	predicateType      = "https://slsa.dev/release/v0.1"
	buildLevelProperty = "slsa.dev/build/level"
	// TODO: make these public for users to be able to construct subjects.
	environmentAnnotation = "environment"
	versionAnnotation     = "version"
)

package release

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type decisionDetails struct {
	Evidence []intoto.ResourceDescriptor `json:"evidence,omitempty"`
	Policy   []intoto.ResourceDescriptor `json:"policy,omitempty"`
}

type predicate struct {
	CreationTime    string                   `json:"creationTime"`
	DecisionDetails *decisionDetails         `json:"decisionDetails,omitempty"`
	Package         intoto.PackageDescriptor `json:"package"`
	Properties      properties               `json:"properties,omitempty"`
	// TODO: properties for dependencies.
	// TODO: add inputs as a list of intoto.PackageDescriptor, so that we can
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
)

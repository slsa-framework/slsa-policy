package publish

import (
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
)

type decisionDetails struct {
	Evidence []intoto.ResourceDescriptor `json:"evidence,omitempty"`
	Policy   []intoto.ResourceDescriptor `json:"policy,omitempty"`
}

type predicate struct {
	CreationTime    string                   `json:"creationTime"`
	DecisionDetails *decisionDetails         `json:"decisionDetails,omitempty"`
	// NOTE: We may replace the descriptor by a PURL.
	Package         intoto.PackageDescriptor `json:"package"`
	Properties      properties               `json:"properties,omitempty"`
	// TODO: properties for dependencies.
}

type attestation struct {
	intoto.Header
	Predicate predicate `json:"predicate"`
}

type properties map[string]interface{}

const (
	statementType      = "https://in-toto.io/Statement/v1"
	predicateType      = "https://slsa.dev/publish/v0.1"
	buildLevelProperty = "slsa.dev/build/level"
)

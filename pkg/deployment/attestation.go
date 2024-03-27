package deployment

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type decisionDetails struct {
	Evidence []intoto.ResourceDescriptor `json:"evidence,omitempty"`
	Policy   []intoto.ResourceDescriptor `json:"policy,omitempty"`
}

type predicate struct {
	CreationTime    string            `json:"creationTime"`
	DecisionDetails decisionDetails   `json:"decisionDetails,omitempty"`
	Scopes          map[string]string `json:"scopes,omitempty"`
	// TODO: add inputs as a list of intoto.PackageDescriptor, so that we can
	// indicate which attestations were used.
}

type attestation struct {
	intoto.Header
	Predicate predicate `json:"predicate"`
}

const (
	statementType          = "https://in-toto.io/Statement/v1"
	predicateType          = "https://slsa.dev/deployment/v0.1"
	scopeGCPServiceAccount = "cloud.google.com/service_account/v1"
)

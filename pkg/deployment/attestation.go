package deployment

import (
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type predicate struct {
	Creator      intoto.Creator           `json:"creator"`
	CreationTime string                   `json:"creationTime"`
	Policy       map[string]intoto.Policy `json:"policy,omitempty"`
	ContextType  string                   `json:"contextType"`
	Context      interface{}              `json:"context,omitempty"`
	// TODO: add inputs as a list of intoto.ResourceDescriptor, so that we can
	// indicate which attestations were used.
}

type attestation struct {
	intoto.Header
	Predicate predicate `json:"predicate"`
}

type properties map[string]interface{}

const (
	statementType        = "https://in-toto.io/Statement/v1"
	predicateType        = "https://slsa.dev/deployment/v0.1"
	contextTypePrincipal = "https://slsa.dev/deployment/contextType/PrincipalID"
	contextPrincipal     = "https://slsa.dev/deployment/context/principalID"
)

package deployment

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// TODO: support time creation.
func Test_CreationNew(t *testing.T) {
	t.Parallel()
	subject := intoto.Subject{
		Digests: intoto.DigestSet{
			"sha256":    "some_value",
			"gitCommit": "another_value",
		},
	}
	contextType := "context_type"
	context := map[string]string{
		"key1": "value1",
		"ke2":  "value2",
	}
	policy := map[string]intoto.Policy{
		"org": intoto.Policy{
			URI: "policy1_uri",
			Digests: intoto.DigestSet{
				"sha256":    "value1",
				"commitSha": "value2",
			},
		},
		"project": intoto.Policy{
			URI: "policy2_uri",
			Digests: intoto.DigestSet{
				"sha256":    "value3",
				"commitSha": "value4",
			},
		},
	}
	creatorVersion := "creator_version"
	tests := []struct {
		name           string
		subject        intoto.Subject
		contextType    string
		context        interface{}
		creatorVersion string
		policy         map[string]intoto.Policy
		expected       error
	}{
		{
			name:        "required fields set nil context",
			subject:     subject,
			contextType: contextType,
		},
		{
			name:        "required fields set non-nil context",
			subject:     subject,
			contextType: contextType,
			context:     context,
		},
		{
			name:        "result with no subject digests",
			subject:     intoto.Subject{},
			contextType: contextType,
			context:     context,
			expected:    errs.ErrorInvalidField,
		},
		{
			name: "result with empty digest value",
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "some_value",
					"gitCommit": "",
				},
			},
			contextType: contextType,
			context:     context,
			expected:    errs.ErrorInvalidField,
		},
		{
			name: "result with empty digest key",
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256": "some_value",
					"":       "another_value",
				},
			},
			contextType: contextType,
			context:     context,
			expected:    errs.ErrorInvalidField,
		},
		{
			name:           "result with creator version",
			subject:        subject,
			contextType:    contextType,
			context:        context,
			creatorVersion: creatorVersion,
		},
		{
			name:        "result with policy",
			subject:     subject,
			contextType: contextType,
			context:     context,
			policy:      policy,
		},
		{
			name:           "result with all set",
			subject:        subject,
			contextType:    contextType,
			context:        context,
			creatorVersion: creatorVersion,
			policy:         policy,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var options []AttestationCreationOption
			if tt.creatorVersion != "" {
				options = append(options, SetCreatorVersion(tt.creatorVersion))
			}
			if tt.policy != nil {
				options = append(options, SetPolicy(tt.policy))
			}
			att, err := CreationNew("creator_id", tt.subject, tt.contextType, tt.context, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Statement type verification.
			if diff := cmp.Diff(statementType, att.Header.Type); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// predicate type verification.
			if diff := cmp.Diff(predicateType, att.Header.PredicateType); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Subjects must match.
			if diff := cmp.Diff([]intoto.Subject{tt.subject}, att.Header.Subjects); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Creator ID must match.
			if diff := cmp.Diff("creator_id", att.Predicate.Creator.ID); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Creator version must match.
			if diff := cmp.Diff(tt.creatorVersion, att.Predicate.Creator.Version); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Policy must match.
			if diff := cmp.Diff(tt.policy, att.Predicate.Policy); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Context type must match.
			if diff := cmp.Diff(tt.contextType, att.Predicate.ContextType); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Context must match.
			if diff := cmp.Diff(tt.context, att.Predicate.Context); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

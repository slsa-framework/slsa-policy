package deployment

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/slsa-framework/slsa-policy/pkg/errs"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
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
	scopes := map[string]string{
		"key1": "value1",
		"ke2":  "value2",
	}
	tests := []struct {
		name     string
		subject  intoto.Subject
		scopes   map[string]string
		policy   map[string]intoto.Policy
		expected error
	}{
		{
			name:    "required fields set nil context",
			subject: subject,
		},
		{
			name:    "required fields set non-nil context",
			subject: subject,
			scopes:  scopes,
		},
		{
			name:     "result with no subject digests",
			subject:  intoto.Subject{},
			scopes:   scopes,
			expected: errs.ErrorInvalidField,
		},
		{
			name: "result with empty digest value",
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "some_value",
					"gitCommit": "",
				},
			},
			scopes:   scopes,
			expected: errs.ErrorInvalidField,
		},
		{
			name: "result with empty digest key",
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256": "some_value",
					"":       "another_value",
				},
			},
			scopes:   scopes,
			expected: errs.ErrorInvalidField,
		},
		{
			name:    "result with all set",
			subject: subject,
			scopes:  scopes,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var options []AttestationCreationOption
			att, err := CreationNew(tt.subject, tt.scopes, options...)
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
			// Scopes must match.
			if diff := cmp.Diff(tt.scopes, att.Predicate.Scopes); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

package attestation

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/attestation"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_New(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		result        intoto.AttestationResult
		authorVersion string
		buildLevel    *int
		environment   string
		policy        map[string]intoto.Policy
		expected      error
	}{
		// Allow policies.
		{
			name:   "allow result",
			result: intoto.AttestationResultAllow,
		},
		{
			name:          "allow result",
			result:        intoto.AttestationResultAllow,
			authorVersion: "my_version",
		},
		{
			name:          "allow result with author version",
			result:        intoto.AttestationResultAllow,
			authorVersion: "my_version",
		},
		{
			name:       "allow result with level",
			result:     intoto.AttestationResultAllow,
			buildLevel: common.AsPointer(2),
		},
		{
			name:       "allow result with negative level",
			result:     intoto.AttestationResultAllow,
			buildLevel: common.AsPointer(-1),
			expected:   errs.ErrorInvalidInput,
		},
		{
			name:       "allow result with large level",
			result:     intoto.AttestationResultAllow,
			buildLevel: common.AsPointer(5),
			expected:   errs.ErrorInvalidInput,
		},
		{
			name:        "allow result with env",
			result:      intoto.AttestationResultAllow,
			environment: "prod",
		},
		{
			name:   "allow result with policy",
			result: intoto.AttestationResultAllow,
			policy: map[string]intoto.Policy{
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
			},
		},
		{
			name:          "allow result with all set",
			result:        intoto.AttestationResultAllow,
			environment:   "prod",
			buildLevel:    common.AsPointer(4),
			authorVersion: "my_version",
			policy: map[string]intoto.Policy{
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
			},
		},
		// Deny policies.
		{
			name:   "deny result",
			result: intoto.AttestationResultDeny,
		},
		{
			name:          "deny result with author version",
			result:        intoto.AttestationResultDeny,
			authorVersion: "my_version",
		},
		{
			name:       "deny result with level",
			result:     intoto.AttestationResultDeny,
			buildLevel: common.AsPointer(2),
			expected:   errs.ErrorInvalidInput,
		},
		{
			name:       "deny result with negative level",
			result:     intoto.AttestationResultDeny,
			buildLevel: common.AsPointer(-1),
			expected:   errs.ErrorInvalidInput,
		},
		{
			name:       "deny result with large level",
			result:     intoto.AttestationResultDeny,
			buildLevel: common.AsPointer(5),
			expected:   errs.ErrorInvalidInput,
		},
		{
			name:        "deny result with env",
			result:      intoto.AttestationResultDeny,
			environment: "prod",
		},
		{
			name:   "deny result with policy",
			result: intoto.AttestationResultDeny,
			policy: map[string]intoto.Policy{
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
			},
		},
		{
			name:          "deny result with all set",
			result:        intoto.AttestationResultDeny,
			environment:   "prod",
			buildLevel:    common.AsPointer(4),
			authorVersion: "my_version",
			policy: map[string]intoto.Policy{
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
			},
			expected: errs.ErrorInvalidInput,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var options []func(*Creation) error
			subject := intoto.ResourceDescriptor{
				Name: "subject1",
				Digests: intoto.DigestSet{
					"sha256":    "some_value",
					"gitCommit": "another_value",
				},
			}
			if tt.authorVersion != "" {
				options = append(options, WithAuthorVersion(tt.authorVersion))
			}
			if tt.buildLevel != nil {
				options = append(options, WithSlsaBuildLevel(*tt.buildLevel))
			}
			if tt.environment != "" {
				options = append(options, WithEnvironment(tt.environment))
			}
			if tt.policy != nil {
				options = append(options, WithPolicy(tt.policy))
			}
			att, err := New(subject, "author_id", tt.result, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Statement type verification.
			if diff := cmp.Diff(attestation.StatementType, att.Header.Type); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Predicate type verification.
			if diff := cmp.Diff(attestation.PredicateType, att.Header.PredicateType); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}

			// Add the environment to the subjects now, to allow comparison.
			if tt.environment != "" {
				subject.Annotations = map[string]interface{}{
					attestation.EnvironmentAnnotation: tt.environment,
				}
			}
			// Subjects must match.
			if diff := cmp.Diff([]intoto.ResourceDescriptor{subject}, att.Header.Subjects); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Author ID must match.
			if diff := cmp.Diff("author_id", att.Predicate.Author.ID); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Release result must match.
			if diff := cmp.Diff(tt.result, att.Predicate.ReleaseResult); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Author version must match.
			if diff := cmp.Diff(tt.authorVersion, att.Predicate.Author.Version); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Policy must match.
			if diff := cmp.Diff(tt.policy, att.Predicate.Policy); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Environment must match.
			if tt.environment != "" {
				if diff := cmp.Diff(tt.environment, att.Header.Subjects[0].Annotations[attestation.EnvironmentAnnotation]); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			} else {
				if diff := cmp.Diff(map[string]any(nil), att.Header.Subjects[0].Annotations); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			}
			// SLSA Levels must match.
			if tt.buildLevel != nil {
				if diff := cmp.Diff(*tt.buildLevel, att.Predicate.ReleaseProperties[attestation.BuildLevelProperty]); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			} else {
				if diff := cmp.Diff(intoto.Properties(nil), att.Predicate.ReleaseProperties); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			}
		})
	}
}

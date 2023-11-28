package project

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
)

func Test_validateFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name: "format is 1",
			policy: &Policy{
				Format: 1,
			},
		},
		{
			name:     "no format defined",
			policy:   &Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "format is not 1",
			policy: &Policy{
				Format: 2,
			},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validateFormat()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validatePublication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name:     "empty uri",
			policy:   &Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "set uri",
			policy: &Policy{
				Publication: Publication{
					URI: "non_empty_uri",
				},
			},
		},
		{
			name: "set uri and environment",
			policy: &Policy{
				Publication: Publication{
					URI: "non_empty_uri",
					Environment: Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			name: "empty environment field",
			policy: &Policy{
				Publication: Publication{
					URI: "non_empty_uri",
					Environment: Environment{
						AnyOf: []string{"", "dev", "prod"},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validatePublication()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateBuildRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		builders []string
		expected error
	}{
		{
			name: "valid policy",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			builders: []string{"builder_name"},
		},
		{
			name: "builders not set",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty builder name",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty repository uri",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "mismatch builder names",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			builders: []string{"other_builder_name"},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validateBuildRequirements(tt.builders)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_FromReaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []Policy
		builders []string
		expected error
	}{
		{
			name: "valid policy",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
		},
		{
			name: "builder name not present in org policy",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "other_builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "publication uri re-use",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "publication uri re-use same env",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
						Environment: Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
						Environment: Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "publication uri re-use different env",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
						Environment: Environment{
							AnyOf: []string{"prod"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
						Environment: Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
		},
		{
			name: "builder not set",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty builder name",
			policies: []Policy{
				Policy{
					Format: 1,
					Publication: Publication{
						URI: "uri_set",
					},
					BuildRequirements: BuildRequirements{
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty repository uri",
			policies: []Policy{
				Policy{
					Format: 1,
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create the org policy (only the buildr names are needed).
			orgPolicy := organization.Policy{}
			for i := range tt.builders {
				orgPolicy.Roots.Build = append(orgPolicy.Roots.Build, organization.Root{Name: &tt.builders[i]})
			}

			// Marshal the project policies into bytes.
			policies := make([][]byte, len(tt.policies), len(tt.policies))
			for i := range tt.policies {
				content, err := json.Marshal(tt.policies[i])
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				policies[i] = content
			}
			// Create the project iterator.
			iter := common.NewBytesIterator(policies)

			// Call the constructor.
			_, err := FromReaders(iter, orgPolicy)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

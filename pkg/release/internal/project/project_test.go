package project

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
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

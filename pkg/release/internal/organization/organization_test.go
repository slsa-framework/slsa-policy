package organization

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
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

func Test_validateBuildRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name:     "empty build requirements",
			policy:   &Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "slsa level is negative",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(-1),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "slsa level is greater than 4",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(5),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "valid build requirements",
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(2),
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validateBuildRequirements()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateBuildRoots(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name:     "empty roots",
			policy:   &Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one root with empty id",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one root with empty name",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one root with empty level",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:   common.AsPointer("builder id"),
							Name: common.AsPointer("the name"),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one root with negative level",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(-1),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one root with level greater than 4",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(5),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one root with valid fields",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
		},
		{
			name: "two roots with valid fields",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							ID:        common.AsPointer("builder id2"),
							Name:      common.AsPointer("the name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
		},
		{
			name: "two roots with same id",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "two roots with same name",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("builder id"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							ID:        common.AsPointer("builder id2"),
							Name:      common.AsPointer("the name"),
							SlsaLevel: common.AsPointer(3),
						},
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

			err := tt.policy.validateBuildRoots()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_FromReader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name: "one build root valid",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
		},
		{
			name: "one build root empty id",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one build root empty name",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one build root empty level",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:   common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name: common.AsPointer("github_actions_level_3"),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one build root negative level",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(-1),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "one build root large level",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(5),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "no build roots",
			policy: &Policy{
				Format: 1,
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "no format",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "invalid format",
			policy: &Policy{
				Format: 2,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty build level requirement",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "negative build level requirement",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(-1),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "large build level requirement",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(5),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "two build roots valid",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							ID:        common.AsPointer("https://cloudbuild.googleapis.com/GoogleHostedWorker"),
							Name:      common.AsPointer("google_cloud_build_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
		},
		{
			name: "two build roots same name",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("https://github.com/actions/runner/github-hosted"),
							Name:      common.AsPointer("same_name"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							ID:        common.AsPointer("https://cloudbuild.googleapis.com/GoogleHostedWorker"),
							Name:      common.AsPointer("same_name"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "two build roots same id",
			policy: &Policy{
				Format: 1,
				Roots: Roots{
					Build: []Root{
						{
							ID:        common.AsPointer("same_id"),
							Name:      common.AsPointer("github_actions_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							ID:        common.AsPointer("same_id"),
							Name:      common.AsPointer("google_cloud_build_level_3"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Marshal the structure.
			content, err := json.Marshal(*tt.policy)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			reader := bytes.NewReader(content)
			_, err = FromReader(reader)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}
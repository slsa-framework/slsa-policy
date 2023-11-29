package organization

import (
	"bytes"
	"encoding/json"
	"io"
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

func Test_RootBuilderNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		builders []string
	}{
		{
			name: "set builders",
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							Name: common.AsPointer("builder1"),
						},
						{
							Name: common.AsPointer("builder2"),
						},
						{
							Name: common.AsPointer("builder3"),
						},
					},
				},
			},
			builders: []string{"builder1", "builder2", "builder3"},
		},
		{
			name:   "empty builders",
			policy: &Policy{},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			builders := tt.policy.RootBuilderNames()
			if diff := cmp.Diff(tt.builders, builders); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_BuilderSlsaLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  *Policy
		builder string
		level   int
	}{
		{
			name:    "builder 1",
			builder: "builder1",
			level:   1,
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							Name:      common.AsPointer("builder1"),
							SlsaLevel: common.AsPointer(1),
						},
						{
							Name:      common.AsPointer("builder2"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							Name:      common.AsPointer("builder3"),
							SlsaLevel: common.AsPointer(2),
						},
					},
				},
			},
		},
		{
			name:    "builder 2",
			builder: "builder2",
			level:   3,
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							Name:      common.AsPointer("builder1"),
							SlsaLevel: common.AsPointer(1),
						},
						{
							Name:      common.AsPointer("builder2"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							Name:      common.AsPointer("builder3"),
							SlsaLevel: common.AsPointer(2),
						},
					},
				},
			},
		},
		{
			name:    "builder 3",
			builder: "builder3",
			level:   2,
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							Name:      common.AsPointer("builder1"),
							SlsaLevel: common.AsPointer(1),
						},
						{
							Name:      common.AsPointer("builder2"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							Name:      common.AsPointer("builder3"),
							SlsaLevel: common.AsPointer(2),
						},
					},
				},
			},
		},
		{
			name:    "unknown builder",
			builder: "unknown",
			level:   -1,
			policy: &Policy{
				Roots: Roots{
					Build: []Root{
						{
							Name:      common.AsPointer("builder1"),
							SlsaLevel: common.AsPointer(1),
						},
						{
							Name:      common.AsPointer("builder2"),
							SlsaLevel: common.AsPointer(3),
						},
						{
							Name:      common.AsPointer("builder3"),
							SlsaLevel: common.AsPointer(2),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			level := tt.policy.BuilderSlsaLevel(tt.builder)
			if diff := cmp.Diff(tt.level, level); diff != "" {
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
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "no build roots",
			policy: &Policy{
				Format: 1,
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
			reader := io.NopCloser(bytes.NewReader(content))
			_, err = FromReader(reader)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name:   "passes",
			policy: &Policy{},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.Evaluate("any_repo", nil)
			if diff := cmp.Diff(tt.expected, err); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

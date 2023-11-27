package organization

import (
	"path/filepath"
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

func Test_FromFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name: "one build root valid",
			path: "valid-one-buildroot.json",
		},
		{
			name:     "one build root empty id",
			path:     "one-buildroot-empty-id.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "one build root empty name",
			path:     "one-buildroot-empty-name.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "one build root empty level",
			path:     "one-buildroot-empty-level.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "one build root negative level",
			path:     "one-buildroot-negative-level.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "one build root large level",
			path:     "one-buildroot-large-level.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "no build roots",
			path:     "no-buildroot.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "no format",
			path:     "no-format.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "invalid format",
			path:     "invalid-format.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "empty build level requirement",
			path:     "empty-build-level-requirement.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "negative build level requirement",
			path:     "negative-build-level-requirement.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "large build level requirement",
			path:     "large-build-level-requirement.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name: "two build roots valid",
			path: "valid-two-buildroots.json",
		},
		{
			name:     "two build roots same name",
			path:     "two-buildroots-same-name.json",
			expected: errs.ErrorInvalidField,
		},
		{
			name:     "two build roots same id",
			path:     "two-buildroots-same-id.json",
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := FromFile(filepath.Join("testdata", tt.path))
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

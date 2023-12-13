package organization

import (
	// "bytes"
	// "encoding/json"
	// "io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
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

func Test_RootReleaserNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		policy    *Policy
		releasers []string
	}{
		{
			name: "set releasers",
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							Name: "releaser1",
						},
						{
							Name: "releaser2",
						},
						{
							Name: "releaser3",
						},
					},
				},
			},
			releasers: []string{"releaser1", "releaser2", "releaser3"},
		},
		{
			name:   "empty releasers",
			policy: &Policy{},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			releasers := tt.policy.RootReleaserNames()
			if diff := cmp.Diff(tt.releasers, releasers); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_ReleaserBuildMaxSlsaLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		releaser string
		level    int
	}{
		{
			name:     "releaser 1",
			releaser: "releaser1",
			level:    1,
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							Name: "releaser1",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							Name: "releaser2",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							Name: "releaser3",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
		},
		{
			name:     "releaser 2",
			releaser: "releaser2",
			level:    3,
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							Name: "releaser1",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							Name: "releaser2",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							Name: "releaser3",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
		},
		{
			name:     "releaser 3",
			releaser: "releaser3",
			level:    2,
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							Name: "releaser1",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							Name: "releaser2",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							Name: "releaser3",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
		},
		{
			name:     "unknown releaser",
			releaser: "unknown",
			level:    -1,
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							Name: "releaser1",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							Name: "releaser2",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							Name: "releaser3",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
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
			level := tt.policy.ReleaserBuildMaxSlsaLevel(tt.releaser)
			if diff := cmp.Diff(tt.level, level); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateReleaseRoots(t *testing.T) {
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
					Release: []Root{
						{
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
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
					Release: []Root{
						{
							ID: "releaser id",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
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
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
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
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(-1),
							},
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
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(5),
							},
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
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
					},
				},
			},
		},
		{
			name: "two roots with valid fields",
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID:   "releaser id2",
							Name: "the name2",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
					},
				},
			},
		},
		{
			name: "two roots with same id",
			policy: &Policy{
				Roots: Roots{
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID:   "releaser id",
							Name: "the name2",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
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
					Release: []Root{
						{
							ID:   "releaser id",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID:   "releaser id2",
							Name: "the name",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
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

			err := tt.policy.validateReleaseRoots()
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
			err := tt.policy.Evaluate(intoto.DigestSet{}, "any_package_uri", options.ReleaseVerification{})
			if diff := cmp.Diff(tt.expected, err); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

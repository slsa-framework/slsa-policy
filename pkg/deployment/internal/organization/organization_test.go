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

func Test_MaxBuildSlsaLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy Policy
		level  int
	}{
		{
			name:  "max different values",
			level: 4,
			policy: Policy{
				Roots: Roots{
					Publish: []Root{
						{
							Build: Build{
								MaxSlsaLevel: common.AsPointer(4),
							},
						},
						{
							Build: Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
					},
				},
			},
		},
		{
			name:  "max same values",
			level: 2,
			policy: Policy{
				Roots: Roots{
					Publish: []Root{
						{
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
						{
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
						{
							Build: Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
		},
		{
			name:  "empty values",
			level: -1,
			policy: Policy{
				Roots: Roots{
					Publish: []Root{},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			level := tt.policy.MaxBuildSlsaLevel()
			if diff := cmp.Diff(tt.level, level); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validatePublishRoots(t *testing.T) {
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
					Publish: []Root{
						{
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
					Publish: []Root{
						{
							ID: "publishr id",
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
					Publish: []Root{
						{
							ID: "publishr id",
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
					Publish: []Root{
						{
							ID: "publishr id",
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
					Publish: []Root{
						{
							ID: "publishr id",
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
					Publish: []Root{
						{
							ID: "publishr id",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: "publishr id2",
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
					Publish: []Root{
						{
							ID: "publishr id",
							Build: Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: "publishr id",
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

			err := tt.policy.validatePublishRoots()
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
			err := tt.policy.Evaluate(intoto.DigestSet{}, "any_package_name", options.PublishVerification{})
			if diff := cmp.Diff(tt.expected, err); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

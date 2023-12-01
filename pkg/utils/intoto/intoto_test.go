package intoto

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
)

func Test_ValidateSubject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		subject  Subject
		expected error
	}{
		{
			name: "valid subject",
			subject: Subject{
				URI: "the_uri",
				Digests: DigestSet{
					"sha256":    "some_value",
					"gitCommit": "another_value",
				},
			},
		},
		{
			name: "no uri",
			subject: Subject{
				Digests: DigestSet{
					"sha256":    "some_value",
					"gitCommit": "another_value",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "not digests",
			subject: Subject{
				URI: "the_uri",
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty digest key",
			subject: Subject{
				URI: "the_uri",
				Digests: DigestSet{
					"sha256": "some_value",
					"":       "another_value",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty digest value",
			subject: Subject{
				URI: "the_uri",
				Digests: DigestSet{
					"sha256":    "some_value",
					"gitCommit": "",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.subject.Validate()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_ValidateDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		digests  DigestSet
		expected error
	}{
		{
			name: "valid digests",
			digests: DigestSet{
				"sha256":    "some_value",
				"gitCommit": "another_value",
			},
		},
		{
			name:     "empty digests",
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty key",
			digests: DigestSet{
				"sha256": "some_value",
				"":       "another_value",
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty value",
			digests: DigestSet{
				"sha256":    "some_value",
				"gitCommit": "",
			},
			expected: errs.ErrorInvalidInput,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.digests.Validate()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

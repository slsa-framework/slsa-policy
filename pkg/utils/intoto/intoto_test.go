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
				Digests: DigestSet{
					"sha256":    "some_value",
					"gitCommit": "another_value",
				},
			},
		},
		{
			name:     "not digests",
			subject:  Subject{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty digest key",
			subject: Subject{
				Digests: DigestSet{
					"sha256": "some_value",
					"":       "another_value",
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty digest value",
			subject: Subject{
				Digests: DigestSet{
					"sha256":    "some_value",
					"gitCommit": "",
				},
			},
			expected: errs.ErrorInvalidField,
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
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty key",
			digests: DigestSet{
				"sha256": "some_value",
				"":       "another_value",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty value",
			digests: DigestSet{
				"sha256":    "some_value",
				"gitCommit": "",
			},
			expected: errs.ErrorInvalidField,
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

func Test_ValidateResource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pkg      PackageDescriptor
		expected error
	}{
		{
			name: "valid descriptor",
			pkg: PackageDescriptor{
				Name:     "name",
				Registry: "registry",
			},
		},
		{
			name:     "empty name",
			expected: errs.ErrorInvalidField,
			pkg: PackageDescriptor{
				Registry: "registry",
			},
		},
		{
			name:     "empty registry",
			expected: errs.ErrorInvalidField,
			pkg: PackageDescriptor{
				Name: "name",
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.pkg.Validate()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_GetAnnotationValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		anno     map[string]interface{}
		value    string
		expected error
	}{
		{
			name: "nil annotations",
		},
		{
			name: "empty annotations",
			anno: map[string]interface{}{},
		},
		{
			name: "anno with empty value",
			anno: map[string]interface{}{
				"key": "",
			},
		},
		{
			name: "anno with non empty value",
			anno: map[string]interface{}{
				"key": "value",
			},
			value: "value",
		},
		{
			name: "anno with non string value",
			anno: map[string]interface{}{
				"key": 123,
			},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			val, err := GetAnnotationValue(tt.anno, "key")
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.value, val); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

package release

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

// TODO: support time creation.
func Test_CreationNew(t *testing.T) {
	t.Parallel()
	subject := intoto.Subject{
		Digests: intoto.DigestSet{
			"sha256":    "some_value",
			"gitCommit": "another_value",
		},
	}
	packageName := "package_name"
	packageRegistry := "package_registry"
	packageDesc := intoto.PackageDescriptor{
		Name:     packageName,
		Registry: packageRegistry,
	}
	tests := []struct {
		name        string
		subject     intoto.Subject
		buildLevel  *int
		packageDesc intoto.PackageDescriptor
		expected    error
	}{
		{
			name:        "subject and package set",
			subject:     subject,
			packageDesc: packageDesc,
		},
		{
			name:     "result with no package URI",
			subject:  subject,
			expected: errs.ErrorInvalidField,
		},
		{
			name:        "result with no subject digests",
			subject:     intoto.Subject{},
			packageDesc: packageDesc,
			expected:    errs.ErrorInvalidField,
		},
		{
			name: "result with empty digest value",
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "some_value",
					"gitCommit": "",
				},
			},
			packageDesc: packageDesc,
			expected:    errs.ErrorInvalidField,
		},
		{
			name: "result with empty digest key",
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256": "some_value",
					"":       "another_value",
				},
			},
			packageDesc: packageDesc,
			expected:    errs.ErrorInvalidField,
		},
		{
			name:        "result with level",
			subject:     subject,
			packageDesc: packageDesc,
			buildLevel:  common.AsPointer(2),
		},
		{
			name:        "result with negative level",
			subject:     subject,
			packageDesc: packageDesc,
			buildLevel:  common.AsPointer(-1),
			expected:    errs.ErrorInvalidInput,
		},
		{
			name:        "result with large level",
			subject:     subject,
			packageDesc: packageDesc,
			buildLevel:  common.AsPointer(5),
			expected:    errs.ErrorInvalidInput,
		},
		{
			name:    "result with env",
			subject: subject,
			packageDesc: intoto.PackageDescriptor{
				Name:        packageName,
				Registry:    packageRegistry,
				Environment: "prod",
			},
		},
		{
			name:        "result with all set",
			subject:     subject,
			packageDesc: packageDesc,
			buildLevel:  common.AsPointer(4),
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var options []AttestationCreationOption
			if tt.buildLevel != nil {
				options = append(options, SetSlsaBuildLevel(*tt.buildLevel))
			}
			att, err := CreationNew(tt.subject, tt.packageDesc, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Statement type verification.
			if diff := cmp.Diff(statementType, att.Header.Type); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// predicate type verification.
			if diff := cmp.Diff(predicateType, att.Header.PredicateType); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Subjects must match.
			if diff := cmp.Diff([]intoto.Subject{tt.subject}, att.Header.Subjects); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Package resource must match.
			if diff := cmp.Diff(tt.packageDesc, att.Predicate.Package); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// SLSA Levels must match.
			if tt.buildLevel != nil {
				if diff := cmp.Diff(*tt.buildLevel, att.Predicate.Properties[buildLevelProperty]); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			} else {
				if diff := cmp.Diff(properties(nil), att.Predicate.Properties); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			}
		})
	}
}

func Test_EnterSafeMode(t *testing.T) {
	t.Parallel()
	subject := intoto.Subject{
		Digests: intoto.DigestSet{
			"sha256":    "some_value",
			"gitCommit": "another_value",
		},
	}
	packageName := "package_name"
	packageRegistry := "package_registry"
	packageVersion := "v1.2.3"
	packageDesc := intoto.PackageDescriptor{
		Name:     packageName,
		Registry: packageRegistry,
		Version:  packageVersion,
	}
	tests := []struct {
		name        string
		subject     intoto.Subject
		packageDesc intoto.PackageDescriptor
		options     []AttestationCreationOption
		expected    error
	}{
		{
			name:        "subject only",
			subject:     subject,
			packageDesc: packageDesc,
		},
		{
			name:        "safe mode allowed setters",
			subject:     subject,
			packageDesc: packageDesc,
			options: []AttestationCreationOption{
				EnterSafeMode(),
				// TODO: Add setters here.
			},
		},
		{
			name:        "safe mode then level",
			subject:     subject,
			packageDesc: packageDesc,
			options: []AttestationCreationOption{
				EnterSafeMode(),
				SetSlsaBuildLevel(4),
			},
			expected: errs.ErrorInternal,
		},
		{
			name:        "level then safe mode",
			subject:     subject,
			packageDesc: packageDesc,
			options: []AttestationCreationOption{
				SetSlsaBuildLevel(4),
				EnterSafeMode(),
			},
		},
		{
			name:        "level then safe mode then allowed setters",
			subject:     subject,
			packageDesc: packageDesc,
			options: []AttestationCreationOption{
				SetSlsaBuildLevel(4),
				EnterSafeMode(),
				// TODO: Add setters here.
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := CreationNew(tt.subject, tt.packageDesc, tt.options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
		})
	}
}

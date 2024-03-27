package release

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_verifyDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		attDigests   intoto.DigestSet
		inputDigests intoto.DigestSet
		expected     error
	}{
		{
			name: "same digests",
			attDigests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "mismatch_another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
				"sha256":    "another",
			},
		},
		{
			name: "subset in attestations",
			attDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
			},
		},
		{
			name: "empty input digests",
			attDigests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "mismatch_another_com",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty att digests",
			inputDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
				"sha256":    "another",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "different digest names",
			attDigests: intoto.DigestSet{
				"a-sha256":    "another",
				"a-gitCommit": "mismatch_another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
				"sha256":    "another",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "mismatch sha256 digest",
			attDigests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "mismatch_another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
				"sha256":    "another",
			},
			expected: errs.ErrorMismatch,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := verifyDigests(tt.attDigests, tt.inputDigests)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

// TODO: split up the function?
// TODO: support time verification.
func Test_Verify(t *testing.T) {
	t.Parallel()
	digests := intoto.DigestSet{
		"sha256":    "another",
		"gitCommit": "another_com",
	}
	subjects := []intoto.Subject{
		intoto.Subject{
			Digests: digests,
		},
	}
	prod := "prod"
	header := intoto.Header{
		Type:          statementType,
		PredicateType: predicateType,
		Subjects:      subjects,
	}
	releaseProperties := map[string]interface{}{
		buildLevelProperty: 3,
	}
	packageName := "package_name"
	packageRegistry := "package_registry"
	packageVersion := "1.2.3"
	packageEnv := "prod"
	packageDesc := intoto.PackageDescriptor{
		Name:        packageName,
		Registry:    packageRegistry,
		Version:     packageVersion,
		Environment: packageEnv,
	}
	pred := predicate{
		CreationTime: intoto.Now(),
		Package:      packageDesc,
		Properties:   releaseProperties,
	}
	att := attestation{
		Header:    header,
		Predicate: pred,
	}
	buildLevel := common.AsPointer(3)
	tests := []struct {
		name               string
		att                attestation
		digests            intoto.DigestSet
		packageVersion     string
		packageName        string
		packageEnvironment string
		buildLevel         *int
		expected           error
	}{
		{
			name:               "all fields set",
			att:                att,
			packageVersion:     packageVersion,
			packageName:        packageName,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			digests:            digests,
		},
		{
			name: "mismatch statement type",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType + "q",
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "mismatch predicate type",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType + "a",
					Subjects:      subjects,
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch package version",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     "1.2.4",
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "no input package version",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			digests:            digests,
		},
		{
			name: "no att package version",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicate{
					CreationTime: intoto.Now(),
					Package: intoto.PackageDescriptor{
						Name:        packageName,
						Registry:    packageRegistry,
						Environment: packageEnv,
					},
					Properties: releaseProperties,
				},
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "empty att uri",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicate{
					CreationTime: intoto.Now(),
					// NOTE: no package set so empty URI.
					Properties: releaseProperties,
				},
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "empty request uri",
			att:                att,
			packageVersion:     packageVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			digests:            digests,
			expected:           errs.ErrorInvalidField,
		},
		{
			name: "empty att subject",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "empty input subject",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			expected:           errs.ErrorInvalidField,
		},
		{
			name: "empty att digest key",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256": "another",
								"":       "mismatch_another_com",
							},
						},
					},
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "empty input digest key",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"sha256": "another",
				"":       "mismatch_another_com",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty att digest value",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "",
							},
						},
					},
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorInvalidField,
		},
		{
			name: "empty input digest value",
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "mismatch_another_com",
							},
						},
					},
				},
				Predicate: pred,
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name:               "mismatch sha256 digest",
			att:                att,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			buildLevel:         buildLevel,
			digests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "mismatch_another_com",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch gitCommit digest",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "mismatch_another_com",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch digest not present",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"other":  "another",
				"other2": "mismatch_another_com",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name:               "one of digests",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"gitCommit": "another_com",
			},
		},
		{
			name:               "input no digest",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "mismatch level",
			att:                att,
			buildLevel:         common.AsPointer(1),
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch env",
			att:                att,
			buildLevel:         buildLevel,
			packageEnvironment: "dev",
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "mismatch no env att",
			att: attestation{
				Header: header,
				Predicate: predicate{
					CreationTime: intoto.Now(),
					Package: intoto.PackageDescriptor{
						Name:     packageName,
						Registry: packageRegistry,
						Version:  packageVersion,
					},
					Properties: releaseProperties,
				},
			},
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name:           "mismatch no env input",
			att:            att,
			packageName:    packageName,
			packageVersion: packageVersion,
			buildLevel:     buildLevel,
			digests:        digests,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "no env no version",
			att: attestation{
				Header: header,
				Predicate: predicate{
					CreationTime: intoto.Now(),
					Package: intoto.PackageDescriptor{
						Name:     packageName,
						Registry: packageRegistry,
					},
					Properties: releaseProperties,
				},
			},
			buildLevel:  buildLevel,
			packageName: packageName,
			digests:     digests,
		},
		{
			name: "level not present empty properties",
			att: attestation{
				Header: header,
				Predicate: predicate{
					CreationTime: intoto.Now(),
					Package:      packageDesc,
				},
			},
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "level field not present",
			att: attestation{
				Header: header,
				Predicate: predicate{
					CreationTime: intoto.Now(),
					Package:      packageDesc,
					Properties: map[string]interface{}{
						buildLevelProperty + "a": 3,
					},
				},
			},
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			expected:           errs.ErrorMismatch,
		},
		// Ignored fields.
		{
			name:               "ignore build level",
			att:                att,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
		},
		{
			name:           "ignore env",
			att:            att,
			buildLevel:     buildLevel,
			packageName:    packageName,
			packageVersion: packageVersion,
			digests:        digests,
			expected:       errs.ErrorMismatch,
		},
		{
			name:               "ignore digests",
			att:                att,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			expected:           errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create the reader for initialization.
			content, err := json.Marshal(tt.att)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			reader := io.NopCloser(bytes.NewReader(content))
			verification, err := VerificationNew(reader, newPackageHelper(tt.att.Predicate.Package.Registry))
			if err != nil {
				t.Fatalf("failed to creation verification: %v", err)
			}

			// Create verification options.
			var options []VerificationOption
			if tt.buildLevel != nil {
				options = append(options, IsSlsaBuildLevel(*tt.buildLevel))
				i := 1
				for i <= *tt.buildLevel {
					options = append(options, IsSlsaBuildLevelOrAbove(i))
					i++
				}
			}
			if tt.packageVersion != "" {
				options = append(options, IsPackageVersion(tt.packageVersion))
			}
			options = append(options, IsPackageEnvironment(tt.packageEnvironment))

			// Verify.
			err = verification.Verify(tt.digests, tt.packageName, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Ensure verification fails for IsSlsaBuildLevelOrAbove(level+).
			if tt.buildLevel != nil {
				i := *tt.buildLevel + 1
				for i <= 4 {
					options = append(options, IsSlsaBuildLevelOrAbove(i))
					i++
				}
				err = verification.Verify(tt.digests, tt.packageName, options...)
				if diff := cmp.Diff(errs.ErrorMismatch, err, cmpopts.EquateErrors()); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			}
		})
	}
}

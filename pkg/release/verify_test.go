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
	policy := map[string]intoto.Policy{
		"org": {
			URI: "org_uri",
			Digests: intoto.DigestSet{
				"sha256":    "org_256",
				"gitCommit": "org_commit",
			},
		},
		"project": {
			URI: "project_uri",
			Digests: intoto.DigestSet{
				"sha256":    "project_256",
				"gitCommit": "project_commit",
			},
		},
	}
	creatorID := "creatorID"
	creatorVersion := "creatorVersion"
	creator := intoto.Creator{
		ID:      creatorID,
		Version: creatorVersion,
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
		Creator:      creator,
		Policy:       policy,
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
		creatorID          string
		creatorVersion     string
		packageVersion     string
		packageName        string
		packageEnvironment string
		buildLevel         *int
		policy             map[string]intoto.Policy
		expected           error
	}{
		{
			name:               "all fields set",
			att:                att,
			creatorID:          creatorID,
			packageVersion:     packageVersion,
			packageName:        packageName,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			digests:            digests,
			policy:             policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch creator id",
			att:                att,
			creatorID:          creatorID + "_mismatch",
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch creator version",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion + "_mismatch",
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch package version",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     "1.2.4",
			digests:            digests,
			policy:             policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			digests:            digests,
			policy:             policy,
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
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.PackageDescriptor{
						Name:        packageName,
						Registry:    packageRegistry,
						Environment: packageEnv,
					},
					Properties: releaseProperties,
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
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
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					// NOTE: no package set so empty URI.
					Properties: releaseProperties,
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "empty request uri",
			att:                att,
			creatorID:          creatorID,
			packageVersion:     packageVersion,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			digests:            digests,
			policy:             policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "empty input subject",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			policy:             policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "empty input digest key",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"sha256": "another",
				"":       "mismatch_another_com",
			},
			policy:   policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
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
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "",
			},
			policy:   policy,
			expected: errs.ErrorInvalidField,
		},
		{
			name:               "mismatch sha256 digest",
			att:                att,
			creatorID:          creatorID,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			digests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "mismatch_another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch gitCommit digest",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "mismatch_another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch digest not present",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"other":  "another",
				"other2": "mismatch_another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:               "one of digests",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests: intoto.DigestSet{
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name:               "input no digest",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "mismatch level",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         common.AsPointer(1),
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch env",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: "dev",
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "mismatch no env att",
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.PackageDescriptor{
						Name:     packageName,
						Registry: packageRegistry,
						Version:  packageVersion,
					},
					Properties: releaseProperties,
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageName:        packageName,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:           "mismatch no env input",
			att:            att,
			creatorID:      creatorID,
			packageName:    packageName,
			packageVersion: packageVersion,
			creatorVersion: creatorVersion,
			buildLevel:     buildLevel,
			digests:        digests,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "no env no version",
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.PackageDescriptor{
						Name:     packageName,
						Registry: packageRegistry,
					},
					Properties: releaseProperties,
				},
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			buildLevel:     buildLevel,
			packageName:    packageName,
			digests:        digests,
			policy:         policy,
		},
		{
			name:               "mismatch no org",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy: map[string]intoto.Policy{
				"not_org": {
					URI: "org_uri",
					Digests: intoto.DigestSet{
						"sha256":    "org_256",
						"gitCommit": "org_commit",
					},
				},
				"project": {
					URI: "project_uri",
					Digests: intoto.DigestSet{
						"sha256":    "project_256",
						"gitCommit": "project_commit",
					},
				},
			},
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch org uri",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy: map[string]intoto.Policy{
				"org": {
					URI: "no_org_uri",
					Digests: intoto.DigestSet{
						"sha256":    "org_256",
						"gitCommit": "org_commit",
					},
				},
				"project": {
					URI: "project_uri",
					Digests: intoto.DigestSet{
						"sha256":    "project_256",
						"gitCommit": "project_commit",
					},
				},
			},
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch org sha256",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy: map[string]intoto.Policy{
				"org": {
					URI: "org_uri",
					Digests: intoto.DigestSet{
						"sha256":    "no_org_256",
						"gitCommit": "org_commit",
					},
				},
				"project": {
					URI: "project_uri",
					Digests: intoto.DigestSet{
						"sha256":    "project_256",
						"gitCommit": "project_commit",
					},
				},
			},
			expected: errs.ErrorMismatch,
		},
		{
			name:               "mismatch org gitCommit",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy: map[string]intoto.Policy{
				"org": {
					URI: "org_uri",
					Digests: intoto.DigestSet{
						"sha256":    "org_256",
						"gitCommit": "no_org_commit",
					},
				},
				"project": {
					URI: "project_uri",
					Digests: intoto.DigestSet{
						"sha256":    "project_256",
						"gitCommit": "project_commit",
					},
				},
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "level not present empty properties",
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package:      packageDesc,
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "level field not present",
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package:      packageDesc,
					Properties: map[string]interface{}{
						buildLevelProperty + "a": 3,
					},
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		// Ignored fields.
		{
			name:               "ignore creator version",
			att:                att,
			creatorID:          creatorID,
			buildLevel:         common.AsPointer(3),
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
		},
		{
			name:               "ignore build level",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
		},
		{
			name:           "ignore env",
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			buildLevel:     buildLevel,
			packageName:    packageName,
			packageVersion: packageVersion,
			digests:        digests,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:               "ignore digests",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "ignore creator id",
			att:                att,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name:               "ignore policy",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageName:        packageName,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
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
			var options []AttestationVerificationOption
			if tt.creatorVersion != "" {
				options = append(options, IsCreatorVersion(tt.creatorVersion))
			}
			if tt.buildLevel != nil {
				options = append(options, IsSlsaBuildLevel(*tt.buildLevel))
				i := 1
				for i <= *tt.buildLevel {
					options = append(options, IsSlsaBuildLevelOrAbove(i))
					i++
				}
			}
			for name, policy := range tt.policy {
				options = append(options, HasPolicy(name, policy.URI, policy.Digests))
			}
			if tt.packageVersion != "" {
				options = append(options, IsPackageVersion(tt.packageVersion))
			}
			options = append(options, IsPackageEnvironment(tt.packageEnvironment))

			// Verify.
			err = verification.Verify(tt.creatorID, tt.digests, tt.packageName, options...)
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
				err = verification.Verify(tt.creatorID, tt.digests, tt.packageName, options...)
				if diff := cmp.Diff(errs.ErrorMismatch, err, cmpopts.EquateErrors()); diff != "" {
					t.Fatalf("unexpected err (-want +got): \n%s", diff)
				}
			}
		})
	}
}

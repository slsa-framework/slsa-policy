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

func Test_verifyAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		attAnnotation   map[string]interface{}
		inputAnnotation map[string]interface{}
		expected        error
	}{
		{
			name: "same nil annotations",
		},
		{
			name:            "same empty annotations",
			attAnnotation:   map[string]interface{}{},
			inputAnnotation: map[string]interface{}{},
		},
		{
			name:          "att empty input nil",
			attAnnotation: map[string]interface{}{},
		},
		{
			name:            "att nil input empty",
			inputAnnotation: map[string]interface{}{},
		},
		{
			name: "att empty key value, input nil",
			attAnnotation: map[string]interface{}{
				"key": "",
			},
		},
		{
			name: "att nil, input empty key value",
			inputAnnotation: map[string]interface{}{
				"key": "",
			},
		},
		{
			name: "att empty key value, input empty key value",
			attAnnotation: map[string]interface{}{
				"key": "",
			},
			inputAnnotation: map[string]interface{}{
				"key": "",
			},
		},
		{
			name: "att and input same key value",
			attAnnotation: map[string]interface{}{
				"key": "val",
			},
			inputAnnotation: map[string]interface{}{
				"key": "val",
			},
		},
		{
			name: "att and input mismatch key value",
			attAnnotation: map[string]interface{}{
				"key": "val1",
			},
			inputAnnotation: map[string]interface{}{
				"key": "val",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "att nil",
			inputAnnotation: map[string]interface{}{
				"key": "val",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "input nil",
			attAnnotation: map[string]interface{}{
				"key": "val",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "input empty",
			attAnnotation: map[string]interface{}{
				"key": "val",
			},
			inputAnnotation: map[string]interface{}{},
			expected:        errs.ErrorMismatch,
		},
		{
			name: "att empty",
			inputAnnotation: map[string]interface{}{
				"key": "val",
			},
			attAnnotation: map[string]interface{}{},
			expected:      errs.ErrorMismatch,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := Verification{
				attestation: attestation{
					Predicate: predicate{
						Package: intoto.ResourceDescriptor{
							Annotations: tt.attAnnotation,
						},
					},
				},
			}
			err := v.verifyAnnotation(tt.inputAnnotation, "key")
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
	packageVersion := "1.2.3"
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
	packageURI := "package_uri"
	packageDesc := intoto.ResourceDescriptor{
		URI: packageURI,
		Annotations: map[string]interface{}{
			environmentAnnotation: "prod",
			versionAnnotation:     "1.2.3",
		},
	}
	pred := predicate{
		Creator:      creator,
		Policy:       policy,
		CreationTime: intoto.Now(),
		Package:      packageDesc,
		Properties:   releaseProperties,
	}
	att := &attestation{
		Header:    header,
		Predicate: pred,
	}
	buildLevel := common.AsPointer(3)
	tests := []struct {
		name               string
		att                *attestation
		digests            intoto.DigestSet
		creatorID          string
		creatorVersion     string
		packageVersion     string
		packageURI         string
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
			packageURI:         packageURI,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			digests:            digests,
			policy:             policy,
		},
		{
			name: "mismatch statement type",
			att: &attestation{
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
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "mismatch predicate type",
			att: &attestation{
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
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch creator id",
			att:                att,
			creatorID:          "mismatch_creatorID",
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:               "mismatch creator version",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     "mismatch_creatorVersion",
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageURI:         packageURI,
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
			packageURI:         packageURI,
			packageVersion:     "1.2.4",
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "no input package version",
			att: &attestation{
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
			packageURI:         packageURI,
			digests:            digests,
			policy:             policy,
		},
		{
			name: "no att package version",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.ResourceDescriptor{
						URI: "the_uri",
						Annotations: map[string]interface{}{
							environmentAnnotation: "prod",
						},
					},
					Properties: releaseProperties,
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "empty att uri",
			att: &attestation{
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
			packageURI:         packageURI,
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
			att: &attestation{
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name: "empty att digest key",
			att: &attestation{
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			att: &attestation{
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
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorInvalidField,
		},
		{
			name: "empty input digest value",
			att: &attestation{
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "mismatch no env att",
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.ResourceDescriptor{
						URI: packageURI,
						Annotations: map[string]interface{}{
							versionAnnotation: "1.2.3",
						},
					},
					Properties: releaseProperties,
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageEnvironment: prod,
			packageURI:         packageURI,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name:           "mismatch no env input",
			att:            att,
			creatorID:      creatorID,
			packageURI:     packageURI,
			packageVersion: packageVersion,
			creatorVersion: creatorVersion,
			buildLevel:     buildLevel,
			digests:        digests,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "no env no version no annotations",
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.ResourceDescriptor{
						URI: packageURI,
					},
					Properties: releaseProperties,
				},
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			buildLevel:     buildLevel,
			packageURI:     packageURI,
			digests:        digests,
			policy:         policy,
		},
		{
			name:               "mismatch no org",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			name:               "mismatch org sha256",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageURI:         packageURI,
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
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.ResourceDescriptor{
						URI: packageURI,
					},
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageURI:         packageURI,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy:             policy,
			expected:           errs.ErrorMismatch,
		},
		{
			name: "level field not present",
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Package: intoto.ResourceDescriptor{
						URI: packageURI,
					},
					Properties: map[string]interface{}{
						buildLevelProperty + "a": 3,
					},
				},
			},
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			buildLevel:         buildLevel,
			packageURI:         packageURI,
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
			packageURI:         packageURI,
			packageEnvironment: prod,
			packageVersion:     packageVersion,
			digests:            digests,
			policy: map[string]intoto.Policy{
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
			},
		},
		{
			name:               "ignore build level",
			att:                att,
			creatorID:          creatorID,
			creatorVersion:     creatorVersion,
			packageURI:         packageURI,
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
			packageURI:     packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			packageURI:         packageURI,
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
			content, err := json.Marshal(*tt.att)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			reader := io.NopCloser(bytes.NewReader(content))
			verification, err := VerificationNew(reader)
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
			}
			for name, policy := range tt.policy {
				options = append(options, HasPolicy(name, policy.URI, policy.Digests))
			}
			if tt.packageVersion != "" {
				options = append(options, IsPackageVersion(tt.packageVersion))
			}
			options = append(options, IsPackageEnvironment(tt.packageEnvironment))

			// Verify.
			err = verification.Verify(tt.creatorID, tt.digests, tt.packageURI, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

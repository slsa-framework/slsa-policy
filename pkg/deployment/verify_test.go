package deployment

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	//"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
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

func Test_verifyContext(t *testing.T) {
	t.Parallel()
	contextType := "context_type"
	context := map[string][]string{
		"key1": []string{"val11", "val12"},
		"key2": []string{"val21", "val22"},
	}
	att := attestation{
		Predicate: predicate{
			ContextType: contextType,
			Context:     context,
		},
	}
	tests := []struct {
		name        string
		contextType string
		context     interface{}
		attestation attestation
		expected    error
	}{
		{
			name:        "match all set",
			attestation: att,
			contextType: contextType,
			context:     context,
		},
		{
			name: "match empty context",
			attestation: attestation{
				Predicate: predicate{
					ContextType: contextType,
				},
			},
			contextType: contextType,
		},
		{
			name:        "mismatch type",
			expected:    errs.ErrorMismatch,
			attestation: att,
			contextType: contextType + "_mismatch",
			context:     context,
		},
		{
			name:        "mismatch context key1",
			expected:    errs.ErrorMismatch,
			attestation: att,
			contextType: contextType,
			context: map[string][]string{
				"key1_mismatch": []string{"val11", "val12"},
				"key2":          []string{"val21", "val22"},
			},
		},
		{
			name:        "mismatch context val11",
			expected:    errs.ErrorMismatch,
			attestation: att,
			contextType: contextType,
			context: map[string][]string{
				"key1": []string{"val11_mismatch", "val12"},
				"key2": []string{"val21", "val22"},
			},
		},
		{
			name:        "mismatch context key2",
			expected:    errs.ErrorMismatch,
			attestation: att,
			contextType: contextType,
			context: map[string][]string{
				"key1":          []string{"val11", "val12"},
				"key2_mismatch": []string{"val21", "val22"},
			},
		},
		{
			name:        "mismatch context val22",
			expected:    errs.ErrorMismatch,
			attestation: att,
			contextType: contextType,
			context: map[string][]string{
				"key11": []string{"val11", "val12"},
				"key2":  []string{"val21", "val22_mismatch"},
			},
		},
		{
			name:        "mismatch empty context",
			expected:    errs.ErrorMismatch,
			attestation: att,
			contextType: contextType,
		},
		{
			name:     "mismatch empty context attestation",
			expected: errs.ErrorMismatch,
			attestation: attestation{
				Predicate: predicate{
					ContextType: contextType,
				},
			},
			contextType: contextType,
			context:     context,
		},
		{
			name:        "error empty type",
			expected:    errs.ErrorInvalidField,
			attestation: att,
			context:     context,
		},
		{
			name:     "error empty type attestation",
			expected: errs.ErrorInvalidField,
			attestation: attestation{
				Predicate: predicate{
					Context: context,
				},
			},
			contextType: contextType,
			context:     context,
		},
		{
			name:     "mismatch empty context attestation",
			expected: errs.ErrorMismatch,
			attestation: attestation{
				Predicate: predicate{
					ContextType: contextType,
				},
			},
			contextType: contextType,
			context:     context,
		},
		{
			name:     "error both empty type",
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			contextInt, err := asInterface(tt.attestation.Predicate.Context)
			if err != nil {
				t.Fatalf("failed to asInterface: %v", err)
			}
			verification := Verification{
				attestation: tt.attestation,
			}
			verification.attestation.Predicate.Context = contextInt
			err = verification.verifyContext(tt.contextType, tt.context)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

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
	contextType := "context_type"
	context := map[string][]string{
		"key1": []string{"val11", "val12"},
		"key2": []string{"val21", "val22"},
	}
	creatorID := "creatorID"
	creatorVersion := "creatorVersion"
	creator := intoto.Creator{
		ID:      creatorID,
		Version: creatorVersion,
	}
	header := intoto.Header{
		Type:          statementType,
		PredicateType: predicateType,
		Subjects:      subjects,
	}
	pred := predicate{
		Creator:      creator,
		Policy:       policy,
		CreationTime: intoto.Now(),
		ContextType:  contextType,
		Context:      context,
	}
	att := attestation{
		Header:    header,
		Predicate: pred,
	}
	tests := []struct {
		name           string
		att            attestation
		digests        intoto.DigestSet
		contextType    string
		context        interface{}
		creatorID      string
		creatorVersion string
		policy         map[string]intoto.Policy
		expected       error
	}{
		{
			name:           "all fields set",
			att:            att,
			contextType:    contextType,
			context:        context,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:     "mismatch statement type",
			expected: errs.ErrorMismatch,
			att: attestation{
				Header: intoto.Header{
					Type:          statementType + "q",
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: pred,
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:     "mismatch predicate type",
			expected: errs.ErrorMismatch,
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType + "a",
					Subjects:      subjects,
				},
				Predicate: pred,
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "mismatch creator id",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID + "_mismatch",
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "mismatch creator version",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion + "_mismatch",
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:     "empty att subject",
			expected: errs.ErrorInvalidField,
			att: attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
				},
				Predicate: pred,
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "empty input subject",
			expected:       errs.ErrorInvalidField,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			policy:         policy,
		},
		{
			name:     "empty att digest key",
			expected: errs.ErrorInvalidField,
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
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "empty input digest key",
			expected:       errs.ErrorInvalidField,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests: intoto.DigestSet{
				"sha256": "another",
				"":       "mismatch_another_com",
			},
			policy: policy,
		},
		{
			name:     "empty att digest value",
			expected: errs.ErrorInvalidField,
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
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:     "empty input digest value",
			expected: errs.ErrorInvalidField,
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
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "",
			},
			policy: policy,
		},
		{
			name:           "mismatch sha256 digest",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "mismatch_another_com",
			},
			policy: policy,
		},
		{
			name:           "mismatch gitCommit digest",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "mismatch_another_com",
			},
			policy: policy,
		},
		{
			name:           "mismatch digest not present",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests: intoto.DigestSet{
				"other":  "another",
				"other2": "mismatch_another_com",
			},
			policy: policy,
		},
		{
			name:           "one of digests",
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests: intoto.DigestSet{
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name:           "input no digest",
			expected:       errs.ErrorInvalidField,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			policy:         policy,
		},
		{
			name:           "mismatch no org",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
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
		},
		{
			name:           "mismatch org uri",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
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
		},
		{
			name:           "mismatch org sha256",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
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
		},
		{
			name:           "mismatch org gitCommit",
			expected:       errs.ErrorMismatch,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
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
		},
		{
			name:           "mismatch context type",
			expected:       errs.ErrorMismatch,
			att:            att,
			contextType:    contextType + "_mismatch",
			context:        context,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "error empty context type",
			expected:       errs.ErrorInvalidField,
			att:            att,
			context:        context,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:     "error empty context type att",
			expected: errs.ErrorInvalidField,
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					Context:      context,
				},
			},
			contextType:    contextType,
			context:        context,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name: "both empty context",
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					ContextType:  contextType,
				},
			},
			contextType:    contextType,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:        "mismatch context key1",
			expected:    errs.ErrorMismatch,
			att:         att,
			contextType: contextType,
			context: map[string][]string{
				"key1_mismatch": []string{"val11", "val12"},
				"key2":          []string{"val21", "val22"},
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:        "mismatch context key2",
			expected:    errs.ErrorMismatch,
			att:         att,
			contextType: contextType,
			context: map[string][]string{
				"key1":          []string{"val11", "val12"},
				"key2_mismatch": []string{"val21", "val22"},
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:        "mismatch context val12",
			expected:    errs.ErrorMismatch,
			att:         att,
			contextType: contextType,
			context: map[string][]string{
				"key1": []string{"val11", "val12_mismatch"},
				"key2": []string{"val21", "val22"},
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:        "mismatch context val22",
			expected:    errs.ErrorMismatch,
			att:         att,
			contextType: contextType,
			context: map[string][]string{
				"key1": []string{"val11", "val12"},
				"key2": []string{"val21", "val22_mismatch"},
			},
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "mismatch empty context",
			expected:       errs.ErrorMismatch,
			att:            att,
			contextType:    contextType,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		{
			name:     "mismatch empty context att",
			expected: errs.ErrorMismatch,
			att: attestation{
				Header: header,
				Predicate: predicate{
					Creator:      creator,
					Policy:       policy,
					CreationTime: intoto.Now(),
					ContextType:  contextType,
				},
			},
			contextType:    contextType,
			context:        context,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			digests:        digests,
			policy:         policy,
		},
		// Ignored fields.
		{
			name:        "ignore creator version",
			att:         att,
			creatorID:   creatorID,
			contextType: contextType,
			context:     context,
			digests:     digests,
			policy:      policy,
		},
		{
			name:           "ignore digests",
			expected:       errs.ErrorInvalidField,
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			policy:         policy,
		},
		{
			name:           "ignore creator id",
			expected:       errs.ErrorInvalidField,
			att:            att,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
			policy:         policy,
		},
		{
			name:           "ignore policy",
			att:            att,
			creatorID:      creatorID,
			creatorVersion: creatorVersion,
			contextType:    contextType,
			context:        context,
			digests:        digests,
		},
		{
			name:      "ignore context type",
			expected:  errs.ErrorInvalidField,
			att:       att,
			creatorID: creatorID,
			context:   context,
			digests:   digests,
			policy:    policy,
		},
		{
			name:        "ignore context",
			expected:    errs.ErrorMismatch,
			att:         att,
			creatorID:   creatorID,
			contextType: contextType,
			digests:     digests,
			policy:      policy,
		},
		{
			name:      "ignore context type",
			expected:  errs.ErrorInvalidField,
			att:       att,
			creatorID: creatorID,
			digests:   digests,
			policy:    policy,
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
			verification, err := VerificationNew(reader)
			if err != nil {
				t.Fatalf("failed to creation verification: %v", err)
			}

			// Create verification options.
			var options []AttestationVerificationOption
			if tt.creatorVersion != "" {
				options = append(options, IsCreatorVersion(tt.creatorVersion))
			}
			for name, policy := range tt.policy {
				options = append(options, HasPolicy(name, policy.URI, policy.Digests))
			}

			// Verify.
			err = verification.Verify(tt.creatorID, tt.digests, tt.contextType, tt.context, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

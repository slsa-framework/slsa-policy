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

func Test_verifyScopes(t *testing.T) {
	t.Parallel()
	scopes := map[string]string{
		"key1": "val1",
		"key2": "val2",
	}
	att := attestation{
		Predicate: predicate{
			Scopes: scopes,
		},
	}
	tests := []struct {
		name        string
		attestation attestation
		scopes      map[string]string
		expected    error
	}{
		{
			name:        "match all set",
			attestation: att,
			scopes:      scopes,
		},
		{
			name: "match empty scopes",
			attestation: attestation{
				Predicate: predicate{},
			},
		},
		{
			name:        "mismatch scopes key1",
			expected:    errs.ErrorMismatch,
			attestation: att,
			scopes: map[string]string{
				"key1_mismatch": "val1",
				"key2":          "val2",
			},
		},
		{
			name:        "mismatch scopes val1",
			expected:    errs.ErrorMismatch,
			attestation: att,
			scopes: map[string]string{
				"key1": "val1_mismatch",
				"key2": "val2",
			},
		},
		{
			name:        "mismatch scopes key2",
			expected:    errs.ErrorMismatch,
			attestation: att,
			scopes: map[string]string{
				"key1_":         "val1",
				"key2_mismatch": "val2",
			},
		},
		{
			name:        "mismatch scopes val2",
			expected:    errs.ErrorMismatch,
			attestation: att,
			scopes: map[string]string{
				"key1_": "val1",
				"key2":  "val2_mismatch",
			},
		},
		{
			name:        "mismatch empty scopes",
			expected:    errs.ErrorMismatch,
			attestation: att,
		},
		{
			name:     "mismatch empty scopes attestation",
			expected: errs.ErrorMismatch,
			attestation: attestation{
				Predicate: predicate{},
			},
			scopes: scopes,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verification := Verification{
				attestation: tt.attestation,
			}
			err := verification.verifyScopes(tt.scopes)
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
	scopes := map[string]string{
		"key1": "val1",
		"key2": "val2",
	}
	header := intoto.Header{
		Type:          statementType,
		PredicateType: predicateType,
		Subjects:      subjects,
	}
	pred := predicate{
		CreationTime: intoto.Now(),
		Scopes:       scopes,
	}
	att := attestation{
		Header:    header,
		Predicate: pred,
	}
	tests := []struct {
		name     string
		att      attestation
		digests  intoto.DigestSet
		scopes   map[string]string
		expected error
	}{
		{
			name:    "all fields set",
			att:     att,
			scopes:  scopes,
			digests: digests,
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
			scopes:  scopes,
			digests: digests,
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
			scopes:  scopes,
			digests: digests,
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
			scopes:  scopes,
			digests: digests,
		},
		{
			name:     "empty input subject",
			expected: errs.ErrorInvalidField,
			att:      att,
			scopes:   scopes,
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
			scopes:  scopes,
			digests: digests,
		},
		{
			name:     "empty input digest key",
			expected: errs.ErrorInvalidField,
			att:      att,
			scopes:   scopes,
			digests: intoto.DigestSet{
				"sha256": "another",
				"":       "mismatch_another_com",
			},
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
			scopes:  scopes,
			digests: digests,
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
			scopes: scopes,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "",
			},
		},
		{
			name:     "mismatch sha256 digest",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes:   scopes,
			digests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "mismatch_another_com",
			},
		},
		{
			name:     "mismatch gitCommit digest",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes:   scopes,
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "mismatch_another_com",
			},
		},
		{
			name:     "mismatch digest not present",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes:   scopes,
			digests: intoto.DigestSet{
				"other":  "another",
				"other2": "mismatch_another_com",
			},
		},
		{
			name:   "one of digests",
			att:    att,
			scopes: scopes,
			digests: intoto.DigestSet{
				"gitCommit": "another_com",
			},
		},
		{
			name:     "input no digest",
			expected: errs.ErrorInvalidField,
			att:      att,
			scopes:   scopes,
		},
		{
			name: "both empty scopes",
			att: attestation{
				Header: header,
				Predicate: predicate{
					CreationTime: intoto.Now(),
				},
			},
			digests: digests,
		},
		{
			name:     "mismatch scopes key1",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes: map[string]string{
				"key1_mismatch": "val1",
				"key2":          "val2",
			},
			digests: digests,
		},
		{
			name:     "mismatch scopes key2",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes: map[string]string{
				"key1":          "val1",
				"key2_mismatch": "val2",
			},
			digests: digests,
		},
		{
			name:     "mismatch context val1",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes: map[string]string{
				"key1": "val1_mismatch",
				"key2": "val2",
			},
			digests: digests,
		},
		{
			name:     "mismatch context val2",
			expected: errs.ErrorMismatch,
			att:      att,
			scopes: map[string]string{
				"key1": "val1",
				"key2": "val2_mismatch",
			},
			digests: digests,
		},
		{
			name:     "mismatch empty scopes",
			expected: errs.ErrorMismatch,
			att:      att,
			digests:  digests,
		},
		{
			name:     "mismatch empty scopes att",
			expected: errs.ErrorMismatch,
			att: attestation{
				Header: header,
				Predicate: predicate{
					CreationTime: intoto.Now(),
				},
			},
			scopes:  scopes,
			digests: digests,
		},
		// Ignored fields.
		{
			name:     "ignore digests",
			expected: errs.ErrorInvalidField,
			att:      att,
			scopes:   scopes,
		},
		{
			name:     "ignore scopes",
			expected: errs.ErrorMismatch,
			att:      att,
			digests:  digests,
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
			var options []VerificationOption

			// Verify.
			err = verification.Verify(tt.digests, tt.scopes, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

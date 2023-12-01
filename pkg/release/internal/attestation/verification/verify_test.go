package attestation

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/attestation"
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
				"gitCommit": "another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "another_com",
				"sha256":    "another",
			},
		},
		{
			name: "subset in attestations",
			attDigests: intoto.DigestSet{
				"gitCommit": "another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "another_com",
			},
		},
		{
			name: "empty input digests",
			attDigests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "different digest names",
			attDigests: intoto.DigestSet{
				"a-sha256":    "another",
				"a-gitCommit": "another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "another_com",
				"sha256":    "another",
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "mismatch sha256 digest",
			attDigests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "another_com",
			},
			inputDigests: intoto.DigestSet{
				"gitCommit": "another_com",
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

func Test_verifySubject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		attSubject   intoto.Subject
		inputSubject intoto.Subject
		expected     error
	}{
		{
			name: "same subject",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
		},
		{
			name: "subset in attestations",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
				},
			},
		},
		{
			name: "empty input digests",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "another_com",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "different digest names",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"a-sha256":    "another",
					"a-gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "mismatch sha256 digest",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
			expected: errs.ErrorMismatch,
		},
		{
			name: "empty att uri",
			attSubject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty input uri",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty att digest key",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256": "another",
					"":       "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty input digest key",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"":          "another",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty att digest value",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "another",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty input digest value",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256": "another",
					"":       "another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
					"sha256":    "",
				},
			},
			expected: errs.ErrorInvalidInput,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := verifySubject(tt.attSubject, tt.inputSubject)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_Verify(t *testing.T) {
	t.Parallel()
	subjects := []intoto.Subject{
		{
			URI: "the_uri",
			Digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			Annotations: map[string]interface{}{
				attestation.EnvironmentAnnotation: "prod",
			},
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
	author_id := "author_id"
	author_version := "author_version"
	author := intoto.Author{
		ID:      author_id,
		Version: author_version,
	}
	subject := intoto.Subject{
		URI: "the_uri",
		Digests: intoto.DigestSet{
			"sha256":    "another",
			"gitCommit": "another_com",
		},
	}
	prod := "prod"
	header := intoto.Header{
		Type:          attestation.StatementType,
		PredicateType: attestation.PredicateType,
		Subjects:      subjects,
	}
	release_properties := map[string]interface{}{
		attestation.BuildLevelProperty: 3,
	}
	predicate := attestation.Predicate{
		Author:            author,
		Policy:            policy,
		ReleaseResult:     intoto.AttestationResultAllow,
		ReleaseProperties: release_properties,
	}
	buildLevel := common.AsPointer(3)
	tests := []struct {
		name          string
		att           *attestation.Attestation
		result        intoto.AttestationResult
		subject       intoto.Subject
		authorID      string
		authorVersion string
		buildLevel    *int
		environment   string
		policy        map[string]intoto.Policy
		expected      error
	}{
		// Allow policies.
		{
			name: "allow all fields set",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "allow mismatch statement type",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType + "q",
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch predicate type",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType + "a",
					Subjects:      subjects,
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch author id",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch author version",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: "other_author_version",
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow empty att uri",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow empty request uri",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "allow empty att subject",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidField,
		},
		{
			name: "allow empty input subject",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow empty att digest key",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256": "another",
								"":       "another_com",
							},
						},
					},
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow empty input digest key",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256": "another",
					"":       "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "allow empty att digest value",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "",
							},
						},
					},
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow empty input digest value",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "allow mismatch sha256 digest",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch gitCommit digest",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "git_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch digest not present",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"other":  "another",
					"other2": "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow one of digests",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
				},
			},
			policy: policy,
		},
		{
			name: "allow mismatch no digest",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow mismatch level",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    common.AsPointer(1),
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch result",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch env",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   "dev",
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch no env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow no env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "allow mismatch no org",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "allow mismatch org uri",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "allow mismatch org sha256",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "allow mismatch org sha256",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "allow level not present",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow level field not present",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty + "a": 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		// Allow with ignored fields.
		{
			name: "allow ignore author version",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:      intoto.AttestationResultAllow,
			authorID:    author_id,
			buildLevel:  common.AsPointer(3),
			environment: "prod",
			subject:     subject,
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
			name: "allow ignore build level",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			environment:   prod,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "allow ignore env",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow ignore digests",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow ignore author id",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow ignore policy",
			att: &attestation.Attestation{
				Header:    header,
				Predicate: predicate,
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
		},
		// Deny policies.
		{
			name: "deny all fields set",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "deny mismatch statement type",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType + "q",
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny mismatch predicate type",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType + "a",
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny mismatch author id",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny mismatch author version",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: "other_author_version",
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},

		{
			name: "deny empty att uri",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny empty request uri",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "deny empty att subject",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidField,
		},
		{
			name: "deny empty input subject",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny empty att digest key",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256": "another",
								"":       "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny empty input digest key",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256": "another",
					"":       "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "deny empty att digest value",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny empty input digest value",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "deny mismatch sha256 digest",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch gitCommit digest",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "git_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch digest not present",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"other":  "another",
					"other2": "another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny one of digests",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
				},
			},
			policy: policy,
		},
		{
			name: "deny mismatch no digest",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny mismatch level",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    common.AsPointer(1),
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny mismatch result",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny mismatch env",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   "dev",
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny mismatch no env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny no env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "deny mismatch no org",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "deny mismatch org uri",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "deny mismatch org sha256",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "deny mismatch org sha256",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			name: "deny level not present",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny level field not present",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty + "a": 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		// Deny with ignored fields.
		{
			name: "deny ignore author version",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:      intoto.AttestationResultDeny,
			authorID:    author_id,
			buildLevel:  common.AsPointer(3),
			environment: "prod",
			subject:     subject,
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
			name: "deny ignore build level",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			environment:   prod,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "deny ignore env",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "deny ignore digests",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny ignore author id",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny ignore policy",
			att: &attestation.Attestation{
				Header: header,
				Predicate: attestation.Predicate{
					Author:            author,
					Policy:            policy,
					ReleaseResult:     intoto.AttestationResultDeny,
					ReleaseProperties: release_properties,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      author_id,
			authorVersion: author_version,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
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
			verification, err := New(reader)
			if err != nil {
				t.Fatalf("failed to creation verification: %v", err)
			}

			// Create verification options.
			var options []func(*Verification) error
			if tt.authorVersion != "" {
				options = append(options, WithAuthorVersion(tt.authorVersion))
			}
			if tt.buildLevel != nil {
				options = append(options, WithSlsaBuildLevel(*tt.buildLevel))
			}
			for name, policy := range tt.policy {
				options = append(options, WithPolicy(name, policy.URI, policy.Digests))
			}
			// Verify.
			err = verification.Verify(tt.authorID, tt.subject, tt.environment, tt.result, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

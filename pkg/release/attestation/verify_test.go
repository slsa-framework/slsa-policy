package attestation

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
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty att digests",
			inputDigests: intoto.DigestSet{
				"gitCommit": "mismatch_another_com",
				"sha256":    "another",
			},
			expected: errs.ErrorInvalidInput,
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
					"gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
				},
			},
		},
		{
			name: "empty input digests",
			attSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "mismatch_another_com",
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
					"a-gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"":       "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"gitCommit": "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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
					"gitCommit": "mismatch_another_com",
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
					"":       "mismatch_another_com",
				},
			},
			inputSubject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "mismatch_another_com",
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

// TODO: split up the function.
// TODO: support time verification.
func Test_Verify(t *testing.T) {
	t.Parallel()
	subject := intoto.Subject{
		URI: "the_uri",
		Digests: intoto.DigestSet{
			"sha256":    "another",
			"gitCommit": "another_com",
		},
	}
	subjects := []intoto.Subject{
		{
			URI: "the_uri",
			Digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			Annotations: map[string]interface{}{
				environmentAnnotation: "prod",
				versionAnnotation:     "1.2.3",
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
	releaseVersion := "1.2.3"
	authorID := "authorID"
	authorVersion := "authorVersion"
	author := intoto.Author{
		ID:      authorID,
		Version: authorVersion,
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
	predicateAllow := predicate{
		Author:            author,
		Policy:            policy,
		CreationTime:      intoto.Now(),
		ReleaseResult:     ReleaseResultAllow,
		ReleaseProperties: releaseProperties,
	}
	predicateDeny := predicate{
		Author:            author,
		Policy:            policy,
		CreationTime:      intoto.Now(),
		ReleaseResult:     ReleaseResultDeny,
		ReleaseProperties: releaseProperties,
	}
	attAllow := &attestation{
		Header:    header,
		Predicate: predicateAllow,
	}
	attDeny := &attestation{
		Header:    header,
		Predicate: predicateDeny,
	}
	buildLevel := common.AsPointer(3)
	tests := []struct {
		name           string
		att            *attestation
		result         ReleaseResult
		subject        intoto.Subject
		authorID       string
		authorVersion  string
		releaseVersion string
		buildLevel     *int
		environment    string
		policy         map[string]intoto.Policy
		expected       error
	}{
		// Allow policies.
		{
			name:           "allow all fields set",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
		},
		{
			name: "allow mismatch statement type",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType + "q",
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicateAllow,
			},
			result:        ReleaseResultAllow,
			authorID:      authorID,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name: "allow mismatch predicate type",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType + "a",
					Subjects:      subjects,
				},
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:          "allow mismatch author id",
			att:           attAllow,
			result:        ReleaseResultAllow,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch author version",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  "mismatch_authorVersion",
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch release version",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: "1.2.4",
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "allow no input release version",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicateAllow,
			},
			result:        ReleaseResultAllow,
			authorID:      authorID,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "allow no att release version",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
							Annotations: map[string]interface{}{
								environmentAnnotation: "prod",
							},
						},
					},
				},
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "allow empty att uri",
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
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name:           "allow empty request uri",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "allow empty att subject",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
				},
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorInvalidField,
		},
		{
			name:           "allow empty input subject",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name: "allow empty att digest key",
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
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name:           "allow empty input digest key",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256": "another",
					"":       "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "allow empty att digest value",
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
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name: "allow empty input digest value",
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
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
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
			name:           "allow mismatch sha256 digest",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch gitCommit digest",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch digest not present",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"other":  "another",
					"other2": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:           "allow one of digests",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
				},
			},
			policy: policy,
		},
		{
			name:           "allow mismatch no digest",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name:           "allow mismatch level",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     common.AsPointer(1),
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch result",
			att:            attAllow,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch env",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    "dev",
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "allow mismatch no env att",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "mismatch_another_com",
							},
						},
					},
				},
				Predicate: predicateAllow,
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "allow mismatch no env input",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "allow no env no annotations",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
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
				Predicate: predicateAllow,
			},
			result:        ReleaseResultAllow,
			authorID:      authorID,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			subject:       subject,
			policy:        policy,
		},
		{
			name:           "allow mismatch no org",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			name:           "allow mismatch org uri",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			name:           "allow mismatch org sha256",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			name:           "allow mismatch org sha256",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: ReleaseResultAllow,
				},
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "allow level field not present",
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: ReleaseResultAllow,
					ReleaseProperties: map[string]interface{}{
						buildLevelProperty + "a": 3,
					},
				},
			},
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		// Allow with ignored fields.
		{
			name:        "allow ignore author version",
			att:         attAllow,
			result:      ReleaseResultAllow,
			authorID:    authorID,
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
			name:           "allow ignore build level",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			environment:    prod,
			subject:        subject,
			policy:         policy,
		},
		{
			name:           "allow ignore env",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "allow ignore digests",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name:          "allow ignore author id",
			att:           attAllow,
			result:        ReleaseResultAllow,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name:           "allow ignore policy",
			att:            attAllow,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
		},
		// Deny policies.
		{
			name:           "deny all fields set",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
		},
		{
			name: "deny mismatch statement type",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType + "q",
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicateDeny,
			},
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "deny mismatch predicate type",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType + "a",
					Subjects:      subjects,
				},
				Predicate: predicateDeny,
			},
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:          "deny mismatch author id",
			att:           attDeny,
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch author version",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  "mismatch_authorVersion",
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch release version",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: "1.2.4",
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "deny no input release version",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects:      subjects,
				},
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      authorID,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
		},
		{
			name: "deny no att release version",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
							Annotations: map[string]interface{}{
								environmentAnnotation: "prod",
							},
						},
					},
				},
				Predicate: predicateDeny,
			},
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "deny empty att uri",
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
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name:          "deny empty request uri",
			att:           attDeny,
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "deny empty att subject",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
				},
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidField,
		},
		{
			name:          "deny empty input subject",
			att:           attDeny,
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny empty att digest key",
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
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name:          "deny empty input digest key",
			att:           attDeny,
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256": "another",
					"":       "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "deny empty att digest value",
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
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny empty input digest value",
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
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      "mismatch_authorID",
			authorVersion: authorVersion,
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
			name:           "deny mismatch sha256 digest",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "not_another",
					"gitCommit": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch gitCommit digest",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"sha256":    "another",
					"gitCommit": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch digest not present",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"other":  "another",
					"other2": "mismatch_another_com",
				},
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name:           "deny one of digests",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject: intoto.Subject{
				URI: "the_uri",
				Digests: intoto.DigestSet{
					"gitCommit": "another_com",
				},
			},
			policy: policy,
		},
		{
			name:           "deny mismatch no digest",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name:           "deny mismatch level",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     common.AsPointer(1),
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch result",
			att:            attDeny,
			result:         ReleaseResultAllow,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch env",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    "dev",
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "deny mismatch no env att",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
					Subjects: []intoto.Subject{
						{
							URI: "the_uri",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "mismatch_another_com",
							},
						},
					},
				},
				Predicate: predicateDeny,
			},
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "deny mismatch no env input",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "deny no env no annotations",
			att: &attestation{
				Header: intoto.Header{
					Type:          statementType,
					PredicateType: predicateType,
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
				Predicate: predicateDeny,
			},
			result:        ReleaseResultDeny,
			authorID:      authorID,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			subject:       subject,
			policy:        policy,
		},
		{
			name:           "deny mismatch no org",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			name:           "deny mismatch org uri",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			name:           "deny mismatch org sha256",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			name:           "deny mismatch org sha256",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: ReleaseResultDeny,
				},
			},
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name: "deny level field not present",
			att: &attestation{
				Header: header,
				Predicate: predicate{
					Author:        author,
					Policy:        policy,
					ReleaseResult: ReleaseResultDeny,
					ReleaseProperties: map[string]interface{}{
						buildLevelProperty + "a": 3,
					},
				},
			},
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		// Deny with ignored fields.
		{
			name:        "deny ignore author version",
			att:         attDeny,
			result:      ReleaseResultDeny,
			authorID:    authorID,
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
			name:           "deny ignore build level",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			environment:    prod,
			subject:        subject,
			policy:         policy,
		},
		{
			name:           "deny ignore env",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			subject:        subject,
			policy:         policy,
			expected:       errs.ErrorMismatch,
		},
		{
			name:           "deny ignore digests",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			policy:         policy,
			expected:       errs.ErrorInvalidInput,
		},
		{
			name:          "deny ignore author id",
			att:           attDeny,
			result:        ReleaseResultDeny,
			authorVersion: authorVersion,
			buildLevel:    buildLevel,
			environment:   prod,
			subject:       subject,
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name:           "deny ignore policy",
			att:            attDeny,
			result:         ReleaseResultDeny,
			authorID:       authorID,
			releaseVersion: releaseVersion,
			authorVersion:  authorVersion,
			buildLevel:     buildLevel,
			environment:    prod,
			subject:        subject,
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
			var options []VerificationOption
			if tt.authorVersion != "" {
				options = append(options, IsAuthorVersion(tt.authorVersion))
			}
			if tt.buildLevel != nil {
				options = append(options, IsSlsaBuildLevel(*tt.buildLevel))
			}
			for name, policy := range tt.policy {
				options = append(options, HasPolicy(name, policy.URI, policy.Digests))
			}
			if tt.releaseVersion != "" {
				options = append(options, IsReleaseVersion(tt.releaseVersion))
			}
			// Verify.
			err = verification.Verify(tt.authorID, tt.subject, tt.environment, tt.result, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

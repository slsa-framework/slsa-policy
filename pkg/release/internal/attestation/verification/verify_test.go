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

func Test_Verify(t *testing.T) {
	t.Parallel()
	subjects := []intoto.ResourceDescriptor{
		{
			Name: "-",
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
	tests := []struct {
		name          string
		att           *attestation.Attestation
		result        intoto.AttestationResult
		digests       intoto.DigestSet
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name: "allow mismatch statement type",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType + "q",
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch predicate type",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType + "a",
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch author id",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "other_author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch author version",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "other_author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch sha256 digest",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch gitCommit digest",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "git_another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch digest not present",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"other":  "another",
				"other2": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch no digest",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow mismatch level",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(1),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch result",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "dev",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch no env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.ResourceDescriptor{
						{
							Name: "-",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow mismatch no org",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "allow level field not present",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty + "a": 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		// Allow with ignored fields.
		{
			name: "allow ignore author version",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:      intoto.AttestationResultAllow,
			authorID:    "author_id",
			buildLevel:  common.AsPointer(3),
			environment: "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name: "allow ignore prod",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name: "allow ignore digests",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "allow ignore author id",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "allow ignore policy",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultAllow,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
		},
		// Deny policies.
		{
			name: "deny all fields set",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy: policy,
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
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
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
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch author id",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "other_author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch author version",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "other_author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch sha256 digest",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "not_another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch gitCommit digest",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "git_another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch digest not present",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"other":  "another",
				"other2": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch no digest",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny mismatch level",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(1),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch result",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultAllow,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "dev",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch no env",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects: []intoto.ResourceDescriptor{
						{
							Name: "-",
							Digests: intoto.DigestSet{
								"sha256":    "another",
								"gitCommit": "another_com",
							},
						},
					},
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny mismatch no org",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		{
			name: "deny level field not present",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty + "a": 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorMismatch,
		},
		// Deny with ignored fields.
		{
			name: "deny ignore author version",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:      intoto.AttestationResultDeny,
			authorID:    "author_id",
			buildLevel:  common.AsPointer(3),
			environment: "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name: "deny ignore prod",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy: policy,
		},
		{
			name: "deny ignore digests",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			policy:        policy,
			expected:      errs.ErrorInvalidInput,
		},
		{
			name: "deny ignore author id",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
			policy:   policy,
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "deny ignore policy",
			att: &attestation.Attestation{
				Header: intoto.Header{
					Type:          attestation.StatementType,
					PredicateType: attestation.PredicateType,
					Subjects:      subjects,
				},
				Predicate: attestation.Predicate{
					Author: intoto.Author{
						ID:      "author_id",
						Version: "author_version",
					},
					Policy:        policy,
					ReleaseResult: intoto.AttestationResultDeny,
					ReleaseProperties: map[string]interface{}{
						attestation.BuildLevelProperty: 3,
					},
				},
			},
			result:        intoto.AttestationResultDeny,
			authorID:      "author_id",
			authorVersion: "author_version",
			buildLevel:    common.AsPointer(3),
			environment:   "prod",
			digests: intoto.DigestSet{
				"sha256":    "another",
				"gitCommit": "another_com",
			},
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
			if tt.environment != "" {
				options = append(options, WithEnvironment(tt.environment))
			}
			for name, policy := range tt.policy {
				options = append(options, WithPolicy(name, policy.URI, policy.Digests))
			}
			// Verify.
			err = verification.Verify(tt.digests, tt.authorID, tt.result, options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

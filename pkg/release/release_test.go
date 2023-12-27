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
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_AttestationNew(t *testing.T) {
	t.Parallel()
	digests := intoto.DigestSet{
		"sha256":    "some_value",
		"gitCommit": "another_value",
	}
	subject := intoto.Subject{
		Digests: digests,
	}
	level := 2
	packageURI := "package_uri"
	environment := common.AsPointer("prod")
	creatorID := "creator_id"
	creatorVersion := "creato_version"
	policy := map[string]intoto.Policy{
		"org": intoto.Policy{
			URI: "policy1_uri",
			Digests: intoto.DigestSet{
				"sha256":    "value1",
				"commitSha": "value2",
			},
		},
		"project": intoto.Policy{
			URI: "policy2_uri",
			Digests: intoto.DigestSet{
				"sha256":    "value3",
				"commitSha": "value4",
			},
		},
	}
	tests := []struct {
		name           string
		creatorID      string
		result         PolicyEvaluationResult
		options        []AttestationCreationOption
		subject        intoto.Subject
		creatorVersion string
		policy         map[string]intoto.Policy
		buildLevel     int
		expected       error
	}{
		{
			name:      "all fields set",
			creatorID: creatorID,
			result: PolicyEvaluationResult{
				level:       level,
				packageURI:  packageURI,
				digests:     digests,
				environment: environment,
			},
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			subject:        subject,
			buildLevel:     level,
			creatorVersion: creatorVersion,
			policy:         policy,
		},
		{
			name:      "no env",
			creatorID: creatorID,
			result: PolicyEvaluationResult{
				level:      level,
				packageURI: packageURI,
				digests:    digests,
			},
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			subject:        subject,
			buildLevel:     level,
			creatorVersion: creatorVersion,
			policy:         policy,
		},
		{
			name:      "no creator version",
			creatorID: creatorID,
			result: PolicyEvaluationResult{
				level:       level,
				packageURI:  packageURI,
				digests:     digests,
				environment: environment,
			},
			options: []AttestationCreationOption{
				SetPolicy(policy),
			},
			subject:    subject,
			buildLevel: level,
			policy:     policy,
		},
		{
			name:      "no policy",
			creatorID: creatorID,
			result: PolicyEvaluationResult{
				level:       level,
				packageURI:  packageURI,
				digests:     digests,
				environment: environment,
			},
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
			},
			subject:        subject,
			buildLevel:     level,
			creatorVersion: creatorVersion,
		},
		{
			name:      "error result",
			creatorID: creatorID,
			result: PolicyEvaluationResult{
				err: errs.ErrorMismatch,
			},
			expected: errs.ErrorInternal,
		},
		{
			name:      "invalid result",
			creatorID: creatorID,
			expected:  errs.ErrorInternal,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			att, err := tt.result.AttestationNew(tt.creatorID, tt.options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(statementType, att.Header.Type); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(predicateType, att.Header.PredicateType); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tt.creatorID, att.attestation.Predicate.Creator.ID); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff([]intoto.Subject{tt.subject}, att.attestation.Header.Subjects); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tt.result.packageURI, att.attestation.Predicate.Package.URI); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			properties := att.attestation.Predicate.Properties
			val, exists := properties[buildLevelProperty]
			if !exists {
				t.Fatalf("%q property does not exist: \n", buildLevelProperty)
			}
			v, ok := val.(int)
			if !ok {
				t.Fatalf("%q is not an int: %T\n", val, val)
			}
			if diff := cmp.Diff(tt.buildLevel, v); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			var expectedEnv string
			if tt.result.environment != nil {
				expectedEnv = *tt.result.environment
			}
			env, err := intoto.GetAnnotationValue(att.attestation.Predicate.Package.Annotations, environmentAnnotation)
			if err != nil {
				t.Fatalf("failed to retrieve annotation: %v\n", err)
			}
			if diff := cmp.Diff(expectedEnv, env); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tt.creatorVersion, att.attestation.Predicate.Creator.Version); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tt.policy, att.attestation.Predicate.Policy); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_e2e(t *testing.T) {
	t.Parallel()
	digests := intoto.DigestSet{
		"sha256":    "some_value",
		"gitCommit": "another_value",
	}

	packageURI := "package_uri"
	packageURI1 := "package_uri1"
	packageEnvironment := common.AsPointer("prod")
	packageVersion := "v1.2.3"
	creatorVersion := "v1.2.3"
	policy := map[string]intoto.Policy{
		"org": intoto.Policy{
			URI: "policy1_uri",
			Digests: intoto.DigestSet{
				"sha256":    "value1",
				"commitSha": "value2",
			},
		},
		"project": intoto.Policy{
			URI: "policy2_uri",
			Digests: intoto.DigestSet{
				"sha256":    "value3",
				"commitSha": "value4",
			},
		},
	}
	selfHostedRunner := "https://github.com/actions/runner/self-hosted"
	githubHostedRunner := "https://github.com/actions/runner/github-hosted"
	selfLevel := 2
	githubLevel := 3
	creatorID := "creator_id"
	sourceURI := "source_uri"
	sourceURI1 := "source_uri1"
	orgPolicy := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Build: []organization.Root{
				{
					ID:        githubHostedRunner,
					Name:      "github_actions_level_3",
					SlsaLevel: common.AsPointer(githubLevel),
				},
				{
					ID:        selfHostedRunner,
					Name:      "github_actions_level_2",
					SlsaLevel: common.AsPointer(selfLevel),
				},
			},
		},
	}
	projectsPolicy := []project.Policy{
		{
			Format: 1,
			Package: project.Package{
				URI: packageURI,
				Environment: project.Environment{
					AnyOf: []string{"dev", "prod"},
				},
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaBuilder: "github_actions_level_3",
				Repository: project.Repository{
					URI: sourceURI,
				},
			},
		},
		{
			Format: 1,
			Package: project.Package{
				URI: packageURI1,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaBuilder: "github_actions_level_2",
				Repository: project.Repository{
					URI: sourceURI1,
				},
			},
		},
	}
	tests := []struct {
		name               string
		creatorID          string
		org                organization.Policy
		projects           []project.Policy
		options            []AttestationCreationOption
		digests            intoto.DigestSet
		packageEnvironment *string
		packageVersion     string
		packageURI         string
		creatorVersion     string
		policy             map[string]intoto.Policy
		buildLevel         int
		builderID          string
		sourceURI          string
		errorEvaluate      error
		errorAttestation   error
		errorVerify        error
	}{
		{
			name:      "all fields set",
			creatorID: creatorID,
			// Policies to evaluate.
			org:                orgPolicy,
			projects:           projectsPolicy,
			packageEnvironment: packageEnvironment,
			packageVersion:     packageVersion,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
				SetPackageVersion(packageVersion),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			policy:         policy,
			// Builder that the verifier will use.
			builderID: githubHostedRunner,
			sourceURI: sourceURI,
		},
		{
			name:      "env not provided",
			creatorID: creatorID,
			// Policies to evaluate.
			org:      orgPolicy,
			projects: projectsPolicy,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			policy:         policy,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorInvalidInput,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name:      "env not in policy",
			creatorID: creatorID,
			// Policies to evaluate.
			org: orgPolicy,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						URI: packageURI,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "github_actions_level_3",
						Repository: project.Repository{
							URI: sourceURI,
						},
					},
				},
			},
			packageEnvironment: packageEnvironment,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			policy:         policy,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorInvalidInput,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name:      "mismatch env",
			creatorID: creatorID,
			// Policies to evaluate.
			org:                orgPolicy,
			projects:           projectsPolicy,
			packageEnvironment: common.AsPointer("not_prod"),
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			policy:         policy,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorNotFound,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name:      "no env",
			creatorID: creatorID,
			// Policies to evaluate.
			org: orgPolicy,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						URI: packageURI,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "github_actions_level_3",
						Repository: project.Repository{
							URI: sourceURI,
						},
					},
				},
			},
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			policy:         policy,
			// Builder that the verifier will use.
			builderID: githubHostedRunner,
			sourceURI: sourceURI,
		},
		{
			name:      "no author version",
			creatorID: creatorID,
			// Policies to evaluate.
			org:                orgPolicy,
			projects:           projectsPolicy,
			packageEnvironment: packageEnvironment,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetPolicy(policy),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
			policy:     policy,
			// Builder that the verifier will use.
			builderID: githubHostedRunner,
			sourceURI: sourceURI,
		},
		{
			name:      "no policy",
			creatorID: creatorID,
			// Policies to evaluate.
			org:                orgPolicy,
			projects:           projectsPolicy,
			packageEnvironment: packageEnvironment,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			// Builder that the verifier will use.
			builderID: githubHostedRunner,
			sourceURI: sourceURI,
		},
		{
			name:      "evaluation error",
			creatorID: creatorID,
			// Policies to evaluate.
			org:      orgPolicy,
			projects: projectsPolicy,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetCreatorVersion(creatorVersion),
				SetPolicy(policy),
			},
			packageURI: packageURI,
			// Fields to validate the created attestation.
			digests:        digests,
			buildLevel:     githubLevel,
			creatorVersion: creatorVersion,
			policy:         policy,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorInvalidInput,
			errorAttestation: errs.ErrorInternal,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create the reader for the org policy.
			orgContent, err := json.Marshal(tt.org)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			orgReader := io.NopCloser(bytes.NewReader(orgContent))
			// Create the readers for the projects policy.
			// Marshal the project policies into bytes.
			policies := make([][]byte, len(tt.projects), len(tt.projects))
			for i := range tt.projects {
				content, err := json.Marshal(tt.projects[i])
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				policies[i] = content
			}
			projectsReader := common.NewBytesIterator(policies)
			pol, err := PolicyNew(orgReader, projectsReader)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			verifier := common.NewAttestationVerifier(tt.digests, tt.packageURI, tt.builderID, tt.sourceURI)
			opts := BuildVerificationOption{
				Verifier:    verifier,
				Environment: tt.packageEnvironment,
			}
			result := pol.Evaluate(tt.digests, tt.packageURI, opts)
			if diff := cmp.Diff(tt.errorEvaluate, result.Error(), cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			att, err := result.AttestationNew(tt.creatorID, tt.options...)
			if diff := cmp.Diff(tt.errorAttestation, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			attBytes, err := att.ToBytes()
			if err != nil {
				t.Fatalf("failed to get attestation bytes: %v\n", err)
			}
			verifReader := io.NopCloser(bytes.NewReader(attBytes))
			verification, err := VerificationNew(verifReader)
			if err != nil {
				t.Fatalf("failed to creation verification: %v", err)
			}

			// Create verification options.
			options := []AttestationVerificationOption{
				IsSlsaBuildLevel(tt.buildLevel),
			}
			if tt.creatorVersion != "" {
				options = append(options, IsCreatorVersion(tt.creatorVersion))
			}

			for name, policy := range tt.policy {
				options = append(options, HasPolicy(name, policy.URI, policy.Digests))
			}
			if tt.packageVersion != "" {
				options = append(options, IsPackageVersion(tt.packageVersion))
			}
			if tt.packageEnvironment != nil {
				options = append(options, IsPackageEnvironment(*tt.packageEnvironment))
			}

			// Verify.
			err = verification.Verify(tt.creatorID, tt.digests, tt.packageURI, options...)
			if diff := cmp.Diff(tt.errorVerify, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

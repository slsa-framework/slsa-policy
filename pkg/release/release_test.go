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
	packageName := "package_name"
	packageRegistry := "package_registry"
	packageDesc := intoto.PackageDescriptor{
		Name:     packageName,
		Registry: packageRegistry,
	}
	environment := common.AsPointer("prod")
	tests := []struct {
		name       string
		result     PolicyEvaluationResult
		options    []AttestationCreationOption
		subject    intoto.Subject
		buildLevel int
		expected   error
	}{
		{
			name: "all fields set",
			result: PolicyEvaluationResult{
				evaluated:   true,
				level:       level,
				packageDesc: packageDesc,
				digests:     digests,
				environment: environment,
			},
			options:    []AttestationCreationOption{},
			subject:    subject,
			buildLevel: level,
		},
		{
			name: "no env",
			result: PolicyEvaluationResult{
				evaluated:   true,
				level:       level,
				packageDesc: packageDesc,
				digests:     digests,
			},
			options:    []AttestationCreationOption{},
			subject:    subject,
			buildLevel: level,
		},
		{
			name: "error result",
			result: PolicyEvaluationResult{
				evaluated: true,
				err:       errs.ErrorMismatch,
			},
			expected: errs.ErrorInternal,
		},
		{
			name:     "invalid result",
			expected: errs.ErrorInternal,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			att, err := tt.result.AttestationNew(tt.options...)
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
			if diff := cmp.Diff([]intoto.Subject{tt.subject}, att.attestation.Header.Subjects); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// TODO: need translation.
			pkgHelper := newPackageHelper(tt.result.packageDesc.Registry)
			packageDesc, err := pkgHelper.PackageDescriptor(tt.result.packageDesc.Name)
			if err != nil {
				t.Fatalf("failed to create package descriptor: %v\n", err)
			}
			if diff := cmp.Diff(tt.result.packageDesc, packageDesc); diff != "" {
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
			env := att.attestation.Predicate.Package.Environment
			if diff := cmp.Diff(expectedEnv, env); diff != "" {
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
	packageRegistry := "registry"
	packageName := "package_name"
	packageName1 := "package_name1"
	packageEnvironment := common.AsPointer("prod")
	packageVersion := "v1.2.3"
	selfHostedRunner := "https://github.com/actions/runner/self-hosted"
	githubHostedRunner := "https://github.com/actions/runner/github-hosted"
	selfLevel := 2
	githubLevel := 3
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
				Name: packageName,
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
				Name: packageName1,
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
		org                organization.Policy
		projects           []project.Policy
		options            []AttestationCreationOption
		digests            intoto.DigestSet
		packageEnvironment *string
		packageVersion     string
		packageName        string
		buildLevel         int
		builderID          string
		sourceURI          string
		errorEvaluate      error
		errorAttestation   error
		errorVerify        error
	}{
		{
			name: "all fields set",
			// Policies to evaluate.
			org:                orgPolicy,
			projects:           projectsPolicy,
			packageEnvironment: packageEnvironment,
			packageVersion:     packageVersion,
			// Options to create the attestation.
			options: []AttestationCreationOption{
				SetPackageVersion(packageVersion),
			},
			packageName: packageName,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
			// Builder that the verifier will use.
			builderID: githubHostedRunner,
			sourceURI: sourceURI,
		},
		{
			name: "env not provided",
			// Policies to evaluate.
			org:      orgPolicy,
			projects: projectsPolicy,
			// Options to create the attestation.
			options:     []AttestationCreationOption{},
			packageName: packageName,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorInvalidInput,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name: "env not in policy",
			// Policies to evaluate.
			org: orgPolicy,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName,
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
			options:     []AttestationCreationOption{},
			packageName: packageName,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorInvalidInput,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name: "mismatch env",
			// Policies to evaluate.
			org:                orgPolicy,
			projects:           projectsPolicy,
			packageEnvironment: common.AsPointer("not_prod"),
			// Options to create the attestation.
			options:     []AttestationCreationOption{},
			packageName: packageName,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
			// Builder that the verifier will use.
			builderID:        githubHostedRunner,
			sourceURI:        sourceURI,
			errorEvaluate:    errs.ErrorNotFound,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name: "no env",
			// Policies to evaluate.
			org: orgPolicy,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName,
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
			options:     []AttestationCreationOption{},
			packageName: packageName,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
			// Builder that the verifier will use.
			builderID: githubHostedRunner,
			sourceURI: sourceURI,
		},
		{
			name: "evaluation error",
			// Policies to evaluate.
			org:      orgPolicy,
			projects: projectsPolicy,
			// Options to create the attestation.
			options:     []AttestationCreationOption{},
			packageName: packageName,
			// Fields to validate the created attestation.
			digests:    digests,
			buildLevel: githubLevel,
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
			packageHelper := newPackageHelper(packageRegistry)
			// Passing validator.
			_, err = PolicyNew(orgReader, projectsReader, packageHelper, SetValidator(newPolicyValidator(true)))
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			// Failing validator.
			orgReader = io.NopCloser(bytes.NewReader(orgContent))
			projectsReader = common.NewBytesIterator(policies)
			_, err = PolicyNew(orgReader, projectsReader, packageHelper, SetValidator(newPolicyValidator(false)))
			if diff := cmp.Diff(errs.ErrorInvalidField, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// No validator.
			orgReader = io.NopCloser(bytes.NewReader(orgContent))
			projectsReader = common.NewBytesIterator(policies)
			pol, err := PolicyNew(orgReader, projectsReader, packageHelper)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			verifier := common.NewAttestationVerifier(tt.digests, tt.packageName, tt.builderID, tt.sourceURI)
			opts := AttestationVerificationOption{
				Verifier: verifier,
			}
			req := RequestOption{
				Environment: tt.packageEnvironment,
			}
			result := pol.Evaluate(tt.digests, tt.packageName, req, opts)
			if diff := cmp.Diff(tt.errorEvaluate, result.Error(), cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			att, err := result.AttestationNew(tt.options...)
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
			verification, err := VerificationNew(verifReader, packageHelper)
			if err != nil {
				t.Fatalf("failed to creation verification: %v", err)
			}

			// Create verification options.
			options := []VerificationOption{
				IsSlsaBuildLevel(tt.buildLevel),
			}

			if tt.packageVersion != "" {
				options = append(options, IsPackageVersion(tt.packageVersion))
			}
			if tt.packageEnvironment != nil {
				options = append(options, IsPackageEnvironment(*tt.packageEnvironment))
			}

			// Verify.
			err = verification.Verify(tt.digests, tt.packageName, options...)
			if diff := cmp.Diff(tt.errorVerify, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

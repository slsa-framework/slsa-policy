package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/publish/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_PolicyNew(t *testing.T) {
	t.Parallel()
	packageName1 := "package_name1"
	packageName2 := "package_name2"
	builderName1 := "builder_name1"
	builderName2 := "builder_name2"
	sourceURI1 := "source_name1"
	sourceURI2 := "source_name2"
	builderID1 := "builder_id1"
	builderID2 := "builder_id2"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Build: []organization.Root{
				{
					ID:        builderID1,
					Name:      builderName1,
					SlsaLevel: common.AsPointer(2),
				},
				{
					ID:        builderID2,
					Name:      builderName2,
					SlsaLevel: common.AsPointer(3),
				},
			},
		},
	}
	projects := []project.Policy{
		{
			Format: 1,
			Package: project.Package{
				Name: packageName1,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaBuilder: builderName1,
				Repository: project.Repository{
					URI: sourceURI1,
				},
			},
		},
		{
			Format: 1,
			Package: project.Package{
				Name: packageName2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaBuilder: builderName2,
				Repository: project.Repository{
					URI: sourceURI2,
				},
			},
		},
	}

	tests := []struct {
		name     string
		org      organization.Policy
		projects []project.Policy
		expected error
	}{
		{
			name:     "valid policies",
			org:      org,
			projects: projects,
		},
		{
			name: "same builder id",
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        "builder_id",
							Name:      builderName1,
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        "builder_id",
							Name:      builderName2,
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: projects,
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same builder name",
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        builderID1,
							Name:      "builder_name",
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        builderID2,
							Name:      "builder_name",
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: projects,
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same package name",
			org:  org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same package name env set and not",
			org:  org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same package name different env",
			org:  org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
						Environment: project.Environment{
							AnyOf: []string{"prod"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same package name same env",
			org:  org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "builder does not exist",
			org:  org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1 + "_mismatch",
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same source valid",
			org:  org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Org policy.
			content, err := json.Marshal(tt.org)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			orgReader := io.NopCloser(bytes.NewReader(content))
			// Project policy.
			// Marshal the project policies into bytes.
			projects := make([][]byte, len(tt.projects), len(tt.projects))
			for i := range tt.projects {
				content, err := json.Marshal(tt.projects[i])
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				projects[i] = content
			}
			// Create the project iterator.
			projectsReader := common.NewBytesIterator(projects)
			_, err = PolicyNew(orgReader, projectsReader, nil)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Same policy with a passing validator.
			orgReader = io.NopCloser(bytes.NewReader(content))
			projectsReader = common.NewBytesIterator(projects)
			_, err = PolicyNew(orgReader, projectsReader, common.NewPolicyValidator(true))
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Same policy with a failing validator.
			orgReader = io.NopCloser(bytes.NewReader(content))
			projectsReader = common.NewBytesIterator(projects)
			_, err = PolicyNew(orgReader, projectsReader, common.NewPolicyValidator(false))
			if diff := cmp.Diff(errs.ErrorInvalidField, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_Evaluate(t *testing.T) {
	t.Parallel()
	type dummyVerifierOpts struct {
		builderID, sourceURI string
		environment          *string
		digests              intoto.DigestSet
	}
	digests := intoto.DigestSet{
		"sha256": "val256",
		"sha512": "val512",
	}
	packageName1 := "package_name1"
	packageName2 := "package_name2"
	builderName1 := "builder_name1"
	builderName2 := "builder_name2"
	sourceURI1 := "source_name1"
	sourceURI2 := "source_name2"
	builderID1 := "builder_id1"
	builderID2 := "builder_id2"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Build: []organization.Root{
				{
					ID:        builderID1,
					Name:      builderName1,
					SlsaLevel: common.AsPointer(2),
				},
				{
					ID:        builderID2,
					Name:      builderName2,
					SlsaLevel: common.AsPointer(3),
				},
			},
		},
	}
	projects := []project.Policy{
		{
			Format: 1,
			Package: project.Package{
				Name: packageName1,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaBuilder: builderName1,
				Repository: project.Repository{
					URI: sourceURI1,
				},
			},
		},
		{
			Format: 1,
			Package: project.Package{
				Name: packageName2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaBuilder: builderName2,
				Repository: project.Repository{
					URI: sourceURI2,
				},
			},
		},
	}
	vopts := dummyVerifierOpts{
		builderID: builderID1,
		sourceURI: sourceURI1,
		digests:   digests,
	}
	tests := []struct {
		name         string
		org          organization.Policy
		projects     []project.Policy
		verifierOpts dummyVerifierOpts
		level        int
		packageName  string
		expected     error
	}{
		{
			name:         "builder 1 success",
			packageName:  packageName1,
			level:        2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:         "mismatch package name",
			packageName:  packageName1 + "_mismatch",
			level:        2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
			expected:     errs.ErrorNotFound,
		},
		{
			name:        "mismatch source name",
			packageName: packageName1,
			level:       2,
			verifierOpts: dummyVerifierOpts{
				builderID: builderID1,
				sourceURI: sourceURI1 + "_mismatch",
				digests:   digests,
			},
			org:      org,
			projects: projects,
			expected: errs.ErrorVerification,
		},
		{
			name:        "request with env policy no env",
			packageName: packageName1,
			level:       2,
			verifierOpts: dummyVerifierOpts{
				builderID:   builderID1,
				sourceURI:   sourceURI1,
				digests:     digests,
				environment: common.AsPointer("dev"),
			},
			org:      org,
			projects: projects,
			expected: errs.ErrorInvalidInput,
		},
		{
			name:         "request no env policy with env",
			packageName:  packageName1,
			level:        2,
			verifierOpts: vopts,
			org:          org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
						Environment: project.Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name:        "success builder 2 with dev env",
			packageName: packageName2,
			level:       3,
			verifierOpts: dummyVerifierOpts{
				builderID:   builderID2,
				sourceURI:   sourceURI2,
				digests:     digests,
				environment: common.AsPointer("dev"),
			},
			org: org,
			projects: []project.Policy{
				{
					Format: 1,
					Package: project.Package{
						Name: packageName1,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName1,
						Repository: project.Repository{
							URI: sourceURI1,
						},
					},
				},
				{
					Format: 1,
					Package: project.Package{
						Name: packageName2,
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: builderName2,
						Repository: project.Repository{
							URI: sourceURI2,
						},
					},
				},
			},
		},
		{
			name:        "mismatch builder id",
			packageName: packageName1,
			level:       2,
			verifierOpts: dummyVerifierOpts{
				builderID: builderName1 + "_mismatch",
				sourceURI: sourceURI1,
				digests:   digests,
			},
			org:      org,
			projects: projects,
			expected: errs.ErrorVerification,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Org policy.
			content, err := json.Marshal(tt.org)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			orgReader := io.NopCloser(bytes.NewReader(content))
			// Project policy.
			// Marshal the project policies into bytes.
			projects := make([][]byte, len(tt.projects), len(tt.projects))
			for i := range tt.projects {
				content, err := json.Marshal(tt.projects[i])
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				projects[i] = content
			}
			// Create the project iterator.
			projectsReader := common.NewBytesIterator(projects)
			policy, err := PolicyNew(orgReader, projectsReader, nil)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			if err != nil {
				return
			}
			// Create the verifier.
			verifier := common.NewAttestationVerifier(tt.verifierOpts.digests, tt.packageName,
				tt.verifierOpts.builderID, tt.verifierOpts.sourceURI)
			opts := options.BuildVerification{
				Verifier: verifier,
			}
			req := options.Request{
				Environment: tt.verifierOpts.environment,
			}
			level, err := policy.Evaluate(tt.verifierOpts.digests, tt.packageName, req, opts)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.level, level); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

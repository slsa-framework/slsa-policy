package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
)

func Test_PolicyNew(t *testing.T) {
	t.Parallel()
	type dummyVerifierOpts struct {
		packageURI string
		releaserID string
		env        string
	}
	releaserID1 := "releaser_id1"
	releaserID2 := "releaser_id2"
	packageURI1 := "package_uri1"
	packageURI2 := "package_uri2"
	packageURI3 := "package_uri3"
	packageURI4 := "package_uri4"
	pricipalURI1 := "principal_uri1"
	pricipalURI2 := "principal_uri2"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Release: []organization.Root{
				{
					ID: releaserID1,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(3),
					},
				},
				{
					ID: releaserID2,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(2),
					},
				},
			},
		},
	}
	projects := []project.Policy{
		{
			Format: 1,
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(2),
			},
			Principal: project.Principal{
				URI: pricipalURI1,
			},
			Packages: []project.Package{
				{
					URI: packageURI1,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					URI: packageURI2,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			Format: 1,
			Principal: project.Principal{
				URI: pricipalURI2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(3),
			},
			Packages: []project.Package{
				{
					URI: packageURI3,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					URI: packageURI4,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
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
		// Project tests.
		{
			name:     "project build level too high",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							ID: releaserID2,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
					},
				},
			},
			projects: projects,
		},
		{
			name:     "project env value empty",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI4,
							Environment: project.Environment{
								AnyOf: []string{"dev", ""},
							},
						},
					},
				},
			},
		},
		{
			name:     "project no packages",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
		{
			name:     "invalid project format",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
		{
			name:     "project empty package uri",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
						},
						// Empty package URI.
						{},
					},
				},
			},
		},
		{
			name:     "project package uri reuse",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
						},
						{
							URI: packageURI3,
						},
					},
				},
			},
		},
		{
			name:     "project empty principal",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
						},
						{
							URI: packageURI3,
						},
					},
				},
			},
		},
		// Org tests.
		{
			name:     "invalid org format",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
			projects: projects,
		},
		{
			name:     "release id reuse",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
			projects: projects,
		},
		{
			name:     "empty releaser id",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
			projects: projects,
		},
		{
			name:     "empty releaser build level",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: releaserID2,
						},
					},
				},
			},
			projects: projects,
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
			projectsReader := common.NewNamedBytesIterator(projects, true)
			_, err = PolicyNew(orgReader, projectsReader)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_Evaluate(t *testing.T) {
	t.Parallel()
	type dummyVerifierOpts struct {
		packageURI string
		releaserID string
		env        string
	}
	releaserID1 := "releaser_id1"
	releaserID2 := "releaser_id2"
	packageURI1 := "package_uri1"
	packageURI2 := "package_uri2"
	packageURI3 := "package_uri3"
	packageURI4 := "package_uri4"
	pricipalURI1 := "principal_uri1"
	pricipalURI2 := "principal_uri2"
	// NOTE: the test iterator indexes policies starting at 0.
	policyID2 := "policy_id1"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Release: []organization.Root{
				{
					ID: releaserID1,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(2),
					},
				},
				{
					ID: releaserID2,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
	}
	projects := []project.Policy{
		{
			Format: 1,
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(2),
			},
			Principal: project.Principal{
				URI: pricipalURI1,
			},
			Packages: []project.Package{
				{
					URI: packageURI3,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					URI: packageURI4,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			Format: 1,
			Principal: project.Principal{
				URI: pricipalURI2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(3),
			},
			Packages: []project.Package{
				{
					URI: packageURI1,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					URI: packageURI2,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
	}

	vopts := dummyVerifierOpts{
		releaserID: releaserID2,
		packageURI: packageURI1,
		env:        "prod",
	}
	tests := []struct {
		name         string
		org          organization.Policy
		projects     []project.Policy
		verifierOpts dummyVerifierOpts
		packageURI   string
		policyID     string
		expected     error
	}{
		{
			name:         "passing policy",
			packageURI:   packageURI2,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:       "no env",
			packageURI: packageURI2,
			policyID:   policyID2,
			verifierOpts: dummyVerifierOpts{
				releaserID: releaserID2,
				packageURI: packageURI1,
			},
			org: org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							// NOTE: This package does not have env set.
							URI: packageURI2,
						},
					},
				},
			},
		},
		{
			name:       "env in attestation not in policy",
			expected:   errs.ErrorVerification,
			packageURI: packageURI2,
			policyID:   policyID2,
			verifierOpts: dummyVerifierOpts{
				releaserID: releaserID2,
				packageURI: packageURI1,
			},
			org:      org,
			projects: projects,
		},
		{
			name:         "env not in attestation set in policy",
			expected:     errs.ErrorVerification,
			packageURI:   packageURI2,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							// NOTE: This package does not have env set.
							URI: packageURI2,
						},
					},
				},
			},
		},
		{
			name:         "policy not present",
			expected:     errs.ErrorNotFound,
			packageURI:   packageURI2,
			policyID:     policyID2 + "_different",
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:         "package uri not present",
			expected:     errs.ErrorNotFound,
			packageURI:   packageURI3,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:         "low build level",
			packageURI:   packageURI2,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(1),
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
			},
		},
		{
			name:         "high build level",
			expected:     errs.ErrorVerification,
			packageURI:   packageURI2,
			policyID:     policyID2,
			verifierOpts: vopts,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: releaserID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: releaserID2,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(2),
							},
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							URI: packageURI3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							URI: packageURI1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: packageURI2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
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
			projectsReader := common.NewNamedBytesIterator(projects, true)
			policy, err := PolicyNew(orgReader, projectsReader)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			if err != nil {
				return
			}
			// Create the verifier.
			verifier := common.NewAttestationVerifier(tt.packageURI,
				tt.verifierOpts.env, tt.verifierOpts.releaserID)
			opts := options.ReleaseVerification{
				Verifier: verifier,
			}
			err = policy.Evaluate(tt.packageURI, tt.policyID, opts)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
		})
	}
}

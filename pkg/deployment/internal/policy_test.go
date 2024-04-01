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
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_PolicyNew(t *testing.T) {
	t.Parallel()
	publishrID1 := "publishr_id1"
	publishrID2 := "publishr_id2"
	packageName1 := "package_name1"
	packageName2 := "package_name2"
	packageName3 := "package_name3"
	packageName4 := "package_name4"
	serviceAccount1 := "service_account1"
	serviceAccount2 := "service_account2"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Publish: []organization.Root{
				{
					ID: publishrID1,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(3),
					},
				},
				{
					ID: publishrID2,
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
			Protection: project.Protection{
				ServiceAccount: serviceAccount1,
			},
			Packages: []project.Package{
				{
					Name: packageName1,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					Name: packageName2,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			Format: 1,
			Protection: project.Protection{
				ServiceAccount: serviceAccount2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(3),
			},
			Packages: []project.Package{
				{
					Name: packageName3,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					Name: packageName4,
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
					Publish: []organization.Root{
						{
							ID: publishrID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							ID: publishrID2,
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
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
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
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
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
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
		{
			name:     "project empty package name",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName3,
						},
						// Empty package Name.
						{},
					},
				},
			},
		},
		{
			name:     "project package name reuse",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName3,
						},
						{
							Name: packageName3,
						},
					},
				},
			},
		},
		{
			name:     "project empty Protection",
			expected: errs.ErrorInvalidField,
			org:      org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
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
							Name: packageName3,
						},
						{
							Name: packageName3,
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
					Publish: []organization.Root{
						{
							ID: publishrID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: publishrID1,
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
			name:     "publish id reuse",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Publish: []organization.Root{
						{
							ID: publishrID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: publishrID1,
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
			name:     "empty publishr id",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Publish: []organization.Root{
						{
							ID: publishrID1,
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
			name:     "empty publishr build level",
			expected: errs.ErrorInvalidField,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Publish: []organization.Root{
						{
							ID: publishrID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: publishrID2,
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
			_, err = PolicyNew(orgReader, projectsReader, nil)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Same policy with a passing validator.
			orgReader = io.NopCloser(bytes.NewReader(content))
			projectsReader = common.NewNamedBytesIterator(projects, true)
			_, err = PolicyNew(orgReader, projectsReader, common.NewPolicyValidator(true))
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Same policy with a failing validator.
			orgReader = io.NopCloser(bytes.NewReader(content))
			projectsReader = common.NewNamedBytesIterator(projects, true)
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
		digests     intoto.DigestSet
		buildLevel  int
		packageName string
		publishrID  string
		env         string
	}
	digests := intoto.DigestSet{
		"sha256": "val256",
		"sha512": "val512",
	}
	publishrID1 := "publishr_id1"
	publishrID2 := "publishr_id2"
	packageName1 := "package_name1"
	packageName2 := "package_name2"
	packageName3 := "package_name3"
	packageName4 := "package_name4"
	serviceAccount1 := "service_account1"
	serviceAccount2 := "service_account2"
	// NOTE: the test iterator indexes policies starting at 0.
	policyID2 := "policy_id1"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Publish: []organization.Root{
				{
					ID: publishrID1,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(2),
					},
				},
				{
					ID: publishrID2,
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
			Protection: project.Protection{
				ServiceAccount: serviceAccount1,
			},
			Packages: []project.Package{
				{
					Name: packageName3,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					Name: packageName4,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			Format: 1,
			Protection: project.Protection{
				ServiceAccount: serviceAccount2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(3),
			},
			Packages: []project.Package{
				{
					Name: packageName1,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					Name: packageName2,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
	}
	buildLevel := 3
	vopts := dummyVerifierOpts{
		digests:     digests,
		buildLevel:  buildLevel,
		publishrID:  publishrID2,
		packageName: packageName1,
		env:         "prod",
	}
	tests := []struct {
		name         string
		org          organization.Policy
		projects     []project.Policy
		verifierOpts dummyVerifierOpts
		packageName  string
		digests      intoto.DigestSet
		policyID     string
		expected     error
	}{
		{
			name:         "passing policy",
			packageName:  packageName2,
			digests:      digests,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:         "empty digests",
			expected:     errs.ErrorInvalidField,
			packageName:  packageName2,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:        "empty digest key",
			expected:    errs.ErrorInvalidField,
			packageName: packageName2,
			digests: intoto.DigestSet{
				"sha256": "val256",
				"":       "val512",
			},
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:        "empty digest value",
			expected:    errs.ErrorInvalidField,
			packageName: packageName2,
			digests: intoto.DigestSet{
				"sha256": "val256",
				"sha512": "",
			},
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:        "mismatch value",
			expected:    errs.ErrorVerification,
			packageName: packageName2,
			digests: intoto.DigestSet{
				"sha256": "val256_different",
				"sha512": "val512",
			},
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:        "mismatch value single hash",
			expected:    errs.ErrorVerification,
			packageName: packageName2,
			digests: intoto.DigestSet{
				"sha512": "val512",
			},
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:        "no env",
			packageName: packageName2,
			digests:     digests,
			policyID:    policyID2,
			verifierOpts: dummyVerifierOpts{
				digests:     digests,
				publishrID:  publishrID2,
				packageName: packageName1,
				buildLevel:  buildLevel,
			},
			org: org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							// NOTE: This package does not have env set.
							Name: packageName2,
						},
					},
				},
			},
		},
		{
			name:        "env in attestation not in policy",
			expected:    errs.ErrorVerification,
			packageName: packageName2,
			digests:     digests,
			policyID:    policyID2,
			verifierOpts: dummyVerifierOpts{
				digests:     digests,
				publishrID:  publishrID2,
				packageName: packageName1,
			},
			org:      org,
			projects: projects,
		},
		{
			name:         "env not in attestation set in policy",
			expected:     errs.ErrorVerification,
			packageName:  packageName2,
			digests:      digests,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							// NOTE: This package does not have env set.
							Name: packageName2,
						},
					},
				},
			},
		},
		{
			name:         "policy not present",
			expected:     errs.ErrorNotFound,
			packageName:  packageName2,
			digests:      digests,
			policyID:     policyID2 + "_different",
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:         "package name not present",
			expected:     errs.ErrorNotFound,
			packageName:  packageName3,
			digests:      digests,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects:     projects,
		},
		{
			name:         "low build level",
			packageName:  packageName2,
			digests:      digests,
			policyID:     policyID2,
			verifierOpts: vopts,
			org:          org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(1),
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
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
			packageName:  packageName2,
			digests:      digests,
			policyID:     policyID2,
			verifierOpts: vopts,
			org: organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Publish: []organization.Root{
						{
							ID: publishrID1,
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(3),
							},
						},
						{
							ID: publishrID2,
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
					Protection: project.Protection{
						ServiceAccount: serviceAccount1,
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Protection: project.Protection{
						ServiceAccount: serviceAccount2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName2,
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
			policy, err := PolicyNew(orgReader, projectsReader, nil)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			if err != nil {
				return
			}
			// Create the verifier.
			verifier := common.NewAttestationVerifier(tt.verifierOpts.digests, tt.packageName,
				tt.verifierOpts.env, tt.verifierOpts.publishrID, tt.verifierOpts.buildLevel)
			opts := options.PublishVerification{
				Verifier: verifier,
			}
			Protection, err := policy.Evaluate(tt.digests, tt.packageName, tt.policyID, opts)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if len(tt.projects) < 2 {
				t.Fatalf("internal error. number of projects: %d", len(tt.projects))
			}
			if diff := cmp.Diff(tt.projects[1].Protection, *Protection, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

package project

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_validateFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		expected error
	}{
		{
			name: "format is 1",
			policy: Policy{
				Format: 1,
			},
		},
		{
			name:     "no format defined",
			policy:   Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "format is not 1",
			policy: Policy{
				Format: 2,
			},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validateFormat()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateProtection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		expected error
	}{
		{
			name: "service_account present",
			policy: Policy{
				Protection: Protection{
					ServiceAccount: "the_sa",
				},
			},
		},
		{
			name:     "service_account not present",
			policy:   Policy{},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.validateProtection()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_getPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      Policy
		packageName string
		expected    error
	}{
		{
			name:        "name2 present",
			packageName: "name2",
			policy: Policy{
				Packages: []Package{
					{
						Name: "name1",
					},
					{
						Name: "name2",
					},
				},
			},
		},
		{
			name:        "name not present",
			expected:    errs.ErrorNotFound,
			packageName: "name3",
			policy: Policy{
				Packages: []Package{
					{
						Name: "name1",
					},
					{
						Name: "name2",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkg, err := tt.policy.getPackage(tt.packageName)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.packageName, pkg.Name); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		env      *string
		envs     []string
		expected error
	}{
		{
			name: "env match",
			env:  common.AsPointer("dev"),
			envs: []string{
				"prod", "dev",
			},
		},
		{
			name:     "env mismatch",
			expected: errs.ErrorInternal,
			env:      common.AsPointer("not dev"),
			envs: []string{
				"prod", "dev",
			},
		},
		{
			name:     "nil env",
			expected: errs.ErrorInternal,
			envs: []string{
				"prod", "dev",
			},
		},
		{
			name:     "nil envs",
			expected: errs.ErrorInternal,
			env:      common.AsPointer("dev"),
		},
		{
			name:     "empty envs",
			expected: errs.ErrorInternal,
			env:      common.AsPointer("dev"),
			envs:     []string{},
		},
		{
			name:     "empty env",
			expected: errs.ErrorInternal,
			env:      common.AsPointer(""),
			envs: []string{
				"prod", "dev",
			},
		},
		{
			name:     "empty envs entry",
			expected: errs.ErrorInternal,
			env:      common.AsPointer(""),
			envs: []string{
				"prod", "",
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateEnv(tt.envs, tt.env)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validatePackages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		expected error
	}{
		{
			name: "two valid packages",
			policy: Policy{
				Packages: []Package{
					{
						Name: "the_name",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					{
						Name: "the_name2",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
				},
			},
		},
		{
			name:     "duplicate name",
			expected: errs.ErrorInvalidField,
			policy: Policy{
				Packages: []Package{
					{
						Name: "the_name",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					{
						Name: "the_name",
						Environment: Environment{
							AnyOf: []string{"staging"},
						},
					},
				},
			},
		},
		{
			name:     "empty env",
			expected: errs.ErrorInvalidField,
			policy: Policy{
				Packages: []Package{
					{
						Name: "the_name",
						Environment: Environment{
							AnyOf: []string{"", "prod"},
						},
					},
					{
						Name: "the_name2",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
				},
			},
		},
		{
			name:     "missing name",
			expected: errs.ErrorInvalidField,
			policy: Policy{
				Packages: []Package{
					{
						Name: "the_name",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					{
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
				},
			},
		},
		{
			name:     "no packages",
			expected: errs.ErrorInvalidField,
			policy:   Policy{},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.validatePackages()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Same policy with a passing validator.
			tt.policy.validator = common.NewPolicyValidator(true)
			err = tt.policy.validatePackages()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Same policy with a failing validator.
			tt.policy.validator = common.NewPolicyValidator(false)
			err = tt.policy.validatePackages()
			if diff := cmp.Diff(errs.ErrorInvalidField, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}

		})
	}
}

func Test_validateBuildRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		policy        Policy
		maxBuildLevel int
		expected      error
	}{
		{
			name:          "same levels",
			maxBuildLevel: 3,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
		},
		{
			name:          "lower reqnameed level",
			maxBuildLevel: 3,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(2),
				},
			},
		},
		{
			name:          "higher reqnameed level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(4),
				},
			},
		},
		{
			name:          "negative level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: -1,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(4),
				},
			},
		},
		{
			name:          "large level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 5,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(4),
				},
			},
		},
		{
			name:          "negative policy level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(-1),
				},
			},
		},
		{
			name:          "large policy level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 5,
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(5),
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.validateBuildRequirements(tt.maxBuildLevel)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
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
		releaserID  string
		env         string
	}
	releaserID1 := "releaser_id1"
	releaserID2 := "releaser_id2"
	packageName1 := "package_name1"
	packageName2 := "package_name2"
	digests := intoto.DigestSet{
		"sha256": "val256",
		"sha512": "val512",
	}
	org := organization.Policy{
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
	project := Policy{
		Protection: Protection{
			ServiceAccount: "protection_name",
		},
		BuildRequirements: BuildRequirements{
			RequireSlsaLevel: common.AsPointer(2),
		},
		Packages: []Package{
			{
				Name: packageName1,
				Environment: Environment{
					AnyOf: []string{"dev", "prod"},
				},
			},
			{
				Name: packageName2,
				Environment: Environment{
					AnyOf: []string{"dev", "prod"},
				},
			},
		},
	}
	buildLevel := 3
	vopts := dummyVerifierOpts{
		digests:     digests,
		releaserID:  releaserID2,
		packageName: packageName1,
		buildLevel:  buildLevel,
		env:         "prod",
	}
	tests := []struct {
		name         string
		policy       Policy
		org          organization.Policy
		noVerifier   bool
		packageName  string
		digests      intoto.DigestSet
		verifierOpts dummyVerifierOpts
		expected     error
	}{
		{
			name:         "passing",
			verifierOpts: vopts,
			packageName:  packageName1,
			digests:      digests,
			org:          org,
			policy:       project,
		},
		{
			name:         "empty digests",
			expected:     errs.ErrorInvalidField,
			verifierOpts: vopts,
			packageName:  packageName1,
			org:          org,
			policy:       project,
		},
		{
			name:         "empty digest value",
			expected:     errs.ErrorInvalidField,
			verifierOpts: vopts,
			packageName:  packageName1,
			digests: intoto.DigestSet{
				"sha256": "val256",
				"":       "val512",
			},
			org:    org,
			policy: project,
		},
		{
			name:         "digest mismatch",
			expected:     errs.ErrorVerification,
			verifierOpts: vopts,
			packageName:  packageName1,
			digests: intoto.DigestSet{
				"sha256": "val256_different",
				"sha512": "val512",
			},
			org:    org,
			policy: project,
		},
		{
			name:         "digest mismatch single match",
			expected:     errs.ErrorVerification,
			verifierOpts: vopts,
			packageName:  packageName1,
			digests: intoto.DigestSet{
				"sha512": "val512",
			},
			org:    org,
			policy: project,
		},
		{
			name:         "empty digest key",
			expected:     errs.ErrorInvalidField,
			verifierOpts: vopts,
			packageName:  packageName1,
			digests: intoto.DigestSet{
				"sha256": "val256",
				"sha512": "",
			},
			org:    org,
			policy: project,
		},
		{
			name:         "no verifier",
			expected:     errs.ErrorInvalidInput,
			noVerifier:   true,
			verifierOpts: vopts,
			packageName:  packageName1,
			digests:      digests,
			org:          org,
			policy:       project,
		},
		{
			name:         "package name not present",
			expected:     errs.ErrorNotFound,
			verifierOpts: vopts,
			packageName:  packageName1 + "_not",
			digests:      digests,
			org:          org,
			policy:       project,
		},
		{
			name:         "root levels too low",
			expected:     errs.ErrorVerification,
			verifierOpts: vopts,
			packageName:  packageName1,
			digests:      digests,
			org: organization.Policy{
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
			policy: project,
		},
		{
			name:     "env mismatch",
			expected: errs.ErrorVerification,
			verifierOpts: dummyVerifierOpts{
				releaserID:  releaserID2,
				packageName: "package_name",
				env:         "staging",
			},
			packageName: packageName1,
			digests:     digests,
			org:         org,
			policy:      project,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create the verifier that succeeds for the right parameters.
			var verifier options.AttestationVerifier
			if !tt.noVerifier {
				verifier = common.NewAttestationVerifier(tt.verifierOpts.digests, tt.packageName,
					tt.verifierOpts.env, tt.verifierOpts.releaserID, tt.verifierOpts.buildLevel)
			}
			opts := options.ReleaseVerification{
				Verifier: verifier,
			}
			protection, err := tt.policy.Evaluate(tt.digests, tt.packageName, tt.org, opts)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(*protection, project.Protection); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_FromReaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		policies      []Policy
		maxBuildLevel int
		buggyIterator bool
		expected      error
	}{
		{
			name:          "two valid policies",
			maxBuildLevel: 3,
			policies: []Policy{
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name2",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
		{
			name:          "same protection name",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policies: []Policy{
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
		{
			name:          "same iterator id",
			buggyIterator: true,
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policies: []Policy{
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name2",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
		{
			name:          "one policy same package name",
			buggyIterator: true,
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policies: []Policy{
				{
					Format: 1,
					Protection: Protection{
						ServiceAccount: "protection_name",
					},
					Packages: []Package{
						{
							Name: "package_name",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: "package_name",
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create the org policy (only the maxBuildLevel is needed).
			orgPolicy := organization.Policy{
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(tt.maxBuildLevel - 1),
							},
						},
						{
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(tt.maxBuildLevel),
							},
						},
					},
				},
			}

			// Marshal the project policies into bytes.
			policies := make([][]byte, len(tt.policies), len(tt.policies))
			for i := range tt.policies {
				content, err := json.Marshal(tt.policies[i])
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				policies[i] = content
			}
			// Create the project iterator.
			iter := common.NewNamedBytesIterator(policies, !tt.buggyIterator)

			// Call the constructor.
			_, err := FromReaders(iter, orgPolicy, nil)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// Same policy with a passing validator.
			iter = common.NewNamedBytesIterator(policies, !tt.buggyIterator)
			_, err = FromReaders(iter, orgPolicy, common.NewPolicyValidator(true))
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			// Same policy with a failing validator.
			iter = common.NewNamedBytesIterator(policies, !tt.buggyIterator)
			_, err = FromReaders(iter, orgPolicy, common.NewPolicyValidator(false))
			if diff := cmp.Diff(errs.ErrorInvalidField, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

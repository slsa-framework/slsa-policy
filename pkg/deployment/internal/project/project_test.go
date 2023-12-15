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
)

func Test_validateFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name: "format is 1",
			policy: &Policy{
				Format: 1,
			},
		},
		{
			name:     "no format defined",
			policy:   &Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "format is not 1",
			policy: &Policy{
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

func Test_validatePrincipal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		expected error
	}{
		{
			name: "uri present",
			policy: &Policy{
				Principal: principal{
					URI: "the_uri",
				},
			},
		},
		{
			name:     "uri not present",
			policy:   &Policy{},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.validatePrincipal()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_getPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *Policy
		uri      string
		expected error
	}{
		{
			name: "uri present",
			uri:  "uri2",
			policy: &Policy{
				Packages: []Package{
					{
						URI: "uri1",
					},
					{
						URI: "uri2",
					},
				},
			},
		},
		{
			name:     "uri not present",
			expected: errs.ErrorNotFound,
			uri:      "uri3",
			policy: &Policy{
				Packages: []Package{
					{
						URI: "uri1",
					},
					{
						URI: "uri2",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkg, err := tt.policy.getPackage(tt.uri)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.uri, pkg.URI, cmpopts.EquateErrors()); diff != "" {
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
		policy   *Policy
		expected error
	}{
		{
			name: "two valid packages",
			policy: &Policy{
				Packages: []Package{
					{
						URI: "the_uri",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					{
						URI: "the_uri2",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
				},
			},
		},
		{
			name:     "duplicate uri",
			expected: errs.ErrorInvalidField,
			policy: &Policy{
				Packages: []Package{
					{
						URI: "the_uri",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					{
						URI: "the_uri",
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
			policy: &Policy{
				Packages: []Package{
					{
						URI: "the_uri",
						Environment: Environment{
							AnyOf: []string{"", "prod"},
						},
					},
					{
						URI: "the_uri2",
						Environment: Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
				},
			},
		},
		{
			name:     "missing uri",
			expected: errs.ErrorInvalidField,
			policy: &Policy{
				Packages: []Package{
					{
						URI: "the_uri",
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
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.validatePackages()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateBuildRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		policy        *Policy
		maxBuildLevel int
		expected      error
	}{
		{
			name:          "same levels",
			maxBuildLevel: 3,
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(3),
				},
			},
		},
		{
			name:          "lower requried level",
			maxBuildLevel: 3,
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(2),
				},
			},
		},
		{
			name:          "higher requried level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(4),
				},
			},
		},
		{
			name:          "negative level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: -1,
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(4),
				},
			},
		},
		{
			name:          "large level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 5,
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(4),
				},
			},
		},
		{
			name:          "negative policy level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policy: &Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaLevel: common.AsPointer(-1),
				},
			},
		},
		{
			name:          "large policy level",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 5,
			policy: &Policy{
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
		packageURI string
		releaserID string
		env        string
	}
	org := &organization.Policy{
		Roots: organization.Roots{
			Release: []organization.Root{
				{
					ID: "releaser_id1",
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(3),
					},
				},
				{
					ID: "releaser_id2",
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(2),
					},
				},
			},
		},
	}
	project := &Policy{
		BuildRequirements: BuildRequirements{
			RequireSlsaLevel: common.AsPointer(2),
		},
		Packages: []Package{
			{
				URI: "package_uri",
				Environment: Environment{
					AnyOf: []string{"dev", "prod"},
				},
			},
			{
				URI: "package_uri2",
				Environment: Environment{
					AnyOf: []string{"dev", "prod"},
				},
			},
		},
	}
	vopts := dummyVerifierOpts{
		releaserID: "releaser_id2",
		packageURI: "package_uri",
		env:        "prod",
	}
	packageURI := "package_uri"
	tests := []struct {
		name         string
		policy       *Policy
		org          *organization.Policy
		noVerifier   bool
		packageURI   string
		verifierOpts dummyVerifierOpts
		expected     error
	}{
		{
			name:         "passing",
			verifierOpts: vopts,
			packageURI:   packageURI,
			org:          org,
			policy:       project,
		},
		{
			name:         "no verifier",
			expected:     errs.ErrorInvalidInput,
			noVerifier:   true,
			verifierOpts: vopts,
			packageURI:   packageURI,
			org:          org,
			policy:       project,
		},
		{
			name:         "package uri not present",
			expected:     errs.ErrorNotFound,
			verifierOpts: vopts,
			packageURI:   packageURI + "_not",
			org:          org,
			policy:       project,
		},
		{
			name:         "root levels too low",
			expected:     errs.ErrorVerification,
			verifierOpts: vopts,
			packageURI:   packageURI,
			org: &organization.Policy{
				Roots: organization.Roots{
					Release: []organization.Root{
						{
							ID: "releaser_id1",
							Build: organization.Build{
								MaxSlsaLevel: common.AsPointer(1),
							},
						},
						{
							ID: "releaser_id2",
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
				releaserID: "releaser_id2",
				packageURI: "package_uri",
				env:        "staging",
			},
			packageURI: packageURI,
			org:        org,
			policy:     project,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create the verifier that succeeds for the right parameters.
			var verifier options.AttestationVerifier
			if !tt.noVerifier {
				verifier = common.NewAttestationVerifier(tt.packageURI,
					tt.verifierOpts.env, tt.verifierOpts.releaserID)
			}
			opts := options.ReleaseVerification{
				Verifier: verifier,
			}
			err := tt.policy.Evaluate(tt.packageURI, *tt.org, opts)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
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
					Principal: principal{
						URI: "principal_uri",
					},
					Packages: []Package{
						{
							URI: "package_uri",
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
					Principal: principal{
						URI: "principal_uri2",
					},
					Packages: []Package{
						{
							URI: "package_uri",
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
			name:          "same principal uri",
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policies: []Policy{
				{
					Format: 1,
					Principal: principal{
						URI: "principal_uri",
					},
					Packages: []Package{
						{
							URI: "package_uri",
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
					Principal: principal{
						URI: "principal_uri",
					},
					Packages: []Package{
						{
							URI: "package_uri",
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
					Principal: principal{
						URI: "principal_uri",
					},
					Packages: []Package{
						{
							URI: "package_uri",
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
					Principal: principal{
						URI: "principal_uri2",
					},
					Packages: []Package{
						{
							URI: "package_uri",
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
			name:          "one policy same package uri",
			buggyIterator: true,
			expected:      errs.ErrorInvalidField,
			maxBuildLevel: 3,
			policies: []Policy{
				{
					Format: 1,
					Principal: principal{
						URI: "principal_uri",
					},
					Packages: []Package{
						{
							URI: "package_uri",
							Environment: Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							URI: "package_uri",
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
			iter := common.NewBytesIterator(policies, !tt.buggyIterator)

			// Call the constructor.
			_, err := FromReaders(iter, orgPolicy)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

package project

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
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

func Test_validatePackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		expected error
	}{
		{
			name:     "empty name",
			policy:   Policy{},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "set name",
			policy: Policy{
				Package: Package{
					Name: "non_empty_name",
				},
			},
		},
		{
			name: "set name and environment",
			policy: Policy{
				Package: Package{
					Name: "non_empty_name",
					Environment: Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			name: "empty environment field",
			policy: Policy{
				Package: Package{
					Name: "non_empty_name",
					Environment: Environment{
						AnyOf: []string{"", "dev", "prod"},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validatePackage()
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_validateBuildRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   Policy
		builders []string
		expected error
	}{
		{
			name: "valid policy",
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			builders: []string{"builder_name"},
		},
		{
			name: "builders not set",
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty builder name",
			policy: Policy{
				BuildRequirements: BuildRequirements{
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty repository name",
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "mismatch builder names",
			policy: Policy{
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder_name",
					Repository: Repository{
						URI: "non_empty",
					},
				},
			},
			builders: []string{"other_builder_name"},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validateBuildRequirements(tt.builders)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_FromReaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []Policy
		builders []string
		expected error
	}{
		{
			name: "valid policy",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
		},
		{
			name: "builder name not present in org policy",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "other_builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "package name re-use",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "package name re-use same env",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
						Environment: Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
						Environment: Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "package name re-use different env",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
						Environment: Environment{
							AnyOf: []string{"prod"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
						Environment: Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "package name re-use env set and not",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
						Environment: Environment{
							AnyOf: []string{"prod"},
						},
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "builder not set",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name: "empty builder name",
			policies: []Policy{
				Policy{
					Format: 1,
					Package: Package{
						Name: "name_set",
					},
					BuildRequirements: BuildRequirements{
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "empty repository name",
			policies: []Policy{
				Policy{
					Format: 1,
					BuildRequirements: BuildRequirements{
						RequireSlsaBuilder: "builder_name",
						Repository: Repository{
							URI: "non_empty",
						},
					},
				},
			},
			builders: []string{"builder_name"},
			expected: errs.ErrorInvalidField,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create the org policy (only the builder names are needed).
			orgPolicy := organization.Policy{}
			for i := range tt.builders {
				orgPolicy.Roots.Build = append(orgPolicy.Roots.Build, organization.Root{Name: tt.builders[i]})
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
			iter := common.NewBytesIterator(policies)

			// Call the constructor.
			_, err := FromReaders(iter, orgPolicy)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
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
	packageName := "package_name"
	sourceURI := "source_name"
	projectBuilder1 := Policy{
		Format: 1,
		Package: Package{
			Name: packageName,
		},
		BuildRequirements: BuildRequirements{
			RequireSlsaBuilder: "builder1",
			Repository: Repository{
				URI: sourceURI,
			},
		},
	}
	projectBuilder2 := Policy{
		Format: 1,
		Package: Package{
			Name: packageName,
		},
		BuildRequirements: BuildRequirements{
			RequireSlsaBuilder: "builder2",
			Repository: Repository{
				URI: sourceURI,
			},
		},
	}
	org := organization.Policy{
		Roots: organization.Roots{
			Build: []organization.Root{
				{
					ID:        "builder2_id",
					Name:      "builder2",
					SlsaLevel: common.AsPointer(2),
				},
				{
					ID:        "builder1_id",
					Name:      "builder1",
					SlsaLevel: common.AsPointer(1),
				},
			},
		},
	}
	vopts := dummyVerifierOpts{
		builderID: "builder1_id",
		sourceURI: sourceURI,
		digests:   digests,
	}
	tests := []struct {
		name         string
		policy       Policy
		org          organization.Policy
		noVerifier   bool
		packageName  string
		digests      intoto.DigestSet
		verifierOpts dummyVerifierOpts
		level        int
		expected     error
	}{
		{
			name:        "no verifier defined",
			packageName: packageName,
			digests:     digests,
			org:         org,
			policy:      projectBuilder1,
			noVerifier:  true,
			expected:    errs.ErrorInvalidInput,
		},
		{
			name:        "digest mismatch",
			packageName: packageName,
			digests: intoto.DigestSet{
				"sha256": "val256_different",
				"sha512": "val512",
			},
			org:      org,
			policy:   projectBuilder1,
			expected: errs.ErrorVerification,
		},
		{
			name:        "digest mismatch single",
			packageName: packageName,
			digests: intoto.DigestSet{
				"sha512": "val512_different",
			},
			org:      org,
			policy:   projectBuilder1,
			expected: errs.ErrorVerification,
		},
		{
			name:        "digest mismatch one correct match",
			packageName: packageName,
			digests: intoto.DigestSet{
				"sha512": "val512",
			},
			org:      org,
			policy:   projectBuilder1,
			expected: errs.ErrorVerification,
		},
		{
			name:        "empty digests",
			packageName: packageName,
			org:         org,
			policy:      projectBuilder1,
			expected:    errs.ErrorInvalidField,
		},
		{
			name:        "empty digest value",
			packageName: packageName,
			org:         org,
			policy:      projectBuilder1,
			digests: intoto.DigestSet{
				"sha256": "val256",
				"sha512": "",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name:        "empty digest key",
			packageName: packageName,
			org:         org,
			policy:      projectBuilder1,
			digests: intoto.DigestSet{
				"sha256": "val256",
				"":       "val512",
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name:         "builder 1 success",
			packageName:  packageName,
			digests:      digests,
			org:          org,
			policy:       projectBuilder1,
			level:        1,
			verifierOpts: vopts,
		},
		{
			name:        "builder 2 success",
			packageName: packageName,
			digests:     digests,
			org:         org,
			policy:      projectBuilder2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder2_id",
				sourceURI: sourceURI,
				digests:   digests,
			},
			level: 2,
		},
		{
			name:        "no builder is supported",
			packageName: packageName,
			digests:     digests,
			org:         org,
			policy:      projectBuilder2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder3_id",
				sourceURI: sourceURI,
				digests:   digests,
			},
			expected: errs.ErrorVerification,
		},
		{
			name:        "builder 2 different source",
			packageName: packageName,
			digests:     digests,
			org:         org,
			policy:      projectBuilder2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder2_id",
				sourceURI: sourceURI + "_different",
				digests:   digests,
			},
			expected: errs.ErrorVerification,
		},
		{
			name:        "request with env policy no env",
			packageName: packageName,
			digests:     digests,
			org:         org,
			policy:      projectBuilder1,
			level:       1,
			verifierOpts: dummyVerifierOpts{
				builderID:   "builder1_id",
				sourceURI:   sourceURI,
				digests:     digests,
				environment: common.AsPointer("dev"),
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name:        "request no env policy with env",
			packageName: packageName,
			digests:     digests,
			org:         org,
			policy: Policy{
				Format: 1,
				Package: Package{
					Name: packageName,
					Environment: Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				BuildRequirements: BuildRequirements{
					RequireSlsaBuilder: "builder1",
					Repository: Repository{
						URI: sourceURI,
					},
				},
			},
			level:        1,
			verifierOpts: vopts,
			expected:     errs.ErrorInvalidInput,
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
					tt.verifierOpts.builderID, tt.verifierOpts.sourceURI)
			}
			opts := options.BuildVerification{
				Verifier: verifier,
			}
			req := options.Request{
				Environment: tt.verifierOpts.environment,
			}
			level, err := tt.policy.Evaluate(tt.digests, tt.packageName, tt.org, req, opts)
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

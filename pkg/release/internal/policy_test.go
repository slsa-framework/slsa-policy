package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/common"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_PolicyNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		org      *organization.Policy
		projects []project.Policy
		expected error
	}{
		{
			name: "valid policies",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
		},
		{
			name: "same builder id",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same builder name",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same release uri",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same release uri env set and not",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same release uri different env",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
						Environment: project.Environment{
							AnyOf: []string{"prod"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same release uri same env",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri",
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "builder does not exist",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "other_builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidField,
		},
		{
			name: "same source valid",
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri",
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
			content, err := json.Marshal(*tt.org)
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
		builderID, sourceURI string
		environment          *string
		digests              intoto.DigestSet
	}
	digests := intoto.DigestSet{
		"sha256": "val256",
		"sha512": "val512",
	}
	tests := []struct {
		name         string
		org          *organization.Policy
		projects     []project.Policy
		verifierOpts dummyVerifierOpts
		level        int
		releaseURI   string
		expected     error
	}{
		{
			name:       "builder 1 success",
			releaseURI: "release_uri1",
			level:      2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "source_uri1",
				digests:   digests,
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
		},
		{
			name:       "mismatch release uri",
			releaseURI: "mismatch_release_uri1",
			level:      2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "source_uri1",
				digests:   digests,
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorNotFound,
		},
		{
			name:       "mismatch source uri",
			releaseURI: "release_uri1",
			level:      2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "mismatch_source_uri1",
				digests:   digests,
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorVerification,
		},
		{
			name:       "request with env policy no env",
			releaseURI: "release_uri1",
			level:      2,
			verifierOpts: dummyVerifierOpts{
				builderID:   "builder_name1",
				sourceURI:   "source_uri1",
				digests:     digests,
				environment: common.AsPointer("dev"),
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name:       "request no env policy with env",
			releaseURI: "release_uri1",
			level:      2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "source_uri1",
				digests:   digests,
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
						Environment: project.Environment{
							AnyOf: []string{"dev", "prod"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorInvalidInput,
		},
		{
			name:       "success builder 2 with dev env",
			releaseURI: "release_uri2",
			level:      3,
			verifierOpts: dummyVerifierOpts{
				builderID:   "builder_name2",
				sourceURI:   "source_uri2",
				digests:     digests,
				environment: common.AsPointer("dev"),
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
						Environment: project.Environment{
							AnyOf: []string{"dev"},
						},
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
		},
		{
			name:       "mismatch builder id",
			releaseURI: "release_uri1",
			level:      2,
			verifierOpts: dummyVerifierOpts{
				builderID: "mismatch_builder_name1",
				sourceURI: "source_uri1",
				digests:   digests,
			},
			org: &organization.Policy{
				Format: 1,
				Roots: organization.Roots{
					Build: []organization.Root{
						{
							ID:        common.AsPointer("builder_id1"),
							Name:      common.AsPointer("builder_name1"),
							SlsaLevel: common.AsPointer(2),
						},
						{
							ID:        common.AsPointer("builder_id2"),
							Name:      common.AsPointer("builder_name2"),
							SlsaLevel: common.AsPointer(3),
						},
					},
				},
			},
			projects: []project.Policy{
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri1",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name1",
						Repository: project.Repository{
							URI: "source_uri1",
						},
					},
				},
				{
					Format: 1,
					Release: project.Release{
						URI: "release_uri2",
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaBuilder: "builder_name2",
						Repository: project.Repository{
							URI: "source_uri2",
						},
					},
				},
			},
			expected: errs.ErrorVerification,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Org policy.
			content, err := json.Marshal(*tt.org)
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
			policy, err := PolicyNew(orgReader, projectsReader)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			if err != nil {
				return
			}
			// Create the verifier.
			verifier := common.NewAttestationVerifier(tt.verifierOpts.digests, tt.releaseURI,
				tt.verifierOpts.builderID, tt.verifierOpts.sourceURI)
			opts := options.BuildVerification{
				Verifier:    verifier,
				Environment: tt.verifierOpts.environment,
			}
			level, err := policy.Evaluate(tt.verifierOpts.digests, tt.releaseURI, opts)
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

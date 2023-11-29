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
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
	"github.com/laurentsimon/slsa-policy/pkg/release/internal/project"
	"github.com/laurentsimon/slsa-policy/pkg/release/options"
)

func Test_New(t *testing.T) {
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			name: "same publication uri",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
			name: "same publication uri env set and not",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
			name: "same publication uri different env",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
			name: "same publication uri same env",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
					Publication: project.Publication{
						URI: "publication_uri",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			_, err = New(orgReader, projectsReader)
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
	}
	tests := []struct {
		name           string
		org            *organization.Policy
		projects       []project.Policy
		verifierOpts   dummyVerifierOpts
		level          int
		publicationURI string
		expected       error
	}{
		{
			name:           "builder 1 success",
			publicationURI: "publication_uri1",
			level:          2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "source_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			name:           "mismatch publication uri",
			publicationURI: "mismatch_publication_uri1",
			level:          2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "source_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			name:           "mismatch source uri",
			publicationURI: "publication_uri1",
			level:          2,
			verifierOpts: dummyVerifierOpts{
				builderID: "builder_name1",
				sourceURI: "mismatch_source_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			name:           "request env not set",
			publicationURI: "publication_uri1",
			level:          2,
			verifierOpts: dummyVerifierOpts{
				builderID:   "builder_name1",
				sourceURI:   "source_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			name:           "success builder 2 with dev env",
			publicationURI: "publication_uri2",
			level:          3,
			verifierOpts: dummyVerifierOpts{
				builderID:   "builder_name2",
				sourceURI:   "source_uri2",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			name:           "mismatch builder id",
			publicationURI: "publication_uri1",
			level:          2,
			verifierOpts: dummyVerifierOpts{
				builderID: "mismatch_builder_name1",
				sourceURI: "source_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri1",
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
					Publication: project.Publication{
						URI: "publication_uri2",
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
			policy, err := New(orgReader, projectsReader)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			if err != nil {
				return
			}
			// Create the verifier.
			verifier := common.NewAttestationVerifier(tt.publicationURI,
				tt.verifierOpts.builderID, tt.verifierOpts.sourceURI)
			opts := options.BuildVerification{
				Verifier:    verifier,
				Environment: tt.verifierOpts.environment,
			}
			level, err := policy.Evaluate(tt.publicationURI, opts)
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

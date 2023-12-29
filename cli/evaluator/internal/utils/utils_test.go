package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_ParseImageReference(t *testing.T) {
	t.Parallel()
	digest := "sha256:f8bc336da3030b431b985652438661f17c0dc8eb9ab75a998c86e4b1387ee501"
	tests := []struct {
		name      string
		image     string
		digest    string
		registry  string
		container string
		expected  error
	}{
		{
			name:      "name only",
			expected:  errorImageParsing,
			image:     "repo/image",
			container: "docker.io/repo/image",
		},
		{
			name:      "name and tag",
			expected:  errorImageParsing,
			image:     "repo/image:tag",
			container: "docker.io/repo/image",
		},
		{
			name:      "docker.io and name",
			expected:  errorImageParsing,
			image:     "docker.io/repo/image",
			container: "docker.io/repo/image",
		},
		{
			name:      "index.docker.io and name",
			expected:  errorImageParsing,
			image:     "index.docker.io/repo/image",
			container: "docker.io/repo/image",
		},
		{
			name:      "gcr and name",
			expected:  errorImageParsing,
			image:     "gcr.io/repo/image",
			container: "gcr.io/repo/image",
		},
		{
			name:      "ghcr and name",
			expected:  errorImageParsing,
			image:     "ghcr.io/repo/image",
			container: "ghcr.io/repo/image",
		},
		{
			name:      "name and digest",
			image:     "repo/image@" + digest,
			container: "docker.io/repo/image",
			digest:    digest,
		},
		{
			name:      "docker.io name and digest",
			image:     "docker.io/repo/image@" + digest,
			container: "docker.io/repo/image",
			digest:    digest,
		},
		{
			name:      "docker.io name tag and digest",
			image:     "docker.io/repo/image:tag@" + digest,
			container: "docker.io/repo/image",
			digest:    digest,
		},
		{
			name:      "gcr.io name and digest",
			image:     "gcr.io/repo/image@" + digest,
			container: "gcr.io/repo/image",
			digest:    digest,
		},
		{
			name:      "gcr.io name tag and digest",
			image:     "gcr.io/repo/image:tag@" + digest,
			container: "gcr.io/repo/image",
			digest:    digest,
		},
		{
			name:      "ghcr.io name and digest",
			image:     "ghcr.io/repo/image@" + digest,
			container: "ghcr.io/repo/image",
			digest:    digest,
		},
		{
			name:      "ghcr.io name tag and digest",
			image:     "ghcr.io/repo/image:tag@" + digest,
			container: "ghcr.io/repo/image",
			digest:    digest,
		},
		{
			name:     "invalid digest",
			expected: errorImageParsing,
			image:    "ghcr.io/repo/image:tag@" + digest + "-",
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			container, digest, err := ParseImageReference(tt.image)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.container, container); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(tt.digest, digest); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

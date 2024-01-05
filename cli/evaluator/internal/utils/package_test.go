package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func Test_PackageDescriptor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		image    string
		desc     intoto.PackageDescriptor
		expected error
	}{
		{
			name:     "name only",
			expected: errorPackageName,
			image:    "repo/image",
		},
		{
			name:  "name and docker registry",
			image: "docker.io/repo/image",
			desc: intoto.PackageDescriptor{
				Name:     "repo/image",
				Registry: "docker.io",
			},
		},
		{
			name:  "name and gcr registry",
			image: "gcr.io/repo/image",
			desc: intoto.PackageDescriptor{
				Name:     "repo/image",
				Registry: "gcr.io",
			},
		},
		{
			name:  "name and ghcr registry",
			image: "ghcr.io/repo/image",
			desc: intoto.PackageDescriptor{
				Name:     "repo/image",
				Registry: "ghcr.io",
			},
		},
		{
			name:     "has tag",
			expected: errorPackageName,
			image:    "docker.io/repo/image:tag",
		},
		{
			name:     "has digest",
			expected: errorPackageName,
			image:    "docker.io/repo/image@sha256:f8bc336da3030b431b985652438661f17c0dc8eb9ab75a998c86e4b1387ee501",
		},
		{
			name:     "has digest and tag",
			expected: errorPackageName,
			image:    "docker.io/repo/image:tag@sha256:f8bc336da3030b431b985652438661f17c0dc8eb9ab75a998c86e4b1387ee501",
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkg := PackageHelper{}
			desc, err := pkg.PackageDescriptor(tt.image)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.desc, desc); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

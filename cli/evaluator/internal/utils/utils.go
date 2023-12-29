package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

var errorImageParsing = errors.New("failed to parse image reference")

func ReadFiles(dir string, ignore string) ([]string, error) {
	var projectsPath []string
	absIgnore, err := filepath.Abs(ignore)
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			// Skip the ignore file.
			if absPath == absIgnore {
				return nil
			}
			// Skip directories.
			if info.IsDir() {
				return nil
			}
			projectsPath = append(projectsPath, path)
			return nil
		})
	return projectsPath, err
}

// ParseImageReference parses the image reference.
func ParseImageReference(image string) (string, string, error) {
	// NOTE: disable "latest" default tag.
	ref, err := name.ParseReference(image, name.WithDefaultTag(""))
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to parse image (%q): %w", errorImageParsing, image, err)
	}
	// NOTE: WithDefaultRegistry("docker.io") does not seem to work, it
	// resets the value to index.docker.io
	registry := ref.Context().RegistryStr()
	if registry == name.DefaultRegistry {
		registry = "docker.io"
	}

	if !strings.HasPrefix(ref.Identifier(), "sha256:") {
		return "", "", fmt.Errorf("%w: no digest in image (%q)", errorImageParsing, image)
	}

	return registry + "/" + ref.Context().RepositoryStr(), ref.Identifier(), nil
}

func ImmutableImage(image string, digests intoto.DigestSet) string {
	return fmt.Sprintf("%v@sha256:%v", image, digests["sha256"])
}

func Log(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
}

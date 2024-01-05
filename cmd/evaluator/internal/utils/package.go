package utils

import (
	"fmt"
	"slices"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type PackageHelper struct{}

// PolicyPackageName constructs the policy name from the descriptor.
// In our case, it's registry/image.
func (h *PackageHelper) PolicyPackageName(packageDesc intoto.PackageDescriptor) (string, error) {
	return packageDesc.Registry + "/" + packageDesc.Name, nil
}

func (h *PackageHelper) PackageDescriptor(policyPackageName string) (intoto.PackageDescriptor, error) {
	var des intoto.PackageDescriptor
	if err := ValidatePolicyPackage(policyPackageName, nil); err != nil {
		return des, err
	}
	ref, err := name.ParseReference(policyPackageName, name.WithDefaultTag(""), name.WithDefaultRegistry(""))
	if err != nil {
		return des, fmt.Errorf("%w: failed to parse image (%q): %w", errorImageParsing, policyPackageName, err)
	}
	des.Registry = ref.Context().RegistryStr()
	if des.Registry == name.DefaultRegistry {
		des.Registry = "docker.io"
	}
	des.Name = ref.Context().RepositoryStr()
	return des, nil
}

// ValidatePolicyPackage validates the package name in the policy.
func ValidatePolicyPackage(policyPackageName string, environment []string) error {
	// Environment is allowed to be set, so nothing to validate.
	// Package name needs to contain both a registry and a name.
	// It must not container an identifier (tag, digest).
	ref, err := name.ParseReference(policyPackageName, name.WithDefaultTag(""), name.WithDefaultRegistry(""))
	if err != nil {
		return fmt.Errorf("%w: failed to parse image (%q): %w", errorImageParsing, policyPackageName, err)
	}
	// Verify the registry is set.
	registry := ref.Context().RegistryStr()
	if registry == "" {
		return fmt.Errorf("%w: registry is empty for image (%q)", errorPackageName, policyPackageName)
	}
	// Verify the registry value is one of the allowed values.
	// TODO(#14): Provide a configuration option in policy for allowed list.
	// NOTE: It's really important to ensure that the registries are validated. If not,
	// a team can "take over" a package policy by using a registry that resolves to the same
	// host. Example: index.docker.io resolves to docker.io. 44.219.3.189 also "resolves" to docker.io.
	// Recall that the package (name,registry) must be unique across all the team policy files.
	allowed := []string{"docker.io", "gcr.io", "ghcr.io"}
	if !slices.Contains(allowed, registry) {
		return fmt.Errorf("%w: registry (%q) not in the allow list (%q)", errorPackageName,
			policyPackageName, registry, allowed)
	}
	// Verify the identifier is not set.
	if ref.Identifier() != "" {
		return fmt.Errorf("%w: identifier is set for image (%q)", errorPackageName, policyPackageName)
	}
	return nil
}

package publish

import "github.com/laurentsimon/slsa-policy/pkg/utils/intoto"

// PackageHelper defines an interface to let callers
// customize the parsing of the packages defined
// in the policy.
type PackageHelper interface {
	// PolicyPackageName constructs a policy package name
	// from an attestation's intoto.PackageDescriptor.
	PolicyPackageName(intoto.PackageDescriptor) (string, error)
	// PackageDescriptor creates an attestation's package descriptor
	// from a policy's package name.
	PackageDescriptor(string) (intoto.PackageDescriptor, error)
}

package publish

import (
	"fmt"

	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

func newPackageHelper(registry string) PackageHelper {
	return &packageHelper{registry: registry}
}

type packageHelper struct {
	registry string
}

func (p *packageHelper) PolicyPackageName(desc intoto.PackageDescriptor) (string, error) {
	return desc.Registry + "/" + desc.Name, nil
}

func (p *packageHelper) PackageDescriptor(name string) (intoto.PackageDescriptor, error) {
	return intoto.PackageDescriptor{
		Name:     name,
		Registry: p.registry,
	}, nil
}

func newPolicyValidator(pass bool) PolicyValidator {
	return &policyValidator{pass: pass}
}

type policyValidator struct {
	pass bool
}

func (v *policyValidator) ValidatePackage(pkg ValidationPackage) error {
	if v.pass {
		return nil
	}
	return fmt.Errorf("failed to validate package: pass (%v)", v.pass)
}

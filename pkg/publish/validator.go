package publish

// ValidationPackage defines the structure holding
// package information to be validated.
type ValidationPackage struct {
	Name        string
	Environment ValidationEnvironment
}

// ValidationEnvironment defines the structure containing
// the policy environment to validate.
type ValidationEnvironment struct {
	AnyOf []string
}

// PolicyValidator defines an interface to validate
// certain fields in the policy.
type PolicyValidator interface {
	ValidatePackage(pkg ValidationPackage) error
}

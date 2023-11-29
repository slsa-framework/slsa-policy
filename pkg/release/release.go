package release

import (
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/release/internal"
	"github.com/laurentsimon/slsa-policy/pkg/release/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// Policy defines the release policy.
type Policy struct {
	policy *internal.Policy
}

// New creates a release policy.
func New(org io.ReadCloser, projects iterator.ReadCloserIterator) (*Policy, error) {
	policy, err := internal.New(org, projects)
	if err != nil {
		return nil, err
	}
	return &Policy{
		policy: policy,
	}, nil
}

// Evaluate evalues the release policy.
func (p *Policy) Evaluate(publicationURI string, buildOpts options.BuildVerification) (int, error) {
	return p.Evaluate(publicationURI, buildOpts)
}

package internal

import (
	"path/filepath"

	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
)

type Policy struct {
	orgPolicy organization.Policy
	// TODO: project part.
}

func New(root string) (*Policy, error) {
	org, err := organization.New(filepath.Join(root, "defaults.json"))
	if err != nil {
		return nil, err
	}
	return &Policy{
		orgPolicy: *org,
	}, nil
}

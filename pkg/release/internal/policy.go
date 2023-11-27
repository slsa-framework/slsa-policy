package internal

import (
	"path/filepath"

	"github.com/laurentsimon/slsa-policy/pkg/release/internal/organization"
)

type Policy struct {
	org organization.Policy
	//projects []
}

func New(root string) (*Policy, error) {
	org, err := organization.FromFile(filepath.Join(root, "defaults.json"))
	if err != nil {
		return nil, err
	}
	return &Policy{
		org: *org,
	}, nil
}

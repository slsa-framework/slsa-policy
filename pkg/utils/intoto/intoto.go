package intoto

import (
	"fmt"
	"time"

	"github.com/slsa-framework/slsa-policy/pkg/errs"
)

type DigestSet map[string]string

type Subject struct {
	Name    string    `json:"name,omitempty"`
	Digests DigestSet `json:"digest,omitempty"`
}

type Header struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subjects      []Subject `json:"subject"`
}

type PackageDescriptor struct {
	// Package name.
	Name string `json:"name,omitempty"`
	// Package registry.
	Registry string `json:"registry,omitempty"`
	// Package version.
	Version string `json:"version,omitempty"`
	// Package architectures.
	Arch string `json:"arch,omitempty"`
	// The package target distro.
	Distro string `json:"distro,omitempty"`
	// Package environment (debug, prod, etc).
	Environment string `json:"environment,omitempty"`
	// NOTE: Can add any additional fields.
	// We may define this structure as simmply a map[string]string.
}

type ResourceDescriptor struct {
	URI              string                 `json:"uri,omitempty"`
	Digest           DigestSet              `json:"digest,omitempty"`
	Name             string                 `json:"name,omitempty"`
	DownloadLocation string                 `json:"downloadLocation,omitempty"`
	MediaType        string                 `json:"mediaType,omitempty"`
	Content          []byte                 `json:"content,omitempty"`
	Annotations      map[string]interface{} `json:"annotations,omitempty"`
}

func (s Subject) Validate() error {
	return s.Digests.Validate()
}

func (r PackageDescriptor) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("%w: package name is empty", errs.ErrorInvalidField)
	}
	if r.Registry == "" {
		return fmt.Errorf("%w: package registry is empty", errs.ErrorInvalidField)
	}
	return nil
}

func (ds DigestSet) Validate() error {
	if len(ds) == 0 {
		return fmt.Errorf("%w: digests empty", errs.ErrorInvalidField)
	}
	for k, v := range ds {
		if k == "" {
			return fmt.Errorf("%w: digests has empty key", errs.ErrorInvalidField)
		}
		if v == "" {
			return fmt.Errorf("%w: digests key (%q) has empty value", errs.ErrorInvalidField, k)
		}
	}
	return nil
}

func GetAnnotationValue(anno map[string]interface{}, name string) (string, error) {
	if anno == nil {
		return "", nil
	}
	val, exists := anno[name]
	if !exists {
		return "", nil
	}
	valStr, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%w: package annotation (%q) is not a string (%T)", errs.ErrorInvalidField, name, val)
	}
	return valStr, nil

}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

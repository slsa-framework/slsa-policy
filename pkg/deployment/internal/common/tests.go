package common

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

func AsPointer[K interface{}](o K) *K {
	return &o
}

// Bytes iterator.
func NewBytesIterator(values [][]byte, uniqueID bool) iterator.NamedReadCloserIterator {
	return &bytesIterator{values: values, index: -1, uniqueID: uniqueID}
}

type bytesIterator struct {
	values   [][]byte
	index    int
	uniqueID bool
	err      error
}

func (iter *bytesIterator) Next() (string, io.ReadCloser) {
	if iter.err != nil {
		return "", nil
	}
	iter.index++
	if iter.uniqueID {
		return fmt.Sprintf("%d", iter.index), io.NopCloser(bytes.NewReader(iter.values[iter.index]))
	}
	return fmt.Sprintf("%d", 0), io.NopCloser(bytes.NewReader(iter.values[iter.index]))
}

func (iter *bytesIterator) HasNext() bool {
	if iter.err != nil {
		return false
	}
	return iter.index+1 < len(iter.values)
}

func (iter *bytesIterator) Error() error {
	return nil
}

// Attestation verifier.
func NewAttestationVerifier(packageURI, env string, releaserID string) options.AttestationVerifier {
	return &attesationVerifier{packageURI: packageURI, releaserID: releaserID, env: env}
}

type attesationVerifier struct {
	packageURI string
	releaserID string
	env        string
}

func (v *attesationVerifier) VerifyReleaseAttestation(packageURI string, env []string, releaserID string) (*string, error) {
	if packageURI == v.packageURI && releaserID == v.releaserID &&
		((v.env != "" && len(env) > 0 && slices.Contains(env, v.env)) ||
			(v.env == "" && len(env) == 0)) {
		return &v.env, nil
	}

	return nil, fmt.Errorf("%w: cannot verify package URI (%q) releaser ID (%q) env (%q)", errs.ErrorVerification, packageURI, releaserID, env)
}

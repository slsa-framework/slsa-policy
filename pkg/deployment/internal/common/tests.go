package common

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"github.com/laurentsimon/slsa-policy/pkg/deployment/internal/options"
	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

func AsPointer[K interface{}](o K) *K {
	return &o
}

// Bytes iterator.
func NewNamedBytesIterator(values [][]byte, uniqueID bool) iterator.NamedReadCloserIterator {
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
		return fmt.Sprintf("policy_id%d", iter.index), io.NopCloser(bytes.NewReader(iter.values[iter.index]))
	}
	return fmt.Sprintf("policy_id%d", 0), io.NopCloser(bytes.NewReader(iter.values[iter.index]))
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
func NewAttestationVerifier(digests intoto.DigestSet, packageName, env, releaserID string, buildLevel int) options.AttestationVerifier {
	return &attestationVerifier{digests: digests, packageName: packageName, releaserID: releaserID, env: env, buildLevel: buildLevel}
}

type attestationVerifier struct {
	packageName string
	releaserID  string
	buildLevel  int
	env         string
	digests     intoto.DigestSet
}

func (v *attestationVerifier) VerifyReleaseAttestation(digests intoto.DigestSet, packageName string, env []string, releaserID string, buildLevel int) (*string, error) {
	if buildLevel <= v.buildLevel && packageName == v.packageName && releaserID == v.releaserID &&
		MapEq(digests, v.digests) &&
		((v.env != "" && len(env) > 0 && slices.Contains(env, v.env)) ||
			(v.env == "" && len(env) == 0)) {
		if v.env == "" {
			return nil, nil
		}
		return &v.env, nil
	}
	return nil, fmt.Errorf("%w: cannot verify package Name (%q) releaser ID (%q) env (%q) buildLevel (%d)", errs.ErrorVerification, packageName, releaserID, env, buildLevel)
}

func MapEq(m1, m2 map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v := range m1 {
		vv, exists := m2[k]
		if !exists {
			return false
		}
		if vv != v {
			return false
		}
	}
	return true
}

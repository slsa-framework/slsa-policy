package common

import (
	"bytes"
	"fmt"
	"io"

	"github.com/slsa-framework/slsa-policy/pkg/errs"
	"github.com/slsa-framework/slsa-policy/pkg/publish/internal/options"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
	"github.com/slsa-framework/slsa-policy/pkg/utils/iterator"
)

func AsPointer[K interface{}](o K) *K {
	return &o
}

// Bytes iterator.
func NewBytesIterator(values [][]byte) iterator.ReadCloserIterator {
	return &bytesIterator{values: values, index: -1}
}

type bytesIterator struct {
	values [][]byte
	index  int
	err    error
}

func (iter *bytesIterator) Next() io.ReadCloser {
	if iter.err != nil {
		return nil
	}
	iter.index++
	return io.NopCloser(bytes.NewReader(iter.values[iter.index]))
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
func NewAttestationVerifier(digests intoto.DigestSet, packageName, builderID, sourceName string) options.AttestationVerifier {
	return &attestationVerifier{packageName: packageName,
		builderID: builderID, sourceName: sourceName,
		digests: digests}
}

type attestationVerifier struct {
	packageName string
	builderID   string
	sourceName  string
	digests     intoto.DigestSet
}

func (v *attestationVerifier) VerifyBuildAttestation(digests intoto.DigestSet, packageName, builderID, sourceName string) error {
	if packageName == v.packageName && builderID == v.builderID && sourceName == v.sourceName && mapEq(digests, v.digests) {
		return nil
	}
	return fmt.Errorf("%w: cannot verify package Name (%q) builder ID (%q) source Name (%q) digests (%q)",
		errs.ErrorVerification, packageName, builderID, sourceName, digests)
}

func mapEq(m1, m2 map[string]string) bool {
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

func NewPolicyValidator(pass bool) options.PolicyValidator {
	return &policyValidator{pass: pass}
}

type policyValidator struct {
	pass bool
}

func (v *policyValidator) ValidatePackage(pkg options.ValidationPackage) error {
	if v.pass {
		return nil
	}
	return fmt.Errorf("failed to validate package: pass (%v)", v.pass)
}

package common

import (
	"bytes"
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
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
func NewAttestationVerifier(publicationURI, builderID, sourceURI string) options.AttestationVerifier {
	return &attesationVerifier{publicationURI: publicationURI, builderID: builderID, sourceURI: sourceURI}
}

type attesationVerifier struct {
	publicationURI string
	builderID      string
	sourceURI      string
}

func (v *attesationVerifier) VerifyBuildAttestation(publicationURI, builderID, sourceURI string) error {
	if publicationURI == v.publicationURI && builderID == v.builderID && sourceURI == v.sourceURI {
		return nil
	}
	return fmt.Errorf("%w: cannot verify with publication URI (%q) builder ID (%q) and source URI (%q)",
		errs.ErrorVerification, publicationURI, builderID, sourceURI)
}

package common

import (
	"bytes"
	"fmt"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/errs"
	"github.com/laurentsimon/slsa-policy/pkg/release/options"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
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
func NewAttestationVerifier(publicationURI, builderID, sourceURI string, digests intoto.DigestSet) options.AttestationVerifier {
	return &attesationVerifier{publicationURI: publicationURI,
		builderID: builderID, sourceURI: sourceURI,
		digests: digests}
}

type attesationVerifier struct {
	publicationURI string
	builderID      string
	sourceURI      string
	digests        intoto.DigestSet
}

func (v *attesationVerifier) VerifyBuildAttestation(publicationURI, builderID, sourceURI string) (intoto.DigestSet, error) {
	if publicationURI == v.publicationURI && builderID == v.builderID && sourceURI == v.sourceURI {
		return v.digests, nil
	}
	// NOTE: We always need a digest. No digest means the artifact cannot be found.
	return v.digests, fmt.Errorf("%w: cannot verify release URI (%q) builder ID (%q) and source URI (%q)",
		errs.ErrorVerification, publicationURI, builderID, sourceURI)
}

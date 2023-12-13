package common

import (
	"bytes"
	"io"

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

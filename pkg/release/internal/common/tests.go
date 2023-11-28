package common

import (
	"bytes"
	"io"

	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

func AsPointer[K interface{}](o K) *K {
	return &o
}

func NewBytesIterator(values [][]byte) iterator.ReaderIterator {
	return &bytesIterator{values: values, index: -1}
}

type bytesIterator struct {
	values [][]byte
	index  int
	err    error
}

func (iter *bytesIterator) Next() io.Reader {
	if iter.err != nil {
		return nil
	}
	iter.index++
	return bytes.NewReader(iter.values[iter.index])
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

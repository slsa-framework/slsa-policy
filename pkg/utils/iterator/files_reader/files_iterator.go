package files_reader

import (
	"io"
	"os"

	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

func FromPaths(paths []string) iterator.ReaderIterator {
	return &filesIterator{paths: paths, index: -1}
}

type filesIterator struct {
	paths []string
	index int
	err   error
}

func (iter *filesIterator) Next() io.Reader {
	if iter.err != nil {
		return nil
	}
	iter.index++
	file, err := os.Open(iter.paths[iter.index])
	if err != nil {
		iter.err = err
		return nil
	}
	return file
}

func (iter *filesIterator) HasNext() bool {
	if iter.err != nil {
		return false
	}
	return iter.index+1 < len(iter.paths)
}

func (iter *filesIterator) Error() error {
	return iter.err
}

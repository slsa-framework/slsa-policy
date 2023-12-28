package named_files_reader

import (
	"io"
	"os"
	"path/filepath"

	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator"
)

// FromPaths creates an iterator for a list of files.
func FromPaths(paths []string) iterator.NamedReadCloserIterator {
	return &filesIterator{paths: paths, index: -1}
}

type filesIterator struct {
	paths []string
	index int
	err   error
}

func (iter *filesIterator) Next() (string, io.ReadCloser) {
	if iter.err != nil {
		return "", nil
	}
	iter.index++
	file, err := os.Open(iter.paths[iter.index])
	if err != nil {
		iter.err = err
		return "", nil
	}
	return filepath.Base(iter.paths[iter.index]), file
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

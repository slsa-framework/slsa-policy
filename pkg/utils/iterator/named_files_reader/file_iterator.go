package named_files_reader

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/slsa-framework/slsa-policy/pkg/utils/iterator"
)

// FromPaths creates an iterator for a list of files.
// root is the root dirctory stripped of absolute file paths to generate unique file IDs.
func FromPaths(root string, paths []string) iterator.NamedReadCloserIterator {
	absRoot, _ := filepath.Abs(root)
	return &filesIterator{root: absRoot + string(os.PathSeparator), paths: paths, index: -1}
}

type filesIterator struct {
	root  string
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
	absPath, _ := filepath.Abs(iter.paths[iter.index])
	p := strings.TrimPrefix(absPath, iter.root)
	return p, file
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

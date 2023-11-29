package iterator

import "io"

// ReaderIterator defines an iterator interface to read.
// NOTE: see https://medium.com/@MTrax/golang-iterator-pattern-47f0daa654de.
type ReadCloserIterator interface {
	Next() io.ReadCloser
	HasNext() bool
	Error() error
}

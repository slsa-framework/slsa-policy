package errs

import "errors"

var (
	ErrorInvalidField = errors.New("invalid field")
	ErrorInvalidInput = errors.New("invalid input")
	ErrorNotFound     = errors.New("not found")
)

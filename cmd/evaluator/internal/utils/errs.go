package utils

import "errors"

var (
	errorImageParsing = errors.New("failed to parse image reference")
	errorPackageName  = errors.New("invalid package name")
)

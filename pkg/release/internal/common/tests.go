package common

func AsPointer[K interface{}](o K) *K {
	return &o
}

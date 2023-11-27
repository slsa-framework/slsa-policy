package main

import (
	"fmt"

	"github.com/laurentsimon/slsa-policy/pkg/release"
)

func main() {
	fmt.Println("Hello, Modules!")
	_, err := release.New(".")
	if err != nil {
		panic(err)
	}
}

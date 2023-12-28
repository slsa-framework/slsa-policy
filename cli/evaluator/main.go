package main

import (
	"fmt"
	"os"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/deployment"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/release"
)

func usage(prog string) {
	msg := "" +
		"Usage: %s [command]\n" +
		"\n" +
		"Available commands:\n" +
		"release \t\tOperation on release policy\n" +
		"deployment \t\tOperation on deployment policy\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, prog)
	os.Exit(1)
}

func fatal(e error) {
	fmt.Fprintf(os.Stderr, "error: %v", e)
	os.Exit(2)
}

func main() {
	arguments := os.Args[1:]
	if len(arguments) < 1 {
		usage(os.Args[0])
	}
	switch arguments[0] {
	default:
		usage(os.Args[0])
	case "release":
		release.Run(os.Args[0], arguments[1:])
	case "deployment":
		deployment.Run(os.Args[0], arguments[1:])
	}
	os.Exit(0)
}

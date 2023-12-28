package main

import (
	"fmt"
	"os"
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
		runRelease(os.Args[0], arguments[1:])
	case "deployment":
		runDeployment(os.Args[0], arguments[1:])
	}
	os.Exit(0)
}

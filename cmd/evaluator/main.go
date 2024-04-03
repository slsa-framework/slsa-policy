package main

import (
	"os"

	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/deployment"
	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/publish"
	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/utils"
)

func usage(prog string) {
	msg := "" +
		"Usage: %s [command]\n" +
		"\n" +
		"Available commands:\n" +
		"publish \t\tOperation on publish policy\n" +
		"deployment \t\tOperation on deployment policy\n" +
		"\n"
	utils.Log(msg, prog)
	os.Exit(1)
}

func fatal(e error) {
	utils.Log("error: %v", e)
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
	case "publish":
		if err := publish.Run(os.Args[0], arguments[1:]); err != nil {
			utils.Log(err.Error() + "\n")
			os.Exit(2)
		}
	case "deployment":
		if err := deployment.Run(os.Args[0], arguments[1:]); err != nil {
			utils.Log(err.Error() + "\n")
			os.Exit(3)
		}
	}
	os.Exit(0)
}

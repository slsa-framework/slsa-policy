package deployment

import (
	"fmt"
	"os"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/deployment/evaluate"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/deployment/validate"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s deployment [options]\n" +
		"\n" +
		"Available options:\n" +
		"validate \t\tValidate the policy files\n" +
		"evaluate \t\tEvaluate the policy\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli)
	os.Exit(1)
}

func Run(cli string, args []string) {
	if len(args) < 1 {
		usage(cli)
	}
	switch args[0] {
	default:
		usage(cli)
	case "validate":
		validate.Run(cli, args[1:])
	case "evaluate":
		evaluate.Run(cli, args[1:])
	}
}

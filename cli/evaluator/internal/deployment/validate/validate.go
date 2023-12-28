package validate

import (
	"fmt"
	"os"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/pkg/deployment"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/named_files_reader"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s deployment validate orgPath projectsPath\n" +
		"\n" +
		"Example:\n" +
		"%s deployment validate ./path/to/policy/org ./path/to/policy/projects\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) {
	// We need 2 paths:
	// 1. Path to org policy
	// 2. Path to project policy.
	if len(args) != 2 {
		usage(cli)
	}
	orgPath := args[0]
	projectsPath, err := utils.ReadFiles(args[1], orgPath)
	if err != nil {
		panic(err)
	}
	// Create a policy. This will validate the files.
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectsReader := named_files_reader.FromPaths(cwd, projectsPath)
	organizationReader, err := os.Open(orgPath)
	_, err = deployment.PolicyNew(organizationReader, projectsReader)
	if err != nil {
		panic(err)
	}
}

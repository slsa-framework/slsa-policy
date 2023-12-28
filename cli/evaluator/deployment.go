package main

import (
	"fmt"
	"os"

	"github.com/laurentsimon/slsa-policy/pkg/deployment"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/named_files_reader"
)

func deploymentUsage(cli string) {
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

func runDeployment(cli string, args []string) {
	if len(args) < 1 {
		deploymentUsage(cli)
	}
	switch args[0] {
	default:
		deploymentUsage(cli)
	case "validate":
		runDeploymentValidate(cli, args[1:])
	case "evaluate":
		runDeploymentEvaluate(cli, args[1:])
	}
}

func deploymentValidateUsage(cli string) {
	msg := "" +
		"Usage: %s deployment validate orgPath projectsPath\n" +
		"\n" +
		"Example:\n" +
		"%s deployment validate ./path/to/policy/org ./path/to/policy/projects\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func runDeploymentValidate(cli string, args []string) {
	// We need 2 paths:
	// 1. Path to org policy
	// 2. Path to project policy.
	if len(args) != 2 {
		deploymentValidateUsage(cli)
	}
	orgPath := args[0]
	if err := validatePaths(orgPath, args[1]); err != nil {
		panic(err)
	}
	projectsPath, err := readFiles(args[1])
	if err != nil {
		panic(err)
	}
	// Create a policy. This will validate the files.
	projectsReader := named_files_reader.FromPaths(projectsPath)
	organizationReader, err := os.Open(orgPath)
	_, err = deployment.PolicyNew(organizationReader, projectsReader)
	if err != nil {
		panic(err)
	}
}

func runDeploymentEvaluate(cli string, args []string) {

}

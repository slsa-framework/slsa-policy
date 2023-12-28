package main

import (
	"fmt"
	"os"

	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/files_reader"
)

func releaseUsage(cli string) {
	msg := "" +
		"Usage: %s release [options]\n" +
		"\n" +
		"Available options:\n" +
		"validate \t\tValidate the policy files\n" +
		"evaluate \t\tEvaluate the policy\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli)
	os.Exit(1)
}

func runRelease(cli string, args []string) {
	if len(args) < 1 {
		releaseUsage(cli)
	}
	switch args[0] {
	default:
		releaseUsage(cli)
	case "validate":
		runReleaseValidate(cli, args[1:])
	case "evaluate":
		runReleaseEvaluate(cli, args[1:])
	}
}

func releaseValidateUsage(cli string) {
	msg := "" +
		"Usage: %s release validate orgPath projectsPath\n" +
		"\n" +
		"Example:\n" +
		"%s release validate ./path/to/policy/org ./path/to/policy/projects\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func runReleaseValidate(cli string, args []string) {
	// We need 2 paths:
	// 1. Path to org policy
	// 2. Path to project policy.
	if len(args) != 2 {
		releaseValidateUsage(cli)
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
	projectsReader := files_reader.FromPaths(projectsPath)
	organizationReader, err := os.Open(orgPath)
	_, err = release.PolicyNew(organizationReader, projectsReader)
	if err != nil {
		panic(err)
	}
}

func runReleaseEvaluate(cli string, args []string) {

}

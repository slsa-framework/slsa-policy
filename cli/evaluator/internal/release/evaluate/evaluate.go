package evaluate

import (
	"fmt"
	"os"
	"strings"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/files_reader"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s release evaluate orgPath projectsPath packageURI digest [optional:environment]\n" +
		"\n" +
		"Example:\n" +
		"%s release validate ./path/to/policy/org ./path/to/policy/projects laurentsimon/echo-server sha256:xxxx prod\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) {
	if len(args) < 4 || len(args) > 5 {
		usage(cli)
	}
	// Extract inputs.
	orgPath := args[0]
	projectsPath, err := utils.ReadFiles(args[1], orgPath)
	if err != nil {
		panic(err)
	}
	packageURI := args[2]
	digest := strings.Split(args[3], ":")
	if len(digest) != 2 || digest[0] == "" || digest[1] == "" {
		panic(fmt.Sprintf("invalid digest %q", args[3]))
	}
	var env *string
	if len(args) == 5 {
		env = new(string)
		*env = args[4]
	}

	// Create a policy.
	projectsReader := files_reader.FromPaths(projectsPath)
	organizationReader, err := os.Open(orgPath)
	pol, err := release.PolicyNew(organizationReader, projectsReader)
	if err != nil {
		panic(err)
	}

	// Evaluate the policy.
	buildOpts := release.BuildVerificationOption{
		Environment: env,
	}
	digests := intoto.DigestSet{
		digest[0]: digest[1],
	}
	result := pol.Evaluate(digests, packageURI, buildOpts)
	if result.Error() != nil {
		panic(result.Error())
	}

	// Create the attestation and sign it.
	// TODO: do not attach the attestation, so that caller can do it however they want.
}

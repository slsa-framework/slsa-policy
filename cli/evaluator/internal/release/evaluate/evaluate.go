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
		"Usage: %s release evaluate orgPath projectsPath packageURI [optional:environment]\n" +
		"\n" +
		"Example:\n" +
		"%s release validate ./path/to/policy/org ./path/to/policy/projects laurentsimon/echo-server@sha256:xxxx prod\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) error {
	if len(args) < 3 || len(args) > 4 {
		usage(cli)
	}
	// Extract inputs.
	orgPath := args[0]
	projectsPath, err := utils.ReadFiles(args[1], orgPath)
	if err != nil {
		return err
	}
	imageURI, digest, err := utils.ParseImageReference(args[2])
	if err != nil {
		return err
	}
	var env *string
	if len(args) == 4 {
		env = new(string)
		*env = args[3]
	}
	digestsArr := strings.Split(digest, ":")
	if len(digestsArr) != 2 {
		return fmt.Errorf("invalid digest (%q)", digest)
	}
	// Create a policy.
	projectsReader := files_reader.FromPaths(projectsPath)
	organizationReader, err := os.Open(orgPath)
	pol, err := release.PolicyNew(organizationReader, projectsReader)
	if err != nil {
		return err
	}

	// Evaluate the policy.
	buildOpts := release.BuildVerificationOption{
		Verifier: newBuildVerifier(),
	}
	reqOpts := release.RequestOption{
		Environment: env,
	}
	digests := intoto.DigestSet{
		digestsArr[0]: digestsArr[1],
	}
	result := pol.Evaluate(digests, imageURI, reqOpts, buildOpts)
	if result.Error() != nil {
		return result.Error()
	}

	// Create the attestation and sign it.
	// TODO: do not attach the attestation, so that caller can do it however they want.
	return nil
}

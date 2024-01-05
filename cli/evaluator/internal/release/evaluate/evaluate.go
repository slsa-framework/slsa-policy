package evaluate

import (
	"fmt"
	"os"
	"strings"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/release/validate"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils/crypto"
	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/files_reader"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s release evaluate orgPath projectsPath packageName creatorID [optional:environment]\n" +
		"\n" +
		"Example:\n" +
		"%s release evaluate ./path/to/policy/org ./path/to/policy/projects laurentsimon/echo-server@sha256:xxxx https://github.com/org/.slsa/.github/workflows/releaser.yml prod\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) error {
	if len(args) < 4 || len(args) > 5 {
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
	creatorID := args[3]
	var env *string
	if len(args) == 5 && args[4] != "" {
		// Only set the env if it's not empty.
		env = new(string)
		*env = args[4]
	}
	digestsArr := strings.Split(digest, ":")
	if len(digestsArr) != 2 {
		return fmt.Errorf("invalid digest (%q)", digest)
	}
	// Create a policy.
	projectsReader := files_reader.FromPaths(projectsPath)
	organizationReader, err := os.Open(orgPath)
	pol, err := release.PolicyNew(organizationReader, projectsReader, &utils.PackageHelper{}, release.SetValidator(&validate.PolicyValidator{}))
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
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

	// Create a release attestation and sign it.
	// TODO(#3): do not attach the attestation, so that caller can do it however they want.
	// TODO(#2): add policy.
	att, err := result.AttestationNew(creatorID)
	if err != nil {
		return fmt.Errorf("failed to create attestation: %w", err)
	}
	attBytes, err := att.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to get attestation bytes: %v\n", err)
	}
	fmt.Println(string(attBytes))

	return crypto.Sign(att, utils.ImmutableImage(imageURI, digests))
}

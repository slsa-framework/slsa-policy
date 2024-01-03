package evaluate

import (
	"fmt"
	"os"
	"strings"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils/crypto"
	"github.com/laurentsimon/slsa-policy/pkg/deployment"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
	"github.com/laurentsimon/slsa-policy/pkg/utils/iterator/named_files_reader"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s deployment evaluate orgPath projectsPath packageURI policyID creatorID [optional:environment]\n" +
		"\n" +
		"Example:\n" +
		"%s deployment evaluate ./path/to/policy/org ./path/to/policy/projects laurentsimon/echo-server@sha256:xxxx https://github.com/org/.slsa/.github/workflows/releaser.yml prod\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) error {
	if len(args) < 5 || len(args) > 6 {
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
	policyID := args[3]
	creatorID := args[4]
	var env *string
	if len(args) == 6 && args[5] != "" {
		// Only set the env if it's not empty.
		env = new(string)
		*env = args[5]
	}
	digestsArr := strings.Split(digest, ":")
	if len(digestsArr) != 2 {
		return fmt.Errorf("invalid digest (%q)", digest)
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Create a policy.
	projectsReader := named_files_reader.FromPaths(wd, projectsPath)
	organizationReader, err := os.Open(orgPath)
	pol, err := deployment.PolicyNew(organizationReader, projectsReader)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Evaluate the policy.
	buildOpts := deployment.ReleaseVerificationOption{
		Verifier: newReleaseVerifier(),
	}
	digests := intoto.DigestSet{
		digestsArr[0]: digestsArr[1],
	}
	result := pol.Evaluate(digests, imageURI, policyID, buildOpts)
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

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
		"Usage: %s release evaluate orgPath projectsPath packageName [optional:environment]\n" +
		"\n" +
		"Example:\n" +
		"%s release evaluate ./path/to/policy/org ./path/to/policy/projects laurentsimon/echo-server@sha256:xxxx prod\n" +
		"\n"
	fmt.Fprintf(os.Stderr, msg, cli, cli)
	os.Exit(1)
}

func Run(cli string, args []string) error {
	if len(args) != 4 {
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
	if len(args) == 4 && args[3] != "" {
		// Only set the env if it's not empty.
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
	pol, err := release.PolicyNew(organizationReader, projectsReader, &utils.PackageHelper{}, release.SetValidator(&validate.PolicyValidator{}))
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Evaluate the policy.
	opts := release.AttestationVerificationOption{
		Verifier: newBuildVerifier(),
	}
	reqOpts := release.RequestOption{
		Environment: env,
	}
	digests := intoto.DigestSet{
		digestsArr[0]: digestsArr[1],
	}
	// NOTE: imageURI must be the same as set in the policy's package name.
	result := pol.Evaluate(digests, imageURI, reqOpts, opts)
	if result.Error() != nil {
		return result.Error()
	}

	// Create a release attestation and sign it.
	// TODO(#3): do not attach the attestation, so that caller can do it however they want.
	// TODO(#2): add policy.
	att, err := result.AttestationNew()
	if err != nil {
		return fmt.Errorf("failed to create attestation: %w", err)
	}
	attBytes, err := att.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to get attestation bytes: %w\n", err)
	}
	fmt.Println(string(attBytes))

	return crypto.Sign(att, utils.ImmutableImage(imageURI, digests))
}

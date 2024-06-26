package evaluate

import (
	"fmt"
	"os"
	"strings"

	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/deployment/validate"
	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/utils"
	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/utils/crypto"
	"github.com/slsa-framework/slsa-policy/pkg/deployment"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
	"github.com/slsa-framework/slsa-policy/pkg/utils/iterator/named_files_reader"
)

func usage(cli string) {
	msg := "" +
		"Usage: %s deployment evaluate orgPath projectsPath packageURI policyID\n" +
		"\n" +
		"Example:\n" +
		"%s deployment evaluate ./path/to/policy/org ./path/to/policy/projects slsa-framework/echo-server@sha256:xxxx servers-prod.json\n" +
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
	policyID := args[3]
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
	if err != nil {
		return fmt.Errorf("failed to read org path: %w", err)
	}
	pol, err := deployment.PolicyNew(organizationReader, projectsReader, deployment.SetValidator(&validate.PolicyValidator{}))
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Evaluate the policy.
	opts := deployment.AttestationVerificationOption{
		Verifier: newPublishVerifier(),
	}
	digests := intoto.DigestSet{
		digestsArr[0]: digestsArr[1],
	}
	// NOTE: imageURI must be the same as set in the policy's package name.
	result := pol.Evaluate(digests, imageURI, policyID, opts)
	if result.Error() != nil {
		return result.Error()
	}

	// Create a publish attestation and sign it.
	// TODO(#3): do not attach the attestation, so that caller can do it however they want.
	// TODO(#2): add policy.
	att, err := result.AttestationNew()
	if err != nil {
		return fmt.Errorf("failed to create attestation: %w", err)
	}
	attBytes, err := att.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to get attestation bytes: %v", err)
	}
	fmt.Println(string(attBytes))

	return crypto.Sign(att, utils.ImmutableImage(imageURI, digests))
}

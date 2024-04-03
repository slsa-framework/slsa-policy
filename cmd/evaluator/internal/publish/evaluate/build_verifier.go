package evaluate

import (
	"context"
	"fmt"

	"github.com/slsa-framework/slsa-policy/cli/evaluator/internal/utils"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
)

type buildVerifier struct {
}

func newBuildVerifier() *buildVerifier {
	return &buildVerifier{}
}

func (v *buildVerifier) VerifyBuildAttestation(digests intoto.DigestSet, imageName, builderID, sourceURI string) error {
	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI: sourceURI,
		ExpectedDigest:    digests["sha256"],
	}

	builderOpts := &options.BuilderOpts{
		ExpectedID: &builderID,
	}
	// NOTE: the API expects an immutable image.
	immutableImage := utils.ImmutableImage(imageName, digests)
	_, fullBuilderID, err := verifiers.VerifyImage(context.Background(), immutableImage, nil, provenanceOpts, builderOpts)
	if err != nil {
		return fmt.Errorf("VerifyBuildAttestation: %w", err)
	}
	utils.Log("Image (%q) verified with builder ID (%q) and sourceURI (%q)\n", imageName, fullBuilderID.String(), sourceURI)
	return nil
}

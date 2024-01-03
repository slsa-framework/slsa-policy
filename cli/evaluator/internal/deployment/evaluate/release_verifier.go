package evaluate

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils/crypto"
	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type releaseVerifier struct {
}

func newReleaseVerifier() *releaseVerifier {
	return &releaseVerifier{}
}

func (v *releaseVerifier) VerifyReleaseAttestation(digests intoto.DigestSet, imageName string, environment []string, releaserID string) (*string, error) {

	// Validate the image.
	if strings.Contains(imageName, "@") || strings.Contains(imageName, ":") {
		return nil, fmt.Errorf("invalid iage name (%q)", imageName)
	}
	// Validate the digests.
	digest, ok := digests["sha256"]
	if !ok {
		return nil, fmt.Errorf("invalid digest (%q)", digests)
	}
	imageURI := fmt.Sprintf("%s@sha256:%s", imageName, digest)
	fmt.Println("imageURI:", imageURI)

	// Verify the signature.
	fullReleaserID, attBytes, err := crypto.Verify(imageURI, releaserID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify image (%q) with release ID (%q): %v", imageURI, releaserID, err)
	}
	fmt.Println(string(attBytes))

	// Verify the attestation itself.
	attReader := io.NopCloser(bytes.NewReader(attBytes))
	verification, err := release.VerificationNew(attReader)
	if err != nil {
		return nil, fmt.Errorf("failed to crate verifier for image (%q) and env (%q): %w", imageName, environment, err)
	}

	// TODO: envionment verification
	// TODO: level verification.
	if err := verification.Verify(fullReleaserID, digests, imageName); err != nil {
		return nil, fmt.Errorf("failed to crate verifier for image (%q) and env (%q): %w", imageName, environment, err)
	}

	env := "dev"
	utils.Log("Image (%q) verified with releaser ID (%q) and env (%q)\n", imageName, releaserID, env)
	return &env, nil
}

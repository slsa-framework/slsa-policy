package evaluate

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils/crypto"
	"github.com/laurentsimon/slsa-policy/pkg/deployment"
	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type releaseVerifier struct {
	deployment.AttestationVerifierReleaseOptions
}

func newReleaseVerifier() *releaseVerifier {
	return &releaseVerifier{}
}

func (v *releaseVerifier) validate() error {
	// Validate the identities.
	if err := crypto.ValidateIdentity(v.AttestationVerifierReleaseOptions.ReleaserID,
		v.AttestationVerifierReleaseOptions.ReleaserIDRegex); err != nil {
		return err
	}
	// Validate the build level.
	if v.AttestationVerifierReleaseOptions.BuildLevel <= 0 || v.AttestationVerifierReleaseOptions.BuildLevel > 4 {
		return fmt.Errorf("build level (%d) must be between 1 and 4", v.AttestationVerifierReleaseOptions.BuildLevel)
	}
	return nil
}

func (v *releaseVerifier) setOptions(opts deployment.AttestationVerifierReleaseOptions) error {
	// Set the options.
	v.AttestationVerifierReleaseOptions = opts
	// Validate the options.
	if err := v.validate(); err != nil {
		return err
	}
	return nil
}

func (v *releaseVerifier) verifySignature(imageName string, digests intoto.DigestSet) (string, []byte, error) {
	// Validate the image.
	if strings.Contains(imageName, "@") || strings.Contains(imageName, ":") {
		return "", nil, fmt.Errorf("invalid image name (%q)", imageName)
	}
	// Validate the digests.
	digest, ok := digests["sha256"]
	if !ok {
		return "", nil, fmt.Errorf("invalid digest (%q)", digests)
	}
	imageURI := fmt.Sprintf("%s@sha256:%s", imageName, digest)
	fmt.Println("imageURI:", imageURI)

	// Verify the signature.
	fullReleaserID, attBytes, err := crypto.VerifySignature(imageURI, v.AttestationVerifierReleaseOptions.ReleaserID,
		v.AttestationVerifierReleaseOptions.ReleaserIDRegex)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify image (%q) with releaser ID (%q) releaser ID regex (%q): %v",
			imageURI, v.AttestationVerifierReleaseOptions.ReleaserID, v.AttestationVerifierReleaseOptions.ReleaserIDRegex, err)
	}
	return fullReleaserID, attBytes, nil
}

func (v *releaseVerifier) verifyAttestationContent(attBytes []byte, imageName string, digests intoto.DigestSet, environment []string) (*string, error) {
	attReader := io.NopCloser(bytes.NewReader(attBytes))
	verification, err := release.VerificationNew(attReader, &utils.PackageHelper{})
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier for image (%q) and env (%q): %w", imageName, environment, err)
	}

	// Build level verification.
	levelOpts := []release.VerificationOption{
		release.IsSlsaBuildLevelOrAbove(v.AttestationVerifierReleaseOptions.BuildLevel),
	}
	// If environment is present, we must verify it.
	var errList []error
	if len(environment) > 0 {
		for i := range environment {
			penv := &environment[i]
			opts := append(levelOpts, release.IsPackageEnvironment(*penv))
			// WARNING: We must ensure that the imageName follows the format defined in the policy.
			// This is the case, since our policy expect an image as registry/image.
			if err := verification.Verify(digests, imageName, opts...); err != nil {
				// Keep track of errors.
				errList = append(errList, fmt.Errorf("failed to verify image (%q) and env (%q): %w", imageName, *penv, err))
				continue
			}
			// Success.
			utils.Log("Image (%q) verified with releaser ID (%q) and releaser ID regex (%q) and env (%q)\n",
				imageName, v.AttestationVerifierReleaseOptions.ReleaserID, v.AttestationVerifierReleaseOptions.ReleaserIDRegex, *penv)
			return penv, nil
		}
		// We could not verify the attestation.
		return nil, fmt.Errorf("%v", errList)
	}

	// No environment present.
	if err := verification.Verify(digests, imageName, levelOpts...); err != nil {
		return nil, fmt.Errorf("failed to verify image (%q) and env (%q): %w", imageName, environment, err)
	}
	utils.Log("Image (%q) verified with releaser ID (%q) and releaser ID regex (%q) and nil env\n",
		imageName, v.AttestationVerifierReleaseOptions.ReleaserID, v.AttestationVerifierReleaseOptions.ReleaserIDRegex)
	return nil, nil
}

func (v *releaseVerifier) VerifyReleaseAttestation(digests intoto.DigestSet, imageName string, environment []string, opts deployment.AttestationVerifierReleaseOptions) (*string, error) {
	if err := v.setOptions(opts); err != nil {
		return nil, err
	}

	// Verify the signature.
	_, attBytes, err := v.verifySignature(imageName, digests)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(attBytes))

	// Verify the attestation content.
	return v.verifyAttestationContent(attBytes, imageName, digests, environment)
}

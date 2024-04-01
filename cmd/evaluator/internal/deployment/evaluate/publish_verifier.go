package evaluate

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils/crypto"
	"github.com/laurentsimon/slsa-policy/pkg/deployment"
	"github.com/laurentsimon/slsa-policy/pkg/publish"
	"github.com/laurentsimon/slsa-policy/pkg/utils/intoto"
)

type publishVerifier struct {
	deployment.AttestationVerifierPublishOptions
}

func newPublishVerifier() *publishVerifier {
	return &publishVerifier{}
}

func (v *publishVerifier) validate() error {
	// Validate the identities.
	if err := crypto.ValidateIdentity(v.AttestationVerifierPublishOptions.PublishrID,
		v.AttestationVerifierPublishOptions.PublishrIDRegex); err != nil {
		return err
	}
	// Validate the build level.
	if v.AttestationVerifierPublishOptions.BuildLevel <= 0 || v.AttestationVerifierPublishOptions.BuildLevel > 4 {
		return fmt.Errorf("build level (%d) must be between 1 and 4", v.AttestationVerifierPublishOptions.BuildLevel)
	}
	return nil
}

func (v *publishVerifier) setOptions(opts deployment.AttestationVerifierPublishOptions) error {
	// Set the options.
	v.AttestationVerifierPublishOptions = opts
	// Validate the options.
	if err := v.validate(); err != nil {
		return err
	}
	return nil
}

func (v *publishVerifier) verifySignature(imageName string, digests intoto.DigestSet) (string, []byte, error) {
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
	fullPublishrID, attBytes, err := crypto.VerifySignature(imageURI, v.AttestationVerifierPublishOptions.PublishrID,
		v.AttestationVerifierPublishOptions.PublishrIDRegex)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify image (%q) with publishr ID (%q) publishr ID regex (%q): %v",
			imageURI, v.AttestationVerifierPublishOptions.PublishrID, v.AttestationVerifierPublishOptions.PublishrIDRegex, err)
	}
	return fullPublishrID, attBytes, nil
}

func (v *publishVerifier) verifyAttestationContent(attBytes []byte, imageName string, digests intoto.DigestSet, environment []string) (*string, error) {
	attReader := io.NopCloser(bytes.NewReader(attBytes))
	verification, err := publish.VerificationNew(attReader, &utils.PackageHelper{})
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier for image (%q) and env (%q): %w", imageName, environment, err)
	}

	// Build level verification.
	levelOpts := []publish.VerificationOption{
		publish.IsSlsaBuildLevelOrAbove(v.AttestationVerifierPublishOptions.BuildLevel),
	}
	// If environment is present, we must verify it.
	var errList []error
	if len(environment) > 0 {
		for i := range environment {
			penv := &environment[i]
			opts := append(levelOpts, publish.IsPackageEnvironment(*penv))
			// WARNING: We must ensure that the imageName follows the format defined in the policy.
			// This is the case, since our policy expect an image as registry/image.
			if err := verification.Verify(digests, imageName, opts...); err != nil {
				// Keep track of errors.
				errList = append(errList, fmt.Errorf("failed to verify image (%q) and env (%q): %w", imageName, *penv, err))
				continue
			}
			// Success.
			utils.Log("Image (%q) verified with publishr ID (%q) and publishr ID regex (%q) and env (%q)\n",
				imageName, v.AttestationVerifierPublishOptions.PublishrID, v.AttestationVerifierPublishOptions.PublishrIDRegex, *penv)
			return penv, nil
		}
		// We could not verify the attestation.
		return nil, fmt.Errorf("%v", errList)
	}

	// No environment present.
	if err := verification.Verify(digests, imageName, levelOpts...); err != nil {
		return nil, fmt.Errorf("failed to verify image (%q) and env (%q): %w", imageName, environment, err)
	}
	utils.Log("Image (%q) verified with publishr ID (%q) and publishr ID regex (%q) and nil env\n",
		imageName, v.AttestationVerifierPublishOptions.PublishrID, v.AttestationVerifierPublishOptions.PublishrIDRegex)
	return nil, nil
}

func (v *publishVerifier) VerifyPublishAttestation(digests intoto.DigestSet, imageName string, environment []string, opts deployment.AttestationVerifierPublishOptions) (*string, error) {
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

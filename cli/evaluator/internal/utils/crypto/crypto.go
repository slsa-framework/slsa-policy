package crypto

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/laurentsimon/slsa-policy/pkg/release"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	clisign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	cpolicy "github.com/sigstore/cosign/v2/pkg/policy"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// This file is copied from https://github.com/sigstore/cosign/blob/main/cmd/cosign/cli/attest/attest.go and
// https://github.com/sigstore/cosign/blob/main/cmd/cosign/cli/verify/verify_attestation.go
var ko = options.KeyOpts{
	FulcioURL: "https://fulcio.sigstore.dev",
	RekorURL:  "https://rekor.sigstore.dev",
	// Don't ask for confirmation to create a certificate.
	SkipConfirmation: true,
}

func uploadToTlog(ctx context.Context, sv *clisign.SignerVerifier, signature []byte, rekorURL string) (*cbundle.RekorBundle, error) {
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return nil, err
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := cosign.TLogUploadDSSEEnvelope(ctx, rekorClient, signature, rekorBytes)
	if err != nil {
		return nil, err
	}
	utils.Log("tlog entry created with index: %v\n", *entry.LogIndex)
	return cbundle.EntryToBundle(entry), nil
}

type Attestation interface {
	ToBytes() ([]byte, error)
	PredicateType() string
}

func Sign(att Attestation, immutableImage string) error {
	// Retrieve the attestation bytes.
	attBytes, err := att.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to get attestation bytes: %w", err)
	}

	// Set up the context.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30*time.Second))
	defer cancel()

	// registryOpts := options.RegistryOptions{}
	// ociremoteOpts, err := registryOpts.ClientOpts(ctx)
	// if err != nil {
	// 	return err
	// }
	// ref, err := name.ParseReference(immutableImage)
	// if err != nil {
	// 	return fmt.Errorf("parsing reference: %w", err)
	// }
	// digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	// if err != nil {
	// 	return err
	// }

	// Create the signer.
	sv, err := clisign.SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return fmt.Errorf("failed to get signer: %w", err)
	}
	defer sv.Close()

	// Create the DSSE signer wrapper.
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(attBytes), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}
	// Upload to TLog.
	bundle, err := uploadToTlog(ctx, sv, signedPayload, ko.RekorURL)
	if err != nil {
		return err
	}

	return attach(immutableImage, att, bundle, signedPayload, sv)
}

func attach(immutableImage string, att Attestation, bundle *cbundle.RekorBundle, signedPayload []byte, sv *clisign.SignerVerifier) error {
	// TODO: verify this empty option works properly.
	var ociremoteOpts []ociremote.Option
	// Add predicateType as manifest annotation.
	predicateTypeAnnotation := map[string]string{
		"predicateType": att.PredicateType(),
	}
	if sv.Cert == nil || sv.Chain == nil {
		return fmt.Errorf("signer cert and / or chain is nil")
	}
	opts := []static.Option{
		static.WithLayerMediaType(types.DssePayloadType),
		static.WithCertChain(sv.Cert, sv.Chain),
		static.WithAnnotations(predicateTypeAnnotation),
		static.WithBundle(bundle),
	}

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}

	digest, err := name.NewDigest(immutableImage)
	if err != nil {
		return fmt.Errorf("failed to create new digest: %w", err)
	}
	fmt.Printf("digest: %T: %v", digest, digest)
	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(digest, ociremoteOpts...)
	dd := cremote.NewDupeDetector(sv)
	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
	}

	// Replace attestation.
	ro := cremote.NewReplaceOp(att.PredicateType())
	signOpts = append(signOpts, mutate.WithReplaceOp(ro))
	newSE, err := mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}

func Verify(immutableImage string, identity string) (string, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30*time.Second))
	defer cancel()

	var err error
	releaserID := identity + "@refs/heads/main"
	co := &cosign.CheckOpts{
		// TODO: verify this empty option works properly.
		RegistryClientOpts: []ociremote.Option{},
		Offline:            false,
		Identities: []cosign.Identity{
			{
				Issuer: "https://token.actions.githubusercontent.com",
				// TODO(#9): make the ref customizable.
				Subject: releaserID,
			},
		},
		// WARNING: This must be set to vrify the subject!
		ClaimVerifier: cosign.IntotoSubjectClaimVerifier,
	}
	// Set CT log keys.
	co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get ctlog public keys: %w", err)
	}
	// Set up rekor client.
	co.RekorClient, err = rekor.NewClient(ko.RekorURL)
	if err != nil {
		return "", nil, fmt.Errorf("failted to create Rekor client: %w", err)
	}
	// This performs an online fetch of the Rekor public keys, but this is needed
	// for verifying tlog entries (both online and offline).
	co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("getting Rekor public keys: %w", err)
	}
	// Set up fulcio.
	// This performs an online fetch of the Fulcio roots. This is needed
	// for verifying keyless certificates (both online and offline).
	co.RootCerts, err = fulcio.GetRoots()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get Fulcio roots: %w", err)
	}
	co.IntermediateCerts, err = fulcio.GetIntermediates()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get Fulcio intermediates: %w", err)
	}
	digest, err := name.NewDigest(immutableImage)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create new digest: %w", err)
	}
	verified, bundleVerified, err := cosign.VerifyImageAttestations(ctx, digest, co)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify: %w", err)
	}
	if !bundleVerified {
		return "", nil, fmt.Errorf("failed to verify bundle")
	}
	var errList []error
	for _, vp := range verified {
		payload, predicateType, err := cpolicy.AttestationToPayloadJSON(ctx, release.PredicateType(), vp)
		if err != nil {
			errList = append(errList, fmt.Errorf("failed to convert to consumable policy validation: %w", err))
			continue
		}
		if len(payload) == 0 {
			// This is not the predicate type we're looking for.
			continue
		}
		if release.PredicateType() != predicateType {
			errList = append(errList, fmt.Errorf("internal error. predicate ype (%q) != attestation type (%q)",
				predicateType, release.PredicateType()))
			continue
		}
		return releaserID, payload, nil
	}
	return "", nil, fmt.Errorf("failed to verify: %v", errList)
}

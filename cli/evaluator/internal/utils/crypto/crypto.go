package crypto

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/laurentsimon/slsa-policy/cli/evaluator/internal/utils"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	clisign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// This file is copied from https://github.com/sigstore/cosign/blob/main/cmd/cosign/cli/attest/attest.go.
var ko = options.KeyOpts{
	FulcioURL: "https://fulcio.sigstore.dev",
	RekorURL:  "https://rekor.sigstore.dev",
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
	digest, err := name.NewDigest(immutableImage)
	if err != nil {
		return fmt.Errorf("failed to create new digest: %w", err)
	}
	fmt.Printf("digest: %T: %v", digest, digest)

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

	return attach(att.PredicateType(), bundle, signedPayload, sv, digest)
}

func attach(predicateType string, bundle *cbundle.RekorBundle, signedPayload []byte, sv *clisign.SignerVerifier, digest name.Digest) error {
	// TODO: verify this empty option works properly.
	var ociremoteOpts []ociremote.Option
	// Add predicateType as manifest annotation.
	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	opts := []static.Option{
		static.WithLayerMediaType(types.DssePayloadType),
		static.WithAnnotations(predicateTypeAnnotation),
		static.WithBundle(bundle),
	}

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(digest, ociremoteOpts...)
	dd := cremote.NewDupeDetector(sv)
	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
	}

	// Replace attestation. TODO
	// ro := cremote.NewReplaceOp(att.PredicateType())
	// signOpts = append(signOpts, mutate.WithReplaceOp(ro))

	newSE, err := mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}

package deployment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/slsa-framework/slsa-policy/pkg/deployment/internal/common"
	"github.com/slsa-framework/slsa-policy/pkg/deployment/internal/organization"
	"github.com/slsa-framework/slsa-policy/pkg/deployment/internal/project"
	"github.com/slsa-framework/slsa-policy/pkg/errs"
	"github.com/slsa-framework/slsa-policy/pkg/utils/intoto"
)

func Test_AttestationNew(t *testing.T) {
	t.Parallel()
	digests := intoto.DigestSet{
		"sha256":    "some_value",
		"gitCommit": "another_value",
	}
	subject := intoto.Subject{
		Digests: digests,
	}
	principal := project.Principal{
		URI: "principal_uri",
	}
	result := PolicyEvaluationResult{
		digests:   digests,
		principal: &principal,
	}
	opts := []AttestationCreationOption{}
	tests := []struct {
		name     string
		result   PolicyEvaluationResult
		options  []AttestationCreationOption
		subject  intoto.Subject
		expected error
	}{
		{
			name:    "all fields set",
			result:  result,
			options: opts,
			subject: subject,
		},
		{
			name:     "error result",
			expected: errs.ErrorInternal,
			result: PolicyEvaluationResult{
				err: errs.ErrorMismatch,
			},
			options: opts,
			subject: subject,
		},
		{
			name:     "invalid result",
			expected: errs.ErrorInternal,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			att, err := tt.result.AttestationNew(tt.options...)
			if diff := cmp.Diff(tt.expected, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(statementType, att.Header.Type); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff(predicateType, att.Header.PredicateType); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if diff := cmp.Diff([]intoto.Subject{tt.subject}, att.attestation.Header.Subjects); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			c := map[string]string{
				scopeKubernetesServiceAccount: tt.result.principal.URI,
			}
			if diff := cmp.Diff(c, att.attestation.Predicate.Scopes); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

// Attestation verifier.
func NewE2eAttestationVerifier(digests intoto.DigestSet, packageName, env, publishrID string, buildLevel int) AttestationVerifier {
	return &attestationVerifier{digests: digests, packageName: packageName, env: env, publishrID: publishrID, buildLevel: buildLevel}
}

type attestationVerifier struct {
	packageName string
	publishrID  string
	buildLevel  int
	env         string
	digests     intoto.DigestSet
}

func (v *attestationVerifier) VerifyPublishAttestation(digests intoto.DigestSet, packageName string, env []string, opts AttestationVerifierPublishOptions) (*string, error) {
	if opts.BuildLevel == v.buildLevel && packageName == v.packageName && opts.PublishrID == v.publishrID &&
		common.MapEq(digests, v.digests) &&
		((v.env != "" && len(env) > 0 && slices.Contains(env, v.env)) ||
			(v.env == "" && len(env) == 0)) {
		if v.env == "" {
			return nil, nil
		}
		return &v.env, nil
	}
	return nil, fmt.Errorf("%w: cannot verify package Name (%q) publishr ID (%q) env (%q) buildLevel (%d)", errs.ErrorVerification, packageName, opts.PublishrID, env, opts.BuildLevel)
}

func newPolicyValidator(pass bool) PolicyValidator {
	return &policyValidator{pass: pass}
}

type policyValidator struct {
	pass bool
}

func (v *policyValidator) ValidatePackage(pkg ValidationPackage) error {
	if v.pass {
		return nil
	}
	return fmt.Errorf("failed to validate package: pass (%v)", v.pass)
}

func Test_e2e(t *testing.T) {
	t.Parallel()
	digests := intoto.DigestSet{
		"sha256": "val256",
		"sha512": "val512",
	}
	publishrID1 := "publishr_id1"
	publishrID2 := "publishr_id2"
	packageName1 := "package_uri1"
	packageName2 := "package_uri2"
	packageName3 := "package_uri3"
	packageName4 := "package_uri4"
	pricipalURI1 := "principal_uri1"
	pricipalURI2 := "principal_uri2"
	// NOTE: the test iterator indexes policies starting at 0.
	policyID2 := "policy_id1"
	org := organization.Policy{
		Format: 1,
		Roots: organization.Roots{
			Publish: []organization.Root{
				{
					ID: publishrID1,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(2),
					},
				},
				{
					ID: publishrID2,
					Build: organization.Build{
						MaxSlsaLevel: common.AsPointer(3),
					},
				},
			},
		},
	}
	projects := []project.Policy{
		{
			Format: 1,
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(2),
			},
			Principal: project.Principal{
				URI: pricipalURI1,
			},
			Packages: []project.Package{
				{
					Name: packageName3,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					Name: packageName4,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
		{
			Format: 1,
			Principal: project.Principal{
				URI: pricipalURI2,
			},
			BuildRequirements: project.BuildRequirements{
				RequireSlsaLevel: common.AsPointer(3),
			},
			Packages: []project.Package{
				{
					Name: packageName1,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
				{
					Name: packageName2,
					Environment: project.Environment{
						AnyOf: []string{"dev", "prod"},
					},
				},
			},
		},
	}
	opts := []AttestationCreationOption{}
	buildLevel3 := 3
	tests := []struct {
		name             string
		org              organization.Policy
		projects         []project.Policy
		packageName      string
		digests          intoto.DigestSet
		options          []AttestationCreationOption
		policyID         string
		env              string
		buildLevel       int
		publishrID       string
		principalURI     string
		expected         error
		errorEvaluate    error
		errorAttestation error
		errorVerify      error
	}{
		{
			name: "all fields set",
			// Policies to evaluate.
			org:      org,
			projects: projects,
			policyID: policyID2,
			// Options to create the attestation.
			options: opts,
			env:     "prod",
			// Fields to validate the created attestation.
			digests:      digests,
			packageName:  packageName1,
			principalURI: pricipalURI2,
			// Data that the verifier will use.
			publishrID: publishrID2,
			buildLevel: buildLevel3,
		},
		{
			name: "env not provided",
			// Policies to evaluate.
			org:      org,
			projects: projects,
			policyID: policyID2,
			// Options to create the attestation.
			options: opts,
			// Fields to validate the created attestation.
			digests:      digests,
			packageName:  packageName1,
			principalURI: pricipalURI2,
			// Data that the verifier will use.
			publishrID:       publishrID2,
			buildLevel:       buildLevel3,
			errorEvaluate:    errs.ErrorVerification,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name: "env not in policy",
			// Policies to evaluate.
			org: org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							// NOTE: no env set.
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
			},
			policyID: policyID2,
			// Options to create the attestation.
			options: opts,
			env:     "prod",
			// Fields to validate the created attestation.
			digests:      digests,
			packageName:  packageName1,
			principalURI: pricipalURI2,
			// Data that the verifier will use.
			publishrID:       publishrID2,
			buildLevel:       buildLevel3,
			errorEvaluate:    errs.ErrorVerification,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name: "mismatch env",
			// Policies to evaluate.
			org:      org,
			projects: projects,
			policyID: policyID2,
			// Options to create the attestation.
			options: opts,
			env:     "mismatch",
			// Fields to validate the created attestation.
			digests:      digests,
			packageName:  packageName1,
			principalURI: pricipalURI2,
			// Data that the verifier will use.
			publishrID:       publishrID2,
			buildLevel:       buildLevel3,
			errorEvaluate:    errs.ErrorVerification,
			errorAttestation: errs.ErrorInternal,
		},
		{
			name: "no env",
			// Policies to evaluate.
			org: org,
			projects: []project.Policy{
				{
					Format: 1,
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(2),
					},
					Principal: project.Principal{
						URI: pricipalURI1,
					},
					Packages: []project.Package{
						{
							Name: packageName3,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
						{
							Name: packageName4,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
				{
					Format: 1,
					Principal: project.Principal{
						URI: pricipalURI2,
					},
					BuildRequirements: project.BuildRequirements{
						RequireSlsaLevel: common.AsPointer(3),
					},
					Packages: []project.Package{
						{
							Name: packageName1,
							// NOTE: no env set.
						},
						{
							Name: packageName2,
							Environment: project.Environment{
								AnyOf: []string{"dev", "prod"},
							},
						},
					},
				},
			},
			policyID: policyID2,
			// Options to create the attestation.
			options: opts,
			// Fields to validate the created attestation.
			digests:      digests,
			packageName:  packageName1,
			principalURI: pricipalURI2,
			// Data that the verifier will use.
			publishrID: publishrID2,
			buildLevel: buildLevel3,
		},
		{
			name: "evaluation error",
			// Policies to evaluate.
			org:      org,
			projects: projects,
			policyID: policyID2,
			// Options to create the attestation.
			options: opts,
			env:     "prod",
			// Fields to validate the created attestation.
			digests:      digests,
			packageName:  packageName1,
			principalURI: pricipalURI2,
			// Data that the verifier will use.
			publishrID:       publishrID1, // NOTE: mismatch publishr ID.
			buildLevel:       buildLevel3,
			errorEvaluate:    errs.ErrorVerification,
			errorAttestation: errs.ErrorInternal,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create the reader for the org policy.
			orgContent, err := json.Marshal(tt.org)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			orgReader := io.NopCloser(bytes.NewReader(orgContent))
			// Create the readers for the projects policy.
			// Marshal the project policies into bytes.
			policies := make([][]byte, len(tt.projects), len(tt.projects))
			for i := range tt.projects {
				content, err := json.Marshal(tt.projects[i])
				if err != nil {
					t.Fatalf("failed to marshal: %v", err)
				}
				policies[i] = content
			}
			projectsReader := common.NewNamedBytesIterator(policies, true)
			// Passing validator.
			_, err = PolicyNew(orgReader, projectsReader, SetValidator(newPolicyValidator(true)))
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			// Failing validator.
			orgReader = io.NopCloser(bytes.NewReader(orgContent))
			projectsReader = common.NewNamedBytesIterator(policies, true)
			_, err = PolicyNew(orgReader, projectsReader, SetValidator(newPolicyValidator(false)))
			if diff := cmp.Diff(errs.ErrorInvalidField, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			// No validator.
			orgReader = io.NopCloser(bytes.NewReader(orgContent))
			projectsReader = common.NewNamedBytesIterator(policies, true)
			pol, err := PolicyNew(orgReader, projectsReader)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			verifier := NewE2eAttestationVerifier(tt.digests, tt.packageName, tt.env, tt.publishrID, tt.buildLevel)
			opts := AttestationVerificationOption{
				Verifier: verifier,
			}
			result := pol.Evaluate(tt.digests, tt.packageName, tt.policyID, opts)
			if diff := cmp.Diff(tt.errorEvaluate, result.Error(), cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			att, err := result.AttestationNew(tt.options...)
			if diff := cmp.Diff(tt.errorAttestation, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
			if err != nil {
				return
			}
			attBytes, err := att.ToBytes()
			if err != nil {
				t.Fatalf("failed to get attestation bytes: %v\n", err)
			}
			verifReader := io.NopCloser(bytes.NewReader(attBytes))
			verification, err := VerificationNew(verifReader)
			if err != nil {
				t.Fatalf("failed to creation verification: %v", err)
			}

			// Create verification options.
			options := []VerificationOption{}
			// Verify.
			scopes := map[string]string{
				scopeKubernetesServiceAccount: tt.principalURI,
			}
			err = verification.Verify(tt.digests, scopes, options...)
			if diff := cmp.Diff(tt.errorVerify, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected err (-want +got): \n%s", diff)
			}
		})
	}
}

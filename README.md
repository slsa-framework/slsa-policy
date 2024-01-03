# slsa-policy

# SLSA policies

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
  - [What is SLSA?](#what-is-slsa)
  - [What is provenance?](#what-is-provenance)
  - [What is slsa-policy?](#what-is-slsa-repo)
- [Installation](#installation)
  - [Release policy](#release-policy)
    - [Org setup](#org-setup)
      - [Org-wide policy setup](#org-wide-policy-setup)
      - [Project policy setup](#project-wide-policy-setup)
      - [Pre-submit validation](#pre-submit-validation)
      - [Releaser workflow](#releaser-workflow)
    - [Team setup](#team-setup)
      - [Policy definition](#policy-definition)
      - [Call the release evaluator](#call-the-release-evaluator)
  - [Deployment policy](#deployment-policy)
    - [Org setup](#org-setup-1)
      - [Org-wide policy setup](#org-wide-policy-setup-1)
      - [Project policy setup](#project-wide-policy-setup-1)
      - [Pre-submit validation](#pre-submit-validation-1)
      - [Releaser workflow](#releaser-workflow-1)
    - [Team setup](#team-setup-1)
      - [Policy definition](#policy-definition-1)
      - [Call the release evaluator](#call-the-release-evaluator-1)
- [Technical design](#technical-design)
  - [Specifications](#specifications)

<!-- tocstop -->

## Overview

### What is SLSA?

[Supply chain Levels for Software Artifacts](https://slsa.dev), or SLSA (salsa),
is a security framework, a check-list of standards and controls to prevent
tampering, improve integrity, and secure packages and infrastructure in your
projects, businesses or enterprises.

SLSA defines an incrementially adoptable set of levels which are defined in
terms of increasing compliance and assurance. SLSA levels are like a common
language to talk about how secure software, supply chains and their component
parts really are.

### What is provenance?

Provenance is information, or metadata, about how a software artifact was
created. This could include information about what source code, build system,
and build steps were used, as well as who and why the build was initiated.
Provenance can be used to determine the authenticity and trustworthiness of
software artifacts that you use.

As part of the framework, SLSA defines a
[provenance format](https://slsa.dev/provenance/) which can be used hold this
metadata.

### What is slsa-policy?

slsa-policy is a Go library and an end-to-end demo showcasing how to enforce SLSA policies
across an organization. The policy focuses on:

1. Ensuring that builds are protected against tanpering across the SDLC
2. Ensuring all builds are bounds to a set of privileges, the same way that OS processes are restricted to a set of running privilages. In OS, users have permissions. In cloud environment, permissions (IAM) are associated with Service Accounts (SAs). So builds will be restricted to run on specific SAs defined by the policies. For more details on the design, see [Technical design](#technical-design).

## Installation

### Release policy

#### Org setup

##### Org-wide policy setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/org.json

TODO: write access to repo + admin. CODEOWNER contains admins

##### Project policy setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/projects

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

##### Pre-submit validation

TODO: example workflow to validate policy.

##### Releaser workflow

https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml

In the workflow above, the CLI is called as follows:

```bash
cd policies/release
# This expands to https://github.com/laurentsimon/slsa-org/.github/workflows/image-releaser.yml@refs/heads/main
creator_id="https://github.com/${{ needs.detect-env.outputs.repository }}/.github/workflows/image-releaser.yml@${{ needs.detect-env.outputs.ref }}"
# This is passed by the caller, e.g. dev or prod.
env="${{ inputs.environment }}"
go run . release evaluate org.json . "${image}" "${creator_id}" "${env}"
```

#### Team setup

##### Policy definition

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/projects

##### Call the release evaluator

See https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/build-echo-server.yml

After the workflow successfully run, you can verify the release attestation via:

```bash
# NOTE: change image to your image.
image=docker.io/laurentsimon/slsa-project-echo-server@sha256:4378b3d11e11ede0f64946e588c590e460e44f90c8a7921ad2cb7b04aaf298d4
creator_id=https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml@refs/heads/main
type=https://slsa.dev/release/v0.1
cosign verify-attestation "{$image}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "${creator_id}" 
    --type "${type}" | jq -r '.payload' | base64 -d | jq
```

### Deployment policy

#### Org setup

##### Org-wide policy setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/org.json

TODO: write access to repo + admin. CODEOWNER contains admins

##### Project policy setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/projects

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

##### Pre-submit validation

TODO: example workflow to validate policy.

##### Deployment workflow

https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-deployer.yml

In the workflow above, the CLI is called as follows:

```bash
cd policies/deployment
# This expands to https://github.com/laurentsimon/slsa-org/.github/workflows/image-deployer.yml@refs/heads/main
creator_id="https://github.com/${{ needs.detect-env.outputs.repository }}/.github/workflows/image-deployer.yml@${{ needs.detect-env.outputs.ref }}"
# This is provided by the caller. It is the unique path to the policy, e.g. servers-dev.json
policy_id="${{ inputs.policy-id }}"
go run . deployment evaluate org.json . "${image}" "${policy_id}" "${creator_id}"
```

#### Project setup

##### Policy definition

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/projects

##### Call the deployment evaluator

See https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/deploy-echo-server.yml

After the workflow successfully run, you can verify the release attestation via:

```bash
# NOTE: change image to your image.
image=docker.io/laurentsimon/slsa-project-echo-server@sha256:4378b3d11e11ede0f64946e588c590e460e44f90c8a7921ad2cb7b04aaf298d4
creator_id=https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-deployer.yml@refs/heads/main
type=https://slsa.dev/deployment/v0.1
cosign verify-attestation "{$image}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "${creator_id}" 
    --type "${type}" | jq -r '.payload' | base64 -d | jq
```

This verification will be made by the admission controller. It should further verify that:
1. "contextType" == "https://slsa.dev/deployment/contextType/PrincipalID"
2. "context": {
      "https://slsa.dev/deployment/context/principalID": "k8_sa://name@dev-project-id.iam.gserviceaccount.com"
    } == Kubernetes service account on the pod.


## Technical design

### Specifications

TODO
# SLSA policies

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
  - [What is SLSA?](#what-is-slsa)
  - [What is provenance?](#what-is-provenance)
  - [What is slsa-policy?](#what-is-slsa-repo)
- [Setup](#setup)
  - [Release policy](#release-policy)
    - [Org setup](#org-setup)
      - [Policy setup](#org-wide-policy-setup)
      - [Pre-submit validation](#pre-submit-validation)
      - [Releaser workflow](#releaser-workflow)
    - [Team setup](#team-setup)
      - [Policy definition](#policy-definition)
      - [Call the release evaluator](#call-the-release-evaluator)
  - [Deployment policy](#deployment-policy)
    - [Org setup](#org-setup-1)
      - [Policy setup](#org-wide-policy-setup-1)
      - [Pre-submit validation](#pre-submit-validation-1)
      - [Releaser workflow](#releaser-workflow-1)
    - [Team setup](#team-setup-1)
      - [Policy definition](#policy-definition-1)
      - [Call the deployment evaluator](#call-the-deployment-evaluator)
  - [Admission controller](#admission-controller)
    - [Kyverno](#kyverno)
    - [OPA](#opa)
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

slsa-policy is a Go library, a CLI and a set of GitHub Actions to implement source-to-deployment policies across an organization. The policy provides the following guarantees:

1. Containers (builds) are protected against tampering across the SDLC
2. Containers (builds) are bounds to a set of privileges, the same way that OS processes are restricted to a set of running privilages. In cloud environments,
  permissions are defined via IAM and are associated with Service Accounts (SAs) by the policy. For more details on the design, see [Technical design](#technical-design).

## Setup

### Release policy

#### Org setup

##### Policy setup

1. Create a folder to store the release policies. See an example [here](https://github.com/laurentsimon/slsa-org/tree/main/policies/release/).
1. Create a file with your trusted roots. See example [org.json](https://github.com/laurentsimon/slsa-org/tree/main/policies/release/org.json).
1. Set up ACLs on `org.json` and on the folder:
  1. Assign ownership via GitHub [CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) for this folder. Set the ownership to the administrators of the policy repository.
  1. Enable [Repository Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/managing-rulesets-for-a-repository) (formerly Branch Protection) for the branch that stores the policies. The following settings can be written as one rule, or [split into multiple rules](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#about-rule-layering). They can be specified at the repository level, or the [organization level](https://docs.github.com/enterprise-cloud@latest/organizations/managing-organization-settings/managing-rulesets-for-repositories-in-your-organization).
    1. Require a pull request before merging. Under additional settings: Require approvals (select at least 1-2 as the required number of approvals before merging).
    1. Require status checks to pass before merging. Under additional settings: Require branches to be up to date before merging (may be problematic for busy repos).
    1. Block force pushes
    1. Restrict deletions
    1. Limit any bypass actors to those that are strictly necessary (i.e. break glass).
    1. Require review from [CODEOWNERS](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#additional-settings).

##### Pre-submit validation

To validate the policy files, run the binary as:

```bash
cd policies/release
$ go run . release validate org.json .
```

TODO: we need pre-submits when new files are created, to ensure the appropriate owners are added to CODEOWNERS.

##### Releaser workflow

You need to define a workflow that your teams will call when they want to release their container images. See an example [image-releaser.yml](https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml)

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

Teams create their policy files under the folder defined by their organization in [Org-wide policy setup](#org-wide-policy-setup). See an example of a policy in [echo-server.json](https://github.com/laurentsimon/slsa-org/blob/main/policies/release/echo-server.json).

When a team creates a new file, the CODEOWNERS file should be udpated to give permissions to the team members who own the package. This allows teams to edit their policies without requiring reviews by the organization admnistrators.

##### Call the release evaluator

When publishing containers, teams must call the release policy evaluator service [image-releaser.yml](https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml) from [Releaser workflow](#release-workflow). See an example [build-echo-server.yml](https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/build-echo-server.yml).

After the workflow has successfully run, you may manually verify the release attestation via:

```bash
# NOTE: change image to your image.
$ image=docker.io/laurentsimon/slsa-project-echo-server@sha256:4378b3d11e11ede0f64946e588c590e460e44f90c8a7921ad2cb7b04aaf298d4
$ creator_id=https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml@refs/heads/main
$ type=https://slsa.dev/release/v0.1
$ cosign verify-attestation "{$image}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "${creator_id}" 
    --type "${type}" | jq -r '.payload' | base64 -d | jq
```

### Deployment policy

#### Org setup

##### Policy setup

1. Create a folder to store the release policies. See an example [here](https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/).
1. Create a file with your trusted roots. See example [org.json](https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/org.json).
1. Set up ACLs on the folder and the `org.json` file:
  1. Assign ownership via GitHub [CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) for this folder. Set the ownership to the administrators of the policy repository.
  1. Enable [Repository Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/managing-rulesets-for-a-repository) (formerly Branch Protection) for the branch that stores the policies. The following settings can be written as one rule, or [split into multiple rules](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#about-rule-layering). They can be specified at the repository level, or the [organization level](https://docs.github.com/enterprise-cloud@latest/organizations/managing-organization-settings/managing-rulesets-for-repositories-in-your-organization).
    1. Require a pull request before merging. Under additional settings: Require approvals (select at least 1-2 as the required number of approvals before merging).
    1. Require status checks to pass before merging. Under additional settings: Require branches to be up to date before merging (may be problematic for busy repos).
    1. Block force pushes
    1. Restrict deletions
    1. Limit any bypass actors to those that are strictly necessary (i.e. break glass).
    1. Require review from [CODEOWNERS](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#additional-settings).

##### Pre-submit validation

To validate the policy files, run the binary as:

```bash
cd policies/deployment
$ go run . deployment validate org.json .
```

TODO: we need pre-submits when new files are created, to ensure the appropriate owners are added to CODEOWNERS.

##### Deployment workflow

You need to define a workflow that your teams will call when they want to release their container images. See an example [image-deployer.yml](https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-deployer.yml)

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

Teams create their policy files under the folder defined by their organization in [Org-wide policy setup](#org-wide-policy-setup-1). See an example of a policy in [servers-prod.json](https://github.com/laurentsimon/slsa-org/blob/main/policies/deployment/servers-prod.json).

When a team creates a new file, the CODEOWNERS file should be udpated to give permissions to the team members who own the package. This allows teams to edit their policies without requiring reviews by the organization admnistrators.

##### Call the deployment evaluator

Before submitting a request to deploy containers, teams must call the deployment policy evaluator service [image-deployer.yml](https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-deployer.yml) from [Deployment workflow](#deployment-workflow). See an example [deploy-echo-server.yml](https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/deploy-echo-server.yml).

After the workflow has successfully run, you may manually verify the release attestation via:

```bash
# NOTE: change image to your image.
$ image=docker.io/laurentsimon/slsa-project-echo-server@sha256:4378b3d11e11ede0f64946e588c590e460e44f90c8a7921ad2cb7b04aaf298d4
$ creator_id=https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-deployer.yml@refs/heads/main
$ type=https://slsa.dev/deployment/v0.1
$ cosign verify-attestation "{$image}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "${creator_id}" 
    --type "${type}" | jq -r '.payload' | base64 -d | jq
```

This verification will be performed by the admission controller. See [Admission controller](#admission-controller).

### Admission controller

The admisson controller is responsible for verifying the deployment attestation:
1. Verify the signature
1. Verify "contextType" == "https://slsa.dev/deployment/contextType/PrincipalID"
2. Verify "context": {
      "https://slsa.dev/deployment/context/principalID": "k8_sa://name@dev-project-id.iam.gserviceaccount.com"
    } == Kubernetes service account on the pod.

#### Kyverno

TODO

#### OPA

TODO

## Technical design

### Specifications

TODO
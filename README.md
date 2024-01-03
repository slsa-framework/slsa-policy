# slsa-policy

https://earthly.dev/blog/golang-monorepo/
https://go.dev/doc/modules/managing-source

tags are ignore.

## Release policy

### Org setup

#### Org-wide policy setup and ACLs

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/org.json

TODO: write access to repo + admin. CODEOWNER contains admins

#### Project policy setup and ACLs

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/projects

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

#### Pre-submit validation

TODO: example workflow to validate policy.

#### Releaser workflow

https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml

Via CLI:

```bash
go run . release evaluate policiesrelease/org.json policiesrelease/ "$image" dev
```

### Team setup

#### Policy definition

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/projects

#### Call the release evaluator

See https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/build-echo-server.yml

## Deployment policy

### Org setup

#### Org-wide policy setup and ACLs

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/org.json

TODO: write access to repo + admin. CODEOWNER contains admins

#### Project policy setup and ACLs

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/projects

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

#### Pre-submit validation

TODO: example workflow to validate policy.

#### Deployment workflow

https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/prod-deployer.yml

Via CLI:

```bash
go run . deployment evaluate policiesdeployment/org.json policiesdeployment/ "$image" dev
```

### Project setup

#### Policy definition

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/projects

#### Call the deployment evaluator

See https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/deploy-echo-server.yml
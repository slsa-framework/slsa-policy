# slsa-policy

https://earthly.dev/blog/golang-monorepo/
https://go.dev/doc/modules/managing-source

tags are ignore.

## Release policy

### Org setup

#### Root setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/org.json

### Projects setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/projects

### ACLs for admins

TODO: write access to repo + admin. CODEOWNER contains admins

### ACLs for project owners

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

### Pre-submit validation

TODO: example workflow to validate policy.

### Releaser workflow

https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/image-releaser.yml

Via CLI:

```bash
go run . release evaluate testdata/release/org.json testdata/release/ "$image" dev
```

### Project setup

#### Policy definition

See https://github.com/laurentsimon/slsa-org/tree/main/policies/release/projects

#### Call the release evaluator

See https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/build-echo-server.yml

### Deployment policy

### Org setup

#### Root setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/org.json

### Projects setup

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/projects

### ACLs for admins

TODO: write access to repo + admin. CODEOWNER contains admins

### ACLs for project owners

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

### Pre-submit validation

TODO: example workflow to validate policy.

### Releaser workflow

https://github.com/laurentsimon/slsa-org/blob/main/.github/workflows/prod-deployer.yml

Via CLI:

```bash
go run . deployment evaluate testdata/release/org.json testdata/release/ "$image" dev
```

### Project setup

#### Policy definition

See https://github.com/laurentsimon/slsa-org/tree/main/policies/deployment/projects

#### Call the deployment evaluator

See https://github.com/laurentsimon/slsa-project/blob/main/.github/workflows/deploy-echo-server.yml
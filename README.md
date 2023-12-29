# slsa-policy

https://earthly.dev/blog/golang-monorepo/
https://go.dev/doc/modules/managing-source

tags are ignore.

## Policy creation on the org

### ACLs for org

TODO: write access to repo + admin. CODEOWNER contains admins

### ACLs for teams

TODO: write access to repo - admin. CODEONWERS contains the owner of the file.

## Release

### Build the container

Run https://github.com/laurentsimon/slsa-project/actions/workflows/build-echo-server.yml, which will create ghcr.io/laurentsimon/slsa-project-echo-server.
In my case, it's docker.io/laurentsimon/slsa-project-echo-server@sha256:3ea35df97f1c8f80984322af66356fbf52d5c05baf7f41a0ec2fd6a5e75bc088
So image=docker.io/laurentsimon/slsa-project-echo-server@sha256:3ea35df97f1c8f80984322af66356fbf52d5c05baf7f41a0ec2fd6a5e75bc088

### Evaluate the release policy

Via CLI:

```bash
go run . release evaluate testdata/release/org.json testdata/release/ "$image" dev
```

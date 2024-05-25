FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.22-openshift-4.17 AS builder_rhel9
WORKDIR /go/src/github.com/openshift/cloud-credential-operator
COPY . .
ENV GO_PACKAGE github.com/openshift/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/ccoctl

FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.22-openshift-4.17 AS builder_rhel8
WORKDIR /go/src/github.com/openshift/cloud-credential-operator
COPY . .
ENV GO_PACKAGE github.com/openshift/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/ccoctl


FROM registry.ci.openshift.org/ocp/4.17:base-rhel9
COPY --from=builder_rhel9 /go/src/github.com/openshift/cloud-credential-operator/cloud-credential-operator /usr/bin/cloud-credential-operator
COPY --from=builder_rhel8 /go/src/github.com/openshift/cloud-credential-operator/ccoctl /usr/bin/ccoctl.rhel8
COPY --from=builder_rhel9 /go/src/github.com/openshift/cloud-credential-operator/ccoctl /usr/bin/ccoctl.rhel9
COPY --from=builder_rhel8 /go/src/github.com/openshift/cloud-credential-operator/ccoctl /usr/bin/ccoctl
COPY manifests /manifests

# Update perms so we can copy updated CA if needed
RUN chmod -R g+w /etc/pki/ca-trust/extracted/pem/
LABEL io.openshift.release.operator=true
# TODO make path explicit here to remove need for ENTRYPOINT
# https://github.com/openshift/installer/blob/a8ddf6619794416c4600a827c2d9284724d382d8/data/data/bootstrap/files/usr/local/bin/bootkube.sh.template#L347
ENTRYPOINT [ "/usr/bin/cloud-credential-operator" ]

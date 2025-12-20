FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.22 AS builder_rhel9
WORKDIR /go/src/github.com/openshift/cloud-credential-operator
COPY . .
ENV GO_PACKAGE github.com/openshift/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/ccoctl
RUN make cloud-credential-tests-ext && \
    mkdir -p /tmp/build && \
    gzip -c ./cloud-credential-tests-ext > /tmp/build/cloud-credential-tests-ext.gz

FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.24-openshift-4.22 AS builder_rhel8
WORKDIR /go/src/github.com/openshift/cloud-credential-operator
COPY . .
ENV GO_PACKAGE github.com/openshift/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/ccoctl


FROM registry.ci.openshift.org/ocp/4.22:base-rhel9
COPY --from=builder_rhel9 /go/src/github.com/openshift/cloud-credential-operator/cloud-credential-operator /usr/bin/cloud-credential-operator
COPY --from=builder_rhel8 /go/src/github.com/openshift/cloud-credential-operator/ccoctl /usr/bin/ccoctl.rhel8
COPY --from=builder_rhel9 /go/src/github.com/openshift/cloud-credential-operator/ccoctl /usr/bin/ccoctl.rhel9
COPY --from=builder_rhel8 /go/src/github.com/openshift/cloud-credential-operator/ccoctl /usr/bin/ccoctl
COPY --from=builder_rhel9 /tmp/build/cloud-credential-tests-ext.gz /usr/bin/cloud-credential-tests-ext.gz
COPY manifests /manifests

# Update perms so we can copy updated CA if needed
RUN chmod -R g+w /etc/pki/ca-trust/extracted/pem/
LABEL io.openshift.release.operator=true
LABEL io.k8s.display-name="OpenShift Cloud Credential Operator" \
      io.openshift.release.operator=true \
      io.openshift.tags="openshift,tests,e2e,e2e-extension"
# TODO make path explicit here to remove need for ENTRYPOINT
# https://github.com/openshift/installer/blob/a8ddf6619794416c4600a827c2d9284724d382d8/data/data/bootstrap/files/usr/local/bin/bootkube.sh.template#L347
ENTRYPOINT [ "/usr/bin/cloud-credential-operator" ]

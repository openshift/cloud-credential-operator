FROM registry.svc.ci.openshift.org/ocp/builder:rhel-8-golang-1.15-openshift-4.7 AS builder
WORKDIR /go/src/github.com/openshift/cloud-credential-operator
COPY . .
ENV GO_PACKAGE github.com/openshift/cloud-credential-operator
RUN go build -ldflags "-X $GO_PACKAGE/pkg/version.versionFromGit=$(git describe --long --tags --abbrev=7 --match 'v[0-9]*')" ./cmd/cloud-credential-operator

FROM registry.svc.ci.openshift.org/ocp/4.7:base
COPY --from=builder /go/src/github.com/openshift/cloud-credential-operator/cloud-credential-operator /usr/bin/
COPY manifests /manifests

# Since /etc/pki/ca-trust is now volume mounted at runtime, we cannot use RUN
# command to make its content world writable as it won't be included in the
# final image. To workaround this we ADD archived contents of /etc/pki/ca-trust
# as writable empty files and then run 'update-ca-trust extract' in the
# container to populate these files
ADD hack/writable-extracted.tar.gz /etc/pki/ca-trust/extracted
LABEL io.openshift.release.operator=true
# TODO make path explicit here to remove need for ENTRYPOINT
# https://github.com/openshift/installer/blob/a8ddf6619794416c4600a827c2d9284724d382d8/data/data/bootstrap/files/usr/local/bin/bootkube.sh.template#L347
ENTRYPOINT [ "/usr/bin/cloud-credential-operator" ]

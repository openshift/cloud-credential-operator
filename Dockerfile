#
# Dockerfile for building local images.
#

# Build the manager binary
FROM registry.svc.ci.openshift.org/openshift/release:golang-1.10 as builder

# Copy in the go src
WORKDIR /go/src/github.com/openshift/cloud-credential-operator
COPY pkg/    pkg/
COPY cmd/    cmd/
COPY vendor/ vendor/
COPY version/ version/

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -o manager github.com/openshift/cloud-credential-operator/cmd/manager

# Copy the controller-manager into a thin image
FROM registry.svc.ci.openshift.org/openshift/origin-v4.0:base
WORKDIR /root/
COPY --from=builder /go/src/github.com/openshift/cloud-credential-operator/manager .
ADD manifests/ /manifests

LABEL io.openshift.release.operator=true
ENTRYPOINT ["./manager"]

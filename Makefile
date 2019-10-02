
# Image URL to use all building/pushing image targets
IMG ?= cloud-credential-operator:latest

DISTRO ?= $(shell if which lsb_release &> /dev/null; then lsb_release -si; else echo "Unknown"; fi)

# Default fedora to not using sudo since it's not needed
ifeq ($(DISTRO),Fedora)
	SUDO_CMD =
else # Other distros like RHEL 7 and CentOS 7 currently need sudo.
	SUDO_CMD = sudo
endif

all: test manager

# Run tests
test: generate fmt vet manifests
	go test ./pkg/... ./cmd/... -coverprofile cover.out

# Run tests without attempting any code generation. (CI)
test-no-gen: fmt vet
	go test ./pkg/... ./cmd/... -coverprofile cover.out

.PHONY: test-sec
test-sec:
	@which gosec 2> /dev/null >&1 || { echo "gosec must be installed to lint code";  exit 1; }
	gosec -severity medium --confidence medium -quiet ./...

# Build manager binary
manager: generate fmt vet
	go build -o bin/manager github.com/openshift/cloud-credential-operator/cmd/manager

# Build without attempting any code generation. (CI)
build-no-gen: fmt vet
	go build -o bin/manager github.com/openshift/cloud-credential-operator/cmd/manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./cmd/manager --log-level=debug

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
.PHONY: manifests
deploy: manifests
	kubectl apply -f config/crds
	kustomize build config | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go crd
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go rbac --name cloud-credential-operator
	# kustomize and move to manifests dir for release image:
	kustomize build config > manifests/01_deployment.yaml
	cp config/crds/cloudcredential_v1_credentialsrequest.yaml manifests/00_v1_crd.yaml

# Run go fmt against code
fmt:
	go fmt ./pkg/... ./cmd/...

# Run go vet against code
vet:
	go vet ./pkg/... ./cmd/...

# Generate code
generate:
	go generate ./pkg/... ./cmd/...
	hack/update-bindata.sh

# Build the image with buildah
.PHONY: buildah-build
buildah-build: test
	BUILDAH_ISOLATION=chroot $(SUDO_CMD) buildah bud --tag ${IMG} .

.PHONY: buildah-push
buildah-push: buildah-build
	$(SUDO_CMD) buildah push ${IMG}


# Image URL to use all building/pushing image targets
IMG ?= cloud-credential-operator:latest
DOCKER_CMD ?= docker

all: test manager

# Run tests
test: generate fmt vet manifests
	go test ./pkg/... ./cmd/... -coverprofile cover.out

# Run tests without attempting any code generation. (CI)
test-no-gen: fmt vet
	go test ./pkg/... ./cmd/... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -o bin/manager github.com/openshift/cloud-credential-operator/cmd/manager

# Build without attempting any code generation. (CI)
build-no-gen: fmt vet
	go build -o bin/manager github.com/openshift/cloud-credential-operator/cmd/manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./cmd/manager/main.go --log-level=debug

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	kubectl apply -f config/crds
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go crd
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go rbac --name cloud-credential-operator

# Run go fmt against code
fmt:
	go fmt ./pkg/... ./cmd/...

# Run go vet against code
vet:
	go vet ./pkg/... ./cmd/...

# Generate code
generate:
	go generate ./pkg/... ./cmd/...

# Build the image with buildah
.PHONY: buildah-build
buildah-build: test
	BUILDAH_ISOLATION=chroot sudo buildah bud --tag ${IMG} .

.PHONY: buildah-push
buildah-push: buildah-build
	sudo buildah push --authfile=~/.docker/config.json ${IMG}

all: build
.PHONY: all

# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	targets/openshift/bindata.mk \
	targets/openshift/crd-schema-gen.mk \
	targets/openshift/deps.mk \
)

# adapted from https://github.com/openshift/build-machinery-go/blob/master/make/targets/openshift/images.mk

# IMAGE_BUILD_EXTRA_FLAGS lets you add extra flags for imagebuilder
# e.g. to mount secrets and repo information into base image like:
# make images IMAGE_BUILD_EXTRA_FLAGS='-mount ~/projects/origin-repos/4.2/:/etc/yum.repos.d/'
IMAGE_BUILD_EXTRA_FLAGS ?= --no-cache

ifeq ($(shell command -v podman 2> /dev/null),)
    DOCKER_CMD=docker
else
    DOCKER_CMD=podman
endif

# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context
define build-image-internal
image-$(1):
	$(strip \
		$(DOCKER_CMD) build \
		-t $(2) \
		-f $(3) \
		$(IMAGE_BUILD_EXTRA_FLAGS) \
		$(4) \
	)
.PHONY: image-$(1)

images: image-$(1)
.PHONY: images
endef

define build-image
$(eval $(call build-image-internal,$(1),$(2),$(3),$(4)))
endef

# Set crd-schema-gen variables
CONTROLLER_GEN_VERSION := v0.2.5
CRD_APIS :=./pkg/apis/cloudcredential/v1

# Exclude e2e tests from unit testing
GO_TEST_PACKAGES :=./pkg/... ./cmd/...

IMAGE_REGISTRY ?=registry.ci.openshift.org
IMAGE_REPO ?=ocp/4.5
IMAGE_TAG ?=cloud-credential-operator


# This will call a macro called "add-bindata" which will generate bindata specific targets based on the parameters:
# $0 - macro name
# $1 - target suffix
# $2 - input dirs
# $3 - prefix
# $4 - pkg
# $5 - output
# It will generate targets {update,verify}-bindata-$(1) logically grouping them in unsuffixed versions of these targets
# and also hooked into {update,verify}-generated for broader integration.
$(call add-bindata,bootstrap,./bindata/bootstrap/...,bindata,bootstrap,pkg/assets/bootstrap/bindata.go)
$(call add-bindata,v4.1.0,./bindata/v4.1.0/...,bindata,v410_00_assets,pkg/assets/v410_00_assets/bindata.go)

# This will call a macro called "build-image" which will generate image specific targets based on the parameters:
# $0 - macro name
# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context directory for image build
$(call build-image,ocp-cloud-credential-operator,$(IMAGE_REGISTRY)/$(IMAGE_REPO):$(IMAGE_TAG), ./Dockerfile,.)

# This will call a macro called "add-crd-gen" will will generate crd manifests based on the parameters:
# $1 - target name
# $2 - apis
# $3 - manifests
# $4 - output
$(call add-crd-gen,cloudcredential-manifests,./pkg/apis/cloudcredential/v1,./manifests,./manifests)
$(call add-crd-gen,cloudcredential-bindata,./pkg/apis/cloudcredential/v1,./bindata/bootstrap,./bindata/bootstrap)

update: update-vendored-crds update-codegen update-bindata generate
.PHONY: update

generate:
	go generate ${GO_TEST_PACKAGES}
.PHONY: generate

update-vendored-crds:
	# copy config CRD from openshift/api
	cp vendor/github.com/openshift/api/operator/v1/zz_generated.crd-manifests/0000_40_cloud-credential_00_cloudcredentials.crd.yaml ./manifests/00-config-custresdef.yaml
	# ...and into where we generate bindata from
	cp vendor/github.com/openshift/api/operator/v1/zz_generated.crd-manifests/0000_40_cloud-credential_00_cloudcredentials.crd.yaml ./bindata/bootstrap/cloudcredential_v1_operator_config_custresdef.yaml
.PHONY: update-vendored-crds

update-codegen: update-codegen-crds
	./hack/update-codegen.sh
.PHONY: update-codegen

verify: verify-vendored-crds verify-codegen verify-bindata

verify-codegen-crds: update-codegen-crds update-vendored-crds
	git diff --exit-code

verify-codegen: verify-codegen-crds
	./hack/verify-codegen.sh
.PHONY: verify-codegen

verify-vendored-crds:
	diff vendor/github.com/openshift/api/operator/v1/zz_generated.crd-manifests/0000_40_cloud-credential_00_cloudcredentials.crd.yaml ./manifests/00-config-custresdef.yaml
	diff vendor/github.com/openshift/api/operator/v1/zz_generated.crd-manifests/0000_40_cloud-credential_00_cloudcredentials.crd.yaml ./bindata/bootstrap/cloudcredential_v1_operator_config_custresdef.yaml
.PHONY: verify-vendored-crds

clean:
	$(RM) ./cloud-credential-operator
.PHONY: clean

# Run against the configured cluster in ~/.kube/config
run: build
	./cloud-credential-operator operator --log-level=debug

# Install CRDs into a cluster
install: update-codegen
	kubectl apply -f manifests/0000_03_cloud-credential-operator_01_crd.yaml

# TODO targets for backward compatibility while we make the shift in CI
test-no-gen: test
.PHONY: test-no-gen

test-e2e-sts:
	go test -mod=vendor -race -tags e2e ./test/e2e/aws/sts/...
.PHONY: test-e2e-sts

test-e2e-azident:
	go test -mod=vendor -race -tags e2e ./test/e2e/azure/azident/...
.PHONY: test-e2e-azident

vet: verify-govet
.PHONY: vet

build-no-gen: build
.PHONY: build-no-gen

coverage:
	hack/codecov.sh
.PHONY: coverage

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

# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context
define build-image-internal
image-$(1):
	$(strip \
		podman build \
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

update: update-codegen update-bindata generate
.PHONY: update

generate:
	go generate ${GO_TEST_PACKAGES}
.PHONY: generate

# TODO: consider migrating to the openshift/api codegen tool
# https://github.com/openshift/api/tree/master/tools/codegen
#
# update-codegen-crds-cloudcredential-manifests and
# update-codegen-crds-cloudcredential-bindata make targets override
# "update-codegen-crds-*" targets created by the above invocations of
# "add-crd-gen".
#
# We copy the cloud credential operator config CRD from the
# openshift/api repository (via the vendor dir) and since
# openshift/api now utilizes a different codegen utility than
# build-machinery-go, running the schemapatch code generator against
# the copied manifest results in a different formatting. This results
# in a diff which causes our verify target to fail so we ensure the
# copied manifests remain unchanged by copying the CRDs once more
# after generating CRDs as a workaround.
update-codegen-crds-cloudcredential-manifests: ensure-controller-gen ensure-yq ensure-yaml-patch
	$(run-crd-gen,./pkg/apis/cloudcredential/v1,./manifests)
	$(MAKE) update-vendored-crds

update-codegen-crds-cloudcredential-bindata: ensure-controller-gen ensure-yq ensure-yaml-patch
	$(run-crd-gen,./pkg/apis/cloudcredential/v1,./bindata/bootstrap)
	$(MAKE) update-vendored-crds

update-vendored-crds:
	# copy config CRD from openshift/api
	cp vendor/github.com/openshift/api/operator/v1/0000_40_cloud-credential-operator_00_config.crd.yaml ./manifests/00-config-custresdef.yaml
	# ...and into where we generate bindata from
	cp vendor/github.com/openshift/api/operator/v1/0000_40_cloud-credential-operator_00_config.crd.yaml ./bindata/bootstrap/cloudcredential_v1_operator_config_custresdef.yaml
.PHONY: update-vendored-crds

update-codegen: update-codegen-crds
	./hack/update-codegen.sh
.PHONY: update-codegen

verify: verify-vendored-crds verify-codegen verify-bindata

verify-codegen: verify-codegen-crds
	./hack/verify-codegen.sh
.PHONY: verify-codegen

verify-vendored-crds:
	diff vendor/github.com/openshift/api/operator/v1/0000_40_cloud-credential-operator_00_config.crd.yaml ./manifests/00-config-custresdef.yaml
	diff vendor/github.com/openshift/api/operator/v1/0000_40_cloud-credential-operator_00_config.crd.yaml ./bindata/bootstrap/cloudcredential_v1_operator_config_custresdef.yaml
.PHONY: verify-vendored-crds

clean:
	$(RM) ./cloud-credential-operator
.PHONY: clean

# Run against the configured cluster in ~/.kube/config
run: build
	./cloud-credential-operator operator --log-level=debug

# Install CRDs into a cluster
install: update-codegen
	kubectl apply -f manifests/00-crd.yaml

# TODO targets for backward compatibility while we make the shift in CI
test-no-gen: test
.PHONY: test-no-gen

test-e2e-sts:
	go test -race -tags e2e ./test/e2e/aws/sts/...
.PHONY: test-e2e-sts

vet: verify-govet
.PHONY: vet

build-no-gen: build
.PHONY: build-no-gen

coverage:
	hack/codecov.sh
.PHONY: coverage

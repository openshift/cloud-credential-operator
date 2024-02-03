#!/bin/bash -e

set -x

verify="${VERIFY:-}"
SED_CMD=${SED_CMD:-$(if [[ $(uname) == Darwin ]]; then echo gsed; else echo sed; fi)}
echo "Using $SED_CMD as the sed command"

# set the passed in directory as a usable GOPATH
# that deepcopy-gen can operate in
ensure-temp-gopath() {
	fake_gopath=$1

	# set up symlink pointing to our repo root
	fake_repopath=$fake_gopath/src/github.com/openshift/cloud-credential-operator
	mkdir -p "$(dirname "${fake_repopath}")"
	ln -s "$REPO_FULL_PATH" "${fake_repopath}"
}

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
REPO_FULL_PATH=$(realpath ${SCRIPT_ROOT})
cd ${REPO_FULL_PATH}

CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../../../k8s.io/code-generator)}

# HACK 1: For some reason this script is not executable.
${SED_CMD} -i 's,^exec \(".*/generate-internal-groups.sh"\),bash \1,g' ${CODEGEN_PKG}/generate-groups.sh
# HACK 2: For verification we need to ensure we don't remove files
if test -n "$verify"; then
  ${SED_CMD} -i 's/xargs \-0 rm \-f/xargs -0 echo ""/g' ${CODEGEN_PKG}/generate-internal-groups.sh
fi
# ...but we have to put it back, or `verify` will puke.
trap "git checkout ${CODEGEN_PKG}/generate-internal-groups.sh ${CODEGEN_PKG}/generate-groups.sh" EXIT


valid_gopath=$(realpath $REPO_FULL_PATH/../../../..)
if [[ "$(realpath ${valid_gopath}/src/github.com/openshift/cloud-credential-operator)" == "${REPO_FULL_PATH}" ]]; then
	temp_gopath=${valid_gopath}
else
	TMP_DIR=$(mktemp -d -t cloud-credential-operator-codegen.XXXX)
	function finish {
		chmod -R +w ${TMP_DIR}
		# ok b/c we will symlink to the original repo
		rm -r ${TMP_DIR}
	}
	trap finish EXIT

	ensure-temp-gopath ${TMP_DIR}

	temp_gopath=${TMP_DIR}
fi

GOPATH="${temp_gopath}" GOFLAGS="" bash ${CODEGEN_PKG}/generate-groups.sh "deepcopy" \
	github.com/openshift/cloud-credential-operator/pkg/client \
	github.com/openshift/cloud-credential-operator/pkg/apis \
	"cloudcredential:v1" \
	--go-header-file ${REPO_FULL_PATH}/hack/boilerplate.go.txt \
	${verify}

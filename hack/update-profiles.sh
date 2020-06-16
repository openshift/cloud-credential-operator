#!/usr/bin/env bash

set -e

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
FULL_REPO_ROOT=$(realpath ${SCRIPT_ROOT})

YAML_PATCH_BIN=${SCRIPT_ROOT}/_output/tools/bin/yaml-patch
JSON_PATCH_BIN=${SCRIPT_ROOT}/_output/tools/bin/json-patch

TMP_DIR=$(mktemp -d)
function finish {
	rm -r ${TMP_DIR}
}
trap finish EXIT

function ensure_yaml_patch {
	YAML_PATCH_SHA="731e2d3a88bbcdea2c5852bbe97795b7d4c32711b44c4db2260af63cce03b69e"
	
	if [[ -f ${YAML_PATCH_BIN} ]]; then
		# verify checksum else update the binary
		echo "${YAML_PATCH_SHA} ${YAML_PATCH_BIN}" | sha256sum --check &>/dev/null || curl --silent --fail --location https://github.com/krishicks/yaml-patch/releases/download/v0.0.10/yaml_patch_linux --output ${YAML_PATCH_BIN}
		echo "${YAML_PATCH_SHA} ${YAML_PATCH_BIN}" | sha256sum --check >/dev/null && echo "Verified checksum for ${YAML_PATCH_BIN}"
	else
		curl --silent --fail --location https://github.com/krishicks/yaml-patch/releases/download/v0.0.10/yaml_patch_linux --output ${YAML_PATCH_BIN}
		echo "${YAML_PATCH_SHA} ${YAML_PATCH_BIN}" | sha256sum --check
	fi
	
	chmod +x ${SCRIPT_ROOT}/_output/tools/bin/yaml-patch
}

function ensure_json_patch {
	JSON_PATCH_TARBALL_CHECKSUM="64ee97c8bca94629effb0fccfd02376764764ca39d4fda74f59aa0679aaf96e2"
	JSON_PATCH_VERSION="v5.0.0"
	JSON_PATCH_TARBALL="${JSON_PATCH_VERSION}.tar.gz"
	
	if [[ ! -f ${JSON_PATCH_BIN} ]]; then
		curl --silent --fail --location https://github.com/evanphx/json-patch/archive/${JSON_PATCH_TARBALL} --output ${TMP_DIR}/${JSON_PATCH_TARBALL}
		# ensure we got the expected file
		echo "${JSON_PATCH_TARBALL_CHECKSUM} ${TMP_DIR}/${JSON_PATCH_TARBALL}" | sha256sum --check

		tar -xf ${TMP_DIR}/${JSON_PATCH_TARBALL} --directory ${TMP_DIR}

		pushd ${TMP_DIR}/json-patch-5.0.0
		go build -o ${FULL_REPO_ROOT}/${JSON_PATCH_BIN} ./cmd/json-patch
		popd
	fi
}

# $1 is the path to the source file
# $2 is the path to the patch file
# $3 is the path of the file to generate
function generate_profile_yaml {
	cat $1 | ${YAML_PATCH_BIN} --ops-file $2 > $3
}
# $1 is the path to the source file
# $2 is the path to the patch file
# $3 is the path of the file to generate
function generate_profile_json {
	cat $1 | ${JSON_PATCH_BIN} --patch-file $2 > $3
}

# $1 is the profile to generate for
# $2 is the path to the patch file
function apply_patch {
	echo "Processing $(basename $2)"
	PROFILE_NAME=$1
	PATCH_FILE=$2

	# Strip out trailing '.patch' and leading directories
	FILE_TO_PATCH=$(basename $2 | sed -e 's/\.patch//g')
	FILE_TO_PATCH_FULL_PATH="${FULL_REPO_ROOT}/manifests/${FILE_TO_PATCH}"

	# Anything that doesn't end in .json.patch is assumed to be yaml
	SOURCE_FILE_TYPE=$(echo $FILE_TO_PATCH | sed -e 's/.*\.//g')

	# Convert from 03-deployment.yaml to 03-deployment-$PROFILE.yaml
	DESTINATION_FILE_NAME=$(basename $FILE_TO_PATCH | sed -e "s/\.$SOURCE_FILE_TYPE/-${PROFILE_NAME}.${SOURCE_FILE_TYPE}/g")
	DESTINATION_FILE_FULL_PATH="${FULL_REPO_ROOT}/manifests/${DESTINATION_FILE_NAME}"

	if [[ "${VERIFY}" == "--verify" ]]; then
		ORIG_CHECKSUM=$(md5sum $DESTINATION_FILE_FULL_PATH 2>/dev/null || echo "NEWFILE")
		if [[ "${ORIG_CHECKSUM}" != "NEWFILE" ]]; then
			ORIG_CHECKSUM=$(echo ${ORIG_CHECKSUM} | cut -c 32)
		fi

		DESTINATION_FILE_FULL_PATH="${TMP_DIR}/${DESTINATION_FILE_NAME}"
	fi

	if [[ "$SOURCE_FILE_TYPE" == "json" ]]; then
		generate_profile_json $FILE_TO_PATCH_FULL_PATH $PATCH_FILE $DESTINATION_FILE_FULL_PATH
	else
		generate_profile_yaml $FILE_TO_PATCH_FULL_PATH $PATCH_FILE $DESTINATION_FILE_FULL_PATH
	fi

	if [[ "${VERIFY}" == "--verify" ]]; then
		if [[ "${ORIG_CHECKSUM}" == "NEWFILE" ]]; then
			echo "Need to generate new profile files for $DESTINATION_FILE_NAME"
			exit 1
		fi

		NEW_CHECKSUM=$(md5sum ${DESTINATION_FILE_FULL_PATH} | cut -c 32)
		if [[ "${NEW_CHECKSUM}" != "${ORIG_CHECKSUM}" ]]; then
			echo "Changes to ${DESTINATION_FILE_NAME} detected, regenerate profiles"
			exit 1
		fi
	fi
}

function generate_profiles {
	if [[ -d ${FULL_REPO_ROOT}/manifests/profile-patches ]]; then
		for dir in $(ls -d ${FULL_REPO_ROOT}/manifests/profile-patches/*); do
			PROFILE_NAME=$(basename $dir)
			echo "Generating for profile $PROFILE_NAME"
			for file in $(find $dir -type f); do
				apply_patch $PROFILE_NAME $file
			done
		done
	fi
}

VERIFY=${1}
if [[ "${VERIFY}" != "" && "${VERIFY}" != "--verify" ]]; then
	echo "Unknown param: '${VERIFY}'"
	exit 1
fi

ensure_json_patch
ensure_yaml_patch

generate_profiles


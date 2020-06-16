#!/usr/bin/env bash

set -e

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..

${SCRIPT_ROOT}/hack/update-profiles.sh --verify

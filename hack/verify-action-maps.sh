#!/usr/bin/env bash
#
# Extracts AWS CredentialsRequest manifests from an OpenShift release payload
# and compares the IAM actions they declare against the hardcoded classification
# maps in pkg/aws/utils.go.
#
# Usage:
#   ./hack/verify-action-maps.sh [RELEASE_IMAGE]
#
# If RELEASE_IMAGE is omitted, the script pulls the latest 4.21.0 nightly.
# Set REGISTRY_AUTH_FILE to point to a pull secret (default: $HOME/.pull-secret).
# Requires: oc, jq, yq, curl

set -euo pipefail

AUTHFILE="${REGISTRY_AUTH_FILE:-$HOME/.pull-secret}"
RELEASE_IMAGE="${1:-}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

for cmd in oc jq yq curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd not found in PATH" >&2
    exit 1
  fi
done

# Resolve release image if not provided
if [[ -z "$RELEASE_IMAGE" ]]; then
  echo "No release image specified, resolving "
  RELEASE_IMAGE=$(curl -sfL 'https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestream/4.21.0-0.nightly/latest' | jq -r '.pullSpec // empty') || true
  if [[ -z "$RELEASE_IMAGE" ]]; then
    echo "ERROR: could not resolve latest nightly (curl or jq failed). Pass a release image explicitly." >&2
    exit 1
  fi
  echo "Using: $RELEASE_IMAGE"
fi

# Extract CredentialsRequest manifests from the payload
echo "Extracting CredentialsRequests from payload..."
AUTH_ARGS=()
if [[ -f "$AUTHFILE" ]]; then
  AUTH_ARGS=(-a "$AUTHFILE")
fi
if ! oc adm release extract \
  "${AUTH_ARGS[@]}" \
  --credentials-requests \
  --to="$TMPDIR/credrequests" \
  "$RELEASE_IMAGE" 2>/dev/null; then
  echo "ERROR: oc adm release extract failed for $RELEASE_IMAGE" >&2
  [[ ! -f "$AUTHFILE" ]] && echo "  No authfile found at $AUTHFILE — set REGISTRY_AUTH_FILE or place a pull secret there" >&2
  exit 1
fi

# Filter to AWS-only CredentialsRequests and extract actions
echo "Parsing AWS actions from CredentialsRequests..."
PAYLOAD_ACTIONS="$TMPDIR/payload-actions.txt"
: > "$PAYLOAD_ACTIONS"

for f in "$TMPDIR"/credrequests/*.yaml; do
  [[ -f "$f" ]] || continue

  # Check if this is an AWS CredentialsRequest (has AWSProviderSpec)
  if ! grep -q 'AWSProviderSpec' "$f" 2>/dev/null; then
    continue
  fi

  CR_NAME=$(grep -m1 'name:' "$f" | awk '{print $2}')

  # Extract action strings using yq (handles YAML reliably)
  if ! yq '(.spec.providerSpec.value // .spec.providerSpec).statementEntries[].action[]' "$f" >> "$PAYLOAD_ACTIONS" 2>/dev/null; then
    echo "WARNING: yq parsing failed for $f (CR: ${CR_NAME:-unknown}), falling back to grep" >&2
    grep -oP '^\s*- \K\S+:\S+' "$f" >> "$PAYLOAD_ACTIONS" 2>/dev/null || true
  fi
done

# Filter to AWS IAM actions only (service:Action pattern, e.g. ec2:DescribeInstances).
# This excludes IBM Cloud CRN strings (crn:v1:bluemix:...) and other non-AWS entries.
grep -P '^[a-z][a-z0-9-]+:[A-Z]' "$PAYLOAD_ACTIONS" > "$PAYLOAD_ACTIONS.filtered" 2>/dev/null || true
mv "$PAYLOAD_ACTIONS.filtered" "$PAYLOAD_ACTIONS"

# Deduplicate and sort
sort -u "$PAYLOAD_ACTIONS" -o "$PAYLOAD_ACTIONS"
PAYLOAD_COUNT=$(wc -l < "$PAYLOAD_ACTIONS")
if [[ "$PAYLOAD_COUNT" -eq 0 ]]; then
  echo "ERROR: no AWS actions found in payload CredentialsRequests — extraction may have failed" >&2
  exit 1
fi
echo "Found $PAYLOAD_COUNT unique AWS actions in payload CredentialsRequests"

# Extract actions from the scoped+unscoped maps in utils.go
UTILS_GO="pkg/aws/utils.go"
if [[ ! -f "$UTILS_GO" ]]; then
  echo "ERROR: $UTILS_GO not found (run from repo root)" >&2
  exit 1
fi

CODE_ACTIONS="$TMPDIR/code-actions.txt"
grep -oP '"\K[a-zA-Z0-9]+:[a-zA-Z0-9*]+(?="\s*:)' "$UTILS_GO" | sort -u > "$CODE_ACTIONS"
CODE_COUNT=$(wc -l < "$CODE_ACTIONS")
if [[ "$CODE_COUNT" -eq 0 ]]; then
  echo "ERROR: no actions extracted from $UTILS_GO — grep pattern may need updating" >&2
  exit 1
fi
echo "Found $CODE_COUNT unique AWS actions in $UTILS_GO maps"

# Extract actions from the test list in utils_test.go
UTILS_TEST="pkg/aws/utils_test.go"
TEST_ACTIONS="$TMPDIR/test-actions.txt"
if [[ -f "$UTILS_TEST" ]]; then
  sed -n '/^var payloadAWSActions/,/^func /p' "$UTILS_TEST" | grep -oP '"\K[a-zA-Z0-9]+:[a-zA-Z0-9*]+(?=")' | sort -u > "$TEST_ACTIONS"
  TEST_COUNT=$(wc -l < "$TEST_ACTIONS")
  echo "Found $TEST_COUNT unique AWS actions in $UTILS_TEST payloadAWSActions"
else
  : > "$TEST_ACTIONS"
  echo "WARNING: $UTILS_TEST not found, skipping test list comparison"
fi

echo ""

# Compare: actions in payload but missing from code maps
MISSING_FROM_CODE="$TMPDIR/missing-from-code.txt"
comm -23 "$PAYLOAD_ACTIONS" "$CODE_ACTIONS" > "$MISSING_FROM_CODE"

# Compare: actions in payload but missing from test list
MISSING_FROM_TEST="$TMPDIR/missing-from-test.txt"
comm -23 "$PAYLOAD_ACTIONS" "$TEST_ACTIONS" > "$MISSING_FROM_TEST"

# Compare: actions in code but not in payload (stale?)
STALE_IN_CODE="$TMPDIR/stale-in-code.txt"
comm -23 "$CODE_ACTIONS" "$PAYLOAD_ACTIONS" > "$STALE_IN_CODE"

# Report
EXIT=0

if [[ -s "$MISSING_FROM_CODE" ]]; then
  echo "FAIL: Actions in payload but MISSING from utils.go maps:"
  sed 's/^/  /' "$MISSING_FROM_CODE"
  echo ""
  echo "  Add these to infraResourceTagScopedActions or infraResourceTagUnscopedActions"
  echo "  in $UTILS_GO."
  echo ""
  EXIT=1
fi

if [[ -s "$MISSING_FROM_TEST" ]]; then
  echo "FAIL: Actions in payload but MISSING from utils_test.go payloadAWSActions:"
  sed 's/^/  /' "$MISSING_FROM_TEST"
  echo ""
  echo "  Add these to payloadAWSActions in $UTILS_TEST."
  echo ""
  EXIT=1
fi

if [[ -s "$STALE_IN_CODE" ]]; then
  echo "INFO: Actions in utils.go maps but NOT in current payload (may be stale or defensive):"
  sed 's/^/  /' "$STALE_IN_CODE"
  echo ""
fi

if [[ $EXIT -eq 0 ]]; then
  echo "OK: All $PAYLOAD_COUNT payload actions are covered in both utils.go and utils_test.go"
fi

exit $EXIT

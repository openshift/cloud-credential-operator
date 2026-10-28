# How to rotate the OIDC bound service account signer key

## Overview
When OpenShift is configured to use temporary credentials (AZWI, STS, WIF) to authenticate with the cloud platform api, special care must be taken when rotating the bound service account signer keys in order to reduce authentication failures. This can be accomplished by adding the new public key to the existing issuer file immediately after the cluster generates it. Once the cluster has fully updated to the new key all other keys can be removed.

This page describes the current manual procedure. The provider-neutral workflow is defined in the
[`ccoctl rotate-signing-key` command contract](ccoctl-rotate-signing-key.md), but its provider
adapters and commands are not registered yet.

This manual procedure assumes an exclusive maintenance window in which no other user, automation,
or controller deletes `next-bound-service-account-signing-key`. Stop if that exclusivity cannot be
guaranteed: the cumulative public signer ConfigMap does not identify which Secret generation
produced an entry, so concurrent rotations cannot be disambiguated safely by this procedure.

The provider upload examples below are legacy unconditional writes. Ensure exclusive publisher
access, verify that the remote JWKS still equals the expected predecessor immediately before each
upload, and read it back to compare with the exact uploaded file afterward. Stop if either
comparison fails or if the provider cannot be protected from another writer. The provider adapters
described by the command contract must replace this operational assumption with conditional writes
and exact readback.

## Process

1. Configure environment variables

    This process depends on the following environment variables being defined. You may need to specify some of the values if the corresponding resource names are not equal to the values derived from the cluster name.

    Common
    ```bash
    set -euo pipefail
    TEMPDIR="$(mktemp -d)"
    ```

    AWS
    ```bash
    INFRA_ID=$(oc get infrastructures cluster -o jsonpath='{.status.infrastructureName}')

    CLUSTER_NAME=${INFRA_ID%-*}

    AWS_BUCKET=${CLUSTER_NAME}-oidc
    ```

    Azure
    ```bash
    CURRENT_ISSUER=$(oc get authentication cluster -o jsonpath='{.spec.serviceAccountIssuer}')

    AZURE_STORAGE_ACCOUNT=$(echo ${CURRENT_ISSUER} | cut -d "/" -f3 | cut -d "." -f1)

    AZURE_STORAGE_CONTAINER=$(echo ${CURRENT_ISSUER} | cut -d "/" -f4)
    ```

    GCP
    ```bash
    CURRENT_ISSUER=$(oc get authentication cluster -o jsonpath='{.spec.serviceAccountIssuer}')

    GCP_BUCKET=$(echo ${CURRENT_ISSUER} | cut -d "/" -f4)

    CLUSTER_NAME=${GCP_BUCKET%-*}
    ```

1. Confirm that your cluster is in a stable state.

    ```bash
    oc adm wait-for-stable-cluster --minimum-stable-period=5s
    ```

1. Download and inspect the current keys.json from the cloud provider.

    Save this recovery artifact before triggering rotation. Confirm that it came from the intended
    issuer and contains at least one key.

    AWS
    ```bash
    aws s3api get-object --bucket "${AWS_BUCKET}" --key keys.json "${TEMPDIR}/jwks.current.download.json"
    ```

    Azure
    ```bash
    az storage blob download --container-name "${AZURE_STORAGE_CONTAINER}" --account-name "${AZURE_STORAGE_ACCOUNT}" --name 'openid/v1/jwks' -f "${TEMPDIR}/jwks.current.download.json"
    ```

    GCP public-bucket
    ```bash
    gcloud storage cp "gs://${GCP_BUCKET}/keys.json" "${TEMPDIR}/jwks.current.download.json"
    ```

    GCP pool-jwk-file
    ```bash
    gcloud iam workload-identity-pools providers describe --format json --location global --workload-identity-pool "${CLUSTER_NAME}" "${CLUSTER_NAME}" \
      | jq -er '.oidc.jwksJson' > "${TEMPDIR}/jwks.current.download.json"
    ```

    Perform this basic structural check before continuing. The forthcoming command also performs
    strict RSA key, key ID, algorithm, purpose, duplicate, and signer-baseline validation that is
    not reproduced by this legacy shell procedure.

    ```bash
    jq -e '
      def supported_key:
        type == "object"
        and ((keys_unsorted - ["alg", "e", "kid", "kty", "n", "use", "x5c", "x5t", "x5t#S256", "x5u"]) | length) == 0
        and .kty == "RSA"
        and (.kid | type == "string" and length > 0)
        and (.n | type == "string" and length > 0)
        and (.e | type == "string" and length > 0)
        and ((.alg // "RS256") == "RS256")
        and ((.use // "sig") == "sig");
      type == "object"
      and ((keys_unsorted - ["keys"]) | length) == 0
      and (.keys | type == "array" and length > 0)
      and all(.keys[]; supported_key)
      and (([.keys[].kid] | length) == ([.keys[].kid] | unique | length))
    ' "${TEMPDIR}/jwks.current.download.json" > /dev/null

    mv "${TEMPDIR}/jwks.current.download.json" "${TEMPDIR}/jwks.current.json"
    ```

1. Trigger the kube-apiserver to create a new bound service account signing key.

    Deleting the `next-bound-service-account-signing-key` Secret asks the operator to generate a
    replacement. The operator first appends the replacement public key to the cumulative signer
    ConfigMap and rolls that verifier state through kube-apiserver revisions before it promotes the
    replacement signer. In order to reduce the risk of authentication failures, it is important to
    complete all steps up to and including ***Upload the combined keys file*** as quickly as
    possible.

    WARNING: The remaining steps may cause downtime for the cluster.

    Immediately before triggering rotation, save the public signer set so that the replacement can
    be identified without reading any Secret data.

    ```bash
    oc -n openshift-kube-apiserver get configmap/bound-sa-token-signing-certs -o json \
      > "${TEMPDIR}/bound-sa-token-signing-certs.before.json.tmp"

    jq -e 'type == "object"' "${TEMPDIR}/bound-sa-token-signing-certs.before.json.tmp" > /dev/null
    mv "${TEMPDIR}/bound-sa-token-signing-certs.before.json.tmp" \
      "${TEMPDIR}/bound-sa-token-signing-certs.before.json"
    ```

    ```bash
    oc -n openshift-kube-apiserver-operator delete secrets/next-bound-service-account-signing-key
    ```

1. Download the new bound service account signing key public key

    Read the public-only signer ConfigMap and select the one public key that was not present in the
    pre-rotation snapshot. Do not select a fixed or highest-numbered `service-account-NNN.pub`
    entry: the ConfigMap is cumulative and its entry names do not identify the active or next key.

    ```bash
    oc -n openshift-kube-apiserver get configmap/bound-sa-token-signing-certs -o json \
      > "${TEMPDIR}/bound-sa-token-signing-certs.after.json.tmp"

    jq -e 'type == "object"' "${TEMPDIR}/bound-sa-token-signing-certs.after.json.tmp" > /dev/null
    mv "${TEMPDIR}/bound-sa-token-signing-certs.after.json.tmp" \
      "${TEMPDIR}/bound-sa-token-signing-certs.after.json"

    jq -enr \
      --slurpfile before "${TEMPDIR}/bound-sa-token-signing-certs.before.json" \
      --slurpfile after "${TEMPDIR}/bound-sa-token-signing-certs.after.json" '
        def signer_map:
          (.data // {}) as $data
          | if ($data | type) != "object" then
              error("signer ConfigMap data is not an object")
            elif ([$data | keys[]
                   | select(test("^service-account-[0-9]+\\.pub$") | not)] | length) != 0 then
              error("signer ConfigMap contains an unexpected data entry")
            elif ([$data[] | select(type != "string")] | length) != 0 then
              error("signer ConfigMap contains a non-string value")
            else $data
            end;
        ($before[0] | signer_map) as $old
        | ($after[0] | signer_map) as $new
        | [$old | to_entries[] | . as $entry
           | select($new[$entry.key] != $entry.value)] as $changed
        | [$new | to_entries[] | . as $entry
           | select(($old | has($entry.key)) | not)] as $added
        | if ($before | length) != 1 or ($after | length) != 1 then
            error("expected exactly one JSON object in each signer snapshot")
          elif (($before[0].metadata.uid // "") | length) == 0
               or (($after[0].metadata.uid // "") | length) == 0 then
            error("signer ConfigMap UID is missing")
          elif (($before[0].metadata.resourceVersion // "") | length) == 0
               or (($after[0].metadata.resourceVersion // "") | length) == 0 then
            error("signer ConfigMap resource version is missing")
          elif $before[0].metadata.uid != $after[0].metadata.uid then
            error("signer ConfigMap was replaced")
          elif $before[0].metadata.resourceVersion == $after[0].metadata.resourceVersion then
            error("signer ConfigMap has not changed")
          elif ($old | length) == 0 then
            error("pre-rotation signer set is empty")
          elif ($changed | length) != 0 then
            error("a pre-rotation signer entry changed or disappeared")
          elif ($added | length) != 1 then
            error("expected exactly one new signer public key, found \($added | length)")
          elif ([$old[]] | index($added[0].value)) != null then
            error("new signer entry repeats a pre-rotation public key")
          else $added[0].value
          end
      ' > "${TEMPDIR}/serviceaccount-signer.public.tmp"

    test -s "${TEMPDIR}/serviceaccount-signer.public.tmp"
    mv "${TEMPDIR}/serviceaccount-signer.public.tmp" \
      "${TEMPDIR}/serviceaccount-signer.public"
    ```

    If no new signer is found, wait for the operator to update the ConfigMap and repeat this read.
    If an existing entry changed or disappeared, the ConfigMap was replaced, or more than one new
    signer is found, stop: another rotation may be in progress and the replacement is ambiguous.

1. Create a keys.json using the new public key

    Use the public key downloaded above to create a new keys.json file. We do this by taking advantage of the --dry-run option in order to only output files on disk, including the new keys.json file. The actual values of many of the parameters is not important as they do not affect the generation of a new key.

    AWS
    ```bash
    ccoctl aws create-identity-provider --dry-run --output-dir ${TEMPDIR} --name fake --region us-east-1

    cp ${TEMPDIR}/03-keys.json ${TEMPDIR}/jwks.new.json
    ```

    Azure - Use aws subcommand until azure --dry-run is functional.
    ```bash
    ccoctl aws create-identity-provider --dry-run --output-dir ${TEMPDIR} --name fake --region us-east-1

    cp ${TEMPDIR}/03-keys.json ${TEMPDIR}/jwks.new.json
    ```

    GCP
    ```bash
    ccoctl gcp create-workload-identity-provider --dry-run --output-dir=${TEMPDIR} --name fake --project fake --workload-identity-pool fake

    cp ${TEMPDIR}/04-keys.json ${TEMPDIR}/jwks.new.json
    ```

1. Combine the current and new keys

    Combine the key(s) downloaded from the cloud provider with the new key. The resulting file will enable authentication for both the old and new keys during the transition.

    ```bash
    jq -e -s '
      .[0] as $current
      | .[1] as $replacement
      | ($current.keys | map(.kid)) as $current_ids
      | if ($replacement.keys | type) != "array" or ($replacement.keys | length) != 1 then
          error("replacement JWKS must contain exactly one key")
        elif ($current_ids | index($replacement.keys[0].kid)) != null then
          error("replacement key ID is already present in the current JWKS")
        else
          {keys: ($current.keys + $replacement.keys)}
        end
    ' "${TEMPDIR}/jwks.current.json" "${TEMPDIR}/jwks.new.json" \
      > "${TEMPDIR}/jwks.combined.json.tmp"

    mv "${TEMPDIR}/jwks.combined.json.tmp" "${TEMPDIR}/jwks.combined.json"
    ```

1. Upload the combined keys file

    Upload the combined keys file to the cloud provider. Both keys are now valid for authenticating to the cloud platform api.

    AWS
    ```bash
    aws s3api put-object --bucket ${AWS_BUCKET} --tagging "openshift.io/cloud-credential-operator/${CLUSTER_NAME}=owned" --key keys.json --body ${TEMPDIR}/jwks.combined.json
    ```

    Azure
    ```bash
    az storage blob upload --overwrite --account-name ${AZURE_STORAGE_ACCOUNT}  --container-name ${AZURE_STORAGE_CONTAINER} --name 'openid/v1/jwks' -f ${TEMPDIR}/jwks.combined.json
    ```

    GCP public-bucket
    ```bash
    gcloud storage cp ${TEMPDIR}/jwks.combined.json gs://${GCP_BUCKET}/keys.json
    ```

    GCP pool-jwk-file
    ```bash
    gcloud iam workload-identity-pools providers update-oidc ${CLUSTER_NAME} --location=global --workload-identity-pool=${CLUSTER_NAME} --jwk-json-path=${TEMPDIR}/jwks.combined.json
    ```

1. Wait for kube-apiserver to update to the new key

    Wait for the kube-apiserver pods to be using the new key before proceeding. The kube-apiserver operator enters the progressing state until all of the pods are cycled and using the new key.

    ```bash
    oc adm wait-for-stable-cluster
    ```

1. Reboot all of the nodes

    After the kube-apiserver is using the new key, reboot all of the config machine pools. This ensures all of the pods on the cluster are using the new key while maintaining uptime on services configured to be highly-available.

    WARNING: The following step may cause downtime for any services which are not configured for HA across multiple nodes.

    ```bash
    oc adm reboot-machine-config-pool mcp/worker mcp/master

    oc adm wait-for-node-reboot nodes --all

    oc adm wait-for-stable-cluster
    ```

1. Upload the new keys file

    Now that the cluster is fully using the new key, remove all other keys from the keys.json file on the cloud provider. The new key is now the only key valid for authenticating to the cloud platform api.

    AWS
    ```bash
    aws s3api put-object --bucket ${AWS_BUCKET} --tagging "openshift.io/cloud-credential-operator/${CLUSTER_NAME}=owned" --key keys.json --body ${TEMPDIR}/jwks.new.json
    ```

    Azure
    ```bash
    az storage blob upload --overwrite --account-name ${AZURE_STORAGE_ACCOUNT} --container-name ${AZURE_STORAGE_CONTAINER} --name 'openid/v1/jwks' -f ${TEMPDIR}/jwks.new.json
    ```

    GCP public-bucket
    ```bash
    gcloud storage cp ${TEMPDIR}/jwks.new.json gs://${GCP_BUCKET}/keys.json
    ```

    GCP pool-jwk-file
    ```bash
    gcloud iam workload-identity-pools providers update-oidc ${CLUSTER_NAME} --location=global --workload-identity-pool=${CLUSTER_NAME} --jwk-json-path=${TEMPDIR}/jwks.new.json
    ```

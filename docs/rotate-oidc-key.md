# How to rotate the OIDC bound service account signer key

## Overview
When OpenShift is configured to use temporary credentials (AZWI, STS, WIF) to authenticate with the cloud platform api, special care must be taken when rotating the bound service account signer keys in order to reduce authentication failures. This can be accomplished by adding the new public key to the existing issuer file immediately after the cluster generates it. Once the cluster has fully updated to the new key all other keys can be removed.

## Process

1. Configure environment variables

    This process depends on the following environment variables being defined. You may need to specify some of the values if the corresponding resource names are not equal to the values derived from the cluster name.

    Common
    ```bash
    CLUSTER_ID=$(oc get infrastructures cluster -o jsonpath='{.status.infrastructureName}')

    CLUSTER_NAME=${CLUSTER_ID:0:-6}

    TEMPDIR=${CLUSTER_NAME}-$(date +%Y%m%d%H%M%S)

    mkdir ${TEMPDIR}
    ```

    AWS
    ```bash
    AWS_BUCKET=${CLUSTER_NAME}-oidc
    ```

    Azure
    ```bash
    CURRENT_ISSUER=$(oc get authentication cluster -o jsonpath='{.spec.serviceAccountIssuer}')

    AZURE_STORAGE_ACCOUNT=$(basename ${CURRENT_ISSUER})

    AZURE_STORAGE_CONTAINER=$(basename ${CURRENT_ISSUER})
    ```

    GCP
    ```bash
    CURRENT_ISSUER=$(oc get authentication cluster -o jsonpath='{.spec.serviceAccountIssuer}')

    GCP_BUCKET=$(basename ${CURRENT_ISSUER})
    ```

1. Confirm that your cluster is in a stable state.

    ```bash
    oc adm wait-for-stable-cluster --minimum-stable-period=5s
    ```

1. Trigger the kube-apiserver to create a new bound service account signing key.

    Deleting the next-bound-service-account-signing-key secret will cause the kube-apserver to generate a new one. At this point, the kube-apiserver will start rolling out the new key. In order to reduce the risk of authentication failures, it is important to complete all steps up to and including ***Upload the combined keys file*** as quickly as possible.

    ```bash
    oc -n openshift-kube-apiserver-operator delete secrets/next-bound-service-account-signing-key
    ```

1. Download the new bound service account signing key public key

    Download the public key from the freshly generated next-bound-service-account-signing-key secret. We will use this key to generate keys.json files to upload to the oidc issuer.

    ```bash
    oc get -n openshift-kube-apiserver-operator secret/next-bound-service-account-signing-key -ojsonpath='{ .data.service-account\.pub }' | base64 -d > ${TEMPDIR}/serviceaccount-signer.public
    ```

1. Create a keys.json using the new public key

    Use the public key downloaded above to create a new keys.json file. We do this by taking advantage of the --dry-run option in order to only output files on disk, including the new keys.json file.

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

    cp ${TEMPDIR}/03-keys.json ${TEMPDIR}/jwks.new.json
    ```

1. Download the current keys.json from the cloud provider.

    AWS
    ```bash
    aws s3api get-object --bucket ${AWS_BUCKET} --key keys.json ${TEMPDIR}/jwks.current.json
    ```

    Azure
    ```bash
    az storage blob download --container-name ${AZURE_STORAGE_CONTAINER} --account-name ${AZURE_STORAGE_ACCOUNT} --name 'openid/v1/jwks' -f ${TEMPDIR}/jwks.current.json
    ```

    GCP
    ```bash
    gcloud storage cp gs://${GCP_BUCKET}/keys.json ${TEMPDIR}/jwks.current.json
    ```

1. Combine the current and new keys

    Combine the key(s) downloaded from the cloud provider with the new key. The resulting file will enable authentication for both the old and new keys during the transistion.

    ```bash
    jq -s '{ keys: map(.keys[])}' ${TEMPDIR}/jwks.current.json ${TEMPDIR}/jwks.new.json > ${TEMPDIR}/jwks.combined.json
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

    GCP
    ```bash
    gcloud storage cp ${TEMPDIR}/jwks.combined.json gs://${GCP_BUCKET}/keys.json
    ```

1. Wait for kube-apiserver to update to the new key

    Wait for the kube-apiserver pods to be using the new key before proceeding. The kube-apiserver operator enters the progressing state until all of the pods are cycled and using the new key.

    ```bash
    oc adm wait-for-stable-cluster
    ```

1. Reboot all of the nodes

    After the kube-apiserver is using the new key, reboot all of the config machine pools. This ensures all of the pods on the cluster are using the new key while maintaining uptime on services configured to be highly-available.

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

    GCP
    ```bash
    gcloud storage cp ${TEMPDIR}/jwks.new.json gs://${GCP_BUCKET}/keys.json
    ```

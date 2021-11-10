# Alibaba Cloud Manual Mode

This is the guide for using  manual mode on alibaba cloud, for more use info about manual mode, please reference to [cco-mode-manual](https://docs.openshift.com/container-platform/4.9/authentication/managing_cloud_provider_credentials/cco-mode-manual.html).

In alibaba cloud manual mode,  the CCO utility (`ccoctl`) binary would generate long-lived RAM AK credentials for individual OpenShift Container Platform cluster components. The ram user who owns the AK would be attached the ram policy with the permission defined in each components, and a root ram user who required `ram:CreatePolicy` and `ram:AttachPolicyToUser` pemission as least is needed for attaching the permission for each component.

## Prerequisite

1. Extract and prepare the ccoctl binary from the release image.

2. [create a ram user](https://partners-intl.aliyun.com/help/doc-detail/93720.htm)(has no permission in default) for binding the cluster components permission, and get the ram accesskey id/accesskey secret/user name as the input parameters of the alibaba cloud ccoctl command.

3. choose an existing ram user who required `ram:CreatePolicy` and `ram:AttachPolicyToUser` pemission as least, and get this ram user's accesskey id/accesskey secret for attaching the specific component permission to the ram user created in step 2.

    

## Procedure

1. Extract the list of CredentialsRequest custom resources (CRs) from the OpenShift Container Platform release image:

   ```bash
   $ oc adm release extract --credentials-requests --cloud=alibabacloud --to=<path_to_directory_with_list_of_credentials_requests>/credrequests quay.io/<path_to>/ocp-release:<version>
   
   ```

2. For each CredentialsRequest CR in the release image, ensure that a namespace that matches the text in the spec.secretRef.namespace field exists in the cluster. This field is where the generated secrets that hold the credentials configuration are stored.

   Sample Alibaba Cloud CredentialsRequest object

   ```yaml
   apiVersion: cloudcredential.openshift.io/v1
   kind: CredentialsRequest
   metadata:
     name: cloud-credential-operator-ram-ro
     namespace: openshift-cloud-credential-operator
   spec:
     providerSpec:
       apiVersion: cloudcredential.openshift.io/v1
       kind: AlibabaCloudProviderSpec
       statementEntries:
       - action:
         - ecs:CopySnapshot
         - ecs:DeleteDisk
         - ecs:DescribeInstanceAttribute
         - ecs:DescribeInstances
         effect: Allow
         resource: '*'
     secretRef:
       namespace: cloud-credential-operator-ram-ro-creds
       name: openshift-cloud-credential-operator
   ```

3. For any `CredentialsRequest` CR for which the cluster does not already have a namespace with the name specified in `spec.secretRef.namespace`, create the namespace:

   ```
   $ oc create namespace <component_namespace>
   ```

4. Use the `ccoctl` tool to process all `CredentialsRequest` objects in the `credrequests` directory:

   ```bash
   $ ccoctl alibabacloud attach-ram-policy --name <name> --region=<region> --credentials-requests-dir=<path_to_directory_with_list_of_credentials_requests>/credrequests --root-access-key=xxxxx --root-access-key-secret=xxxxx --user-name=testuser --component-access-key=xxxxxx --component-access-secret=xxxxxx --output-dir=xxxxxx
   ```

    where:

   - `name` is the name used to tag any cloud resources that are created for tracking. 
   - `region` is the Alibaba Cloud region in which cloud resources will be created.
   - `credentials-requests-dir` is the directory containing files of component CredentialsRequests.
   - `root-access-key` is the ram user ak with ram permission such as CreatePolicy/AttachPolicyToUser as least.
   - `root-access-key-secret` is the ram user sk with ram permission such as CreatePolicy/AttachPolicyToUser as least.
   - `user-name` is the ram user name who created for binding components required ram permission.
   - `component-access-key` is the ram user ak who created for binding components required ram permission.
   - `component-access-secret` is the ram user sk who created for binding components required ram permission.
   - `output-dir`/manifests is the directory containing files of component credentials secret.

5. Apply the secrets to your cluster:

   ```bash
   $ ls <output_dir>/manifests/*-credentials.yaml | xargs -I{} oc apply -f {}
   ```

   
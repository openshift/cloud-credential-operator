# Short lived Credentials with AWS Security Token Service
### Overview
OpenShift can be configured to use temporary credentials for different components with AWS Security Token Service (STS). It enables an authentication flow allowing a component to assume an IAM Role resulting in short-lived credentials. It also automates requesting and refreshing of credentials using an AWS IAM OpenID Connect (OIDC) Identity Provider. OpenShift can sign ServiceAccount tokens trusted by AWS IAM which can be projected into a Pod and used for authentication. The following is a diagram showing how it works.

![sts flow](sts_flow.png)

### Changes in the Credentials Secret with STS
Previously, if we checked the credentials secret, we'd find the following base64 encoded content in the `credentials` key of the `data` field.

```yaml
[default]
aws_access_key_id = <access_key_id>
secret_access_key = <secret_access_key>
```

With STS we have a full-fledged AWS configuration that defines a `role` and `web identity token`

```yaml
[default]
role_name = arn:...:role/some-role-name
web_identity_token_file = /path/to/token
```
The token is a projected ServiceAccount into the Pod, and is short lived for an hour after which it is refreshed.

### Steps to install an OpenShift Cluster with STS

1. Set $RELEASE_IMAGE to point to a sufficiently new OpenShift release
2. Extract the AWS Credentials Request objects from the above release image
   
   With newer version of oc CLI (4.7+):
   ```
   mkdir credreqs ; oc adm release extract --cloud=aws --credentials-requests $RELEASE_IMAGE --to=./credreqs
   ```
3. Extract the OpenShift install binary from the release image
   ```
   oc adm release extract --command=openshift-install $RELEASE_IMAGE
   ```
4. Create an install-config.yaml
   ```
   ./openshift-install create install-config
   ```
5. Make sure that we install the cluster in Manual mode
   ```
   echo "credentialsMode: Manual" >> install-config.yaml
   ``` 
6. Create install manifests
   ```
   ./openshift-install create manifests   
   ```
7. Create AWS resources using the [ccoctl](ccoctl.md) tool (you will need aws credentials with sufficient permissions). The command below will generate public/private ServiceAccount signing keys, create the S3 bucket, upload the OIDC config into the bucket, set up an IAM Identity Provider that trusts that bucket configuration, and create IAM Roles for each AWS CredentialsRequest extracted above. It will also dump the files needed by the installer in the `_output` directory
   ```
   ./ccoctl aws create-all --name <aws_infra_name> --region <aws_region> --credentials-requests-dir /path/to/credreqs.yaml/downloaded/in/step/2   
   ```
8. Copy the manifests created in the step 7 and put them in the same location as install-config.yaml in the `manifests` directory
   ```
   cp _output/manifests/* /path/to/dir/with/install-config.yaml/manifests/
   ```
9. Copy the private key for the ServiceAccount signer and put it in the same location as install-config.yaml
   ```
   cp -a _output/tls /path/to/dir/with/install-config.yaml
   ```
10. Run the OpenShift installer
    ```
    ./openshift-install create cluster --log-level=debug
    ```

### Post install verification

1. Connect to the newly installed cluster and verify that the OpenShift cluster does not have `root` credentials. Below command should throw secret not found error
   ```yaml
   oc get secrets -n kube-system aws-creds
   ```
2. Verify that components are assuming the IAM Role specified in the secret manifests, instead of creds minted by the cloud-credential-operator. Below command should show you the `role` and `web identity token` used by the image registry operator
   ```yaml
   oc get secrets -n openshift-image-registry installer-cloud-credentials -o json | jq -r .data.credentials | base64 -d
   ```
   sample output of the above command
   ```
   [default]
   role_arn = arn:aws:iam::123456789:role/<aws_infra_name>-openshift-image-registry-installer-cloud-credentials
   web_identity_token_file = /var/run/secrets/openshift/serviceaccount/token
   ```

### Cleanup AWS resources after uninstalling the cluster

Delete the S3 bucket, IAM identity provider, and IAM Roles using the  [ccoctl](ccoctl.md#deleting-resources) tool.

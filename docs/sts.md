# Short lived Credentials with AWS Security Token Service (beta)
### Overview
OpenShift can be configured to use temporary credentials for different components with AWS Security Token Service (STS). It enables an authentication flow allowing a component to assume an IAM Role resulting in short-lived credentials. It also automates requesting and refreshing of credentials using an AWS IAM OpenID Connect (OIDC) Identity Provider. OpenShift can sign ServiceAccount tokens trusted by AWS IAM which can be projected into a Pod and used for authentication. The following is a diagram showing how it works.

![sts flow](sts_flow.png)

### Changes in the Credentials Secret with STS
If we check the credentials secret, we have the following base64 encoded content in the `credentials` key of the `data` field.

Without STS we have `access key id` and `secret access key`

```yaml
[default]
aws_access_key_id = <access_key_id>
secret_access_key = <secret_access_key>
```

With STS we have `role` and `web identity token`

```yaml
[default]
role_name = arn:...:role/some-role-name
web_identity_token_file = /path/to/token
```
The token is short lived for an hour after which it is refreshed.

### Steps to install an OpenShift Cluster with STS

1. Set $RELEASE_IMAGE to point to a sufficiently new OpenShift release
2. Extract the AWS Credentials Request objects from the above release image
   
   With newer version of oc CLI (4.7+) where you no longer get the output in the stdout
   ```
   mkdir credreqs ; oc adm release extract --cloud=aws --credentials-requests $RELEASE_IMAGE --to=./credreqs ; cat ./credreqs/*.yaml > credreqs.yaml
   ```
   With older version of oc CLI
   ```
   oc adm release extract --cloud=aws --credentials-requests $RELEASE_IMAGE > credreqs.yaml
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
7. Create AWS resources using [sts-preflight](https://github.com/sjenning/sts-preflight) tool (you will need aws credentials with sufficient permissions). Below command will generate public/private ServiceAccount signing keys, create the S3 bucket, upload the OIDC config into the bucket, set up an IAM Identity Provider that trusts that bucket, an IAM Role to be used for installation (this role has admin rights), and create IAM Roles for each AWS CredentialsRequest. It will also dump the files needed by the installer in the `_output` directory
   ```
   ./sts-preflight create --infra-name <aws_infra_name> --region <aws_region> --credentials-requests-to-roles /path/to/credreqs.yaml/downloaded/in/step/2   
   ```
8. Currently, the [sts-preflight](https://github.com/sjenning/sts-preflight) tool does not put a condition on the created IAM role to allow only specific namespace/ServiceAccountNames from assuming the Role. To more properly restrict which identities can assume which Role we need to manually modify each Role to achieve this. Please note that Role names might be truncated if they are more than 64 characters

   i. Modify trust relationship of the role <aws_infra_name>-openshift-image-registry-installer-cloud-credentials to have the following condition.

    ```json
    "Condition": {
      "StringEquals": {
        "s3.us-east-1.amazonaws.com/<aws_infra_name>-installer:sub": [
          "system:serviceaccount:openshift-image-registry:registry",
          "system:serviceaccount:openshift-image-registry:cluster-image-registry-operator"
        ]
      }
    }         
    ```

   ii. Modify trust relationship of the role <aws_infra_name>-openshift-ingress-operator-cloud-credentials to have the following condition.

    ```json
    "Condition": {
      "StringEquals": {
        "s3.us-east-1.amazonaws.com/<aws_infra_name>-installer:sub": [
          "system:serviceaccount:openshift-ingress-operator:ingress-operator"
        ]
      }
    }         
    ```
   iii. Modify trust relationship of the role <aws_infra_name>-openshift-cluster-csi-drivers-ebs-cloud-credentials to have the following condition.

    ```json
    "Condition": {
      "StringEquals": {
        "s3.us-east-1.amazonaws.com/<aws_infra_name>-installer:sub": [
          "system:serviceaccount:openshift-cluster-csi-drivers:aws-ebs-csi-driver-operator",
          "system:serviceaccount:openshift-cluster-csi-drivers:aws-ebs-csi-driver-controller-sa"          
        ]
      }
    }         
    ```
   iv. Modify trust relationship of the role <aws_infra_name>-openshift-machine-api-aws-cloud-credentials to have the following condition.

    ```json
    "Condition": {
      "StringEquals": {
        "s3.us-east-1.amazonaws.com/<aws_infra_name>-installer:sub": [
          "system:serviceaccount:openshift-machine-api:machine-api-controllers"          
        ]
      }
    }         
    ```

9. Copy the manifests created in the step 7 and put them in the same location as install-config.yaml in the `manifests` directory
   ```
   cp _output/manifests/* /path/to/dir/with/install-config.yaml/manifests/
   ```
10. Copy the private key for the ServiceAccount signer and put it in the same location as install-config.yaml
   ```
   cp -a _output/tls /path/to/dir/with/install-config.yaml
   ```
11. Create a token trusted by OpenID Connect provider. We will use this token to assume a role to get credentials to start the installation. This token will be created in `_output/token` directory
   ```
   ./sts-preflight token
   ```
12. Use the token created above to assume the installer role and mint credentials required for the OpenShift installation process.
    ```
    ./sts-preflight assume
    ```
13. Run the `export` commands from the output of the above the step.
    ```
    export AWS_ACCESS_KEY_ID=<aws_access_key_id>
    export AWS_SECRET_ACCESS_KEY=<aws_secret_access_>
    export AWS_SESSION_TOKEN=<aws_session_token>
    ```
14. Run the OpenShift installer
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

Make sure you clean up the following resources after you uninstall your cluster. You can use `aws_infra_name` used in installation step 7 to identify these resources

1. IAM Identity Provider
2. S3 bucket used to store OpenID Connect configuration and the public key
3. IAM roles created by [sts-preflight](https://github.com/sjenning/sts-preflight) tool
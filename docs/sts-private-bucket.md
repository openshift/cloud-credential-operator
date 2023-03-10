# Short-lived Credentials with AWS Security Token Service using AWS CloudFront and private S3 bucket

<!-- # Diagram explaining current flow (S3 public)
![aws-iam-oidc-flow](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/t6j45d92bmgauvy9zket.png)
-->

> NOTE: The steps described in this document, create a private S3 Bucket using CloudFront Distribution, was introduced to `ccoctl` using the flag `--create-private-s3-bucket`. We are keeping this document to provide an overview of the steps used in this solution.

To create an IAM OpenID Connect identity provider you should expose the OIDC config using a public HTTPS endpoint. The steps described here will guide you to create one CloudFront Distribution to expose the HTTPS endpoint, serving objects from a private S3 Bucket accessed by [Origin Access Identity](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html).

Summary:
- [Create](#steps-create)
  - [Create the Origin Access Identity](#step-create-oai)
  - [Create the Bucket](#step-create-bucket)
  - [Create the CloudFront Distribution](#step-create-cloudfront-dist)
  - [Generate the OIDC configuration and keys](#step-gen-oidc)
  - [Create the OpenID Connector identity provider](#step-create-oidc)
  - [Create the IAM Roles](#step-create-iam-roles)
- [Delete](#steps-delete)
  - [Delete the CloudFront Distribution](#step-delete-dist)
  - [Delete the Origin Access Identity](#step-delete-oai)

## Requirements

- oc
- ccoctl
- [aws-cli](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html)
- You followed the Steps 1 to in the section ["Steps to install an OpenShift Cluster with STS"](./sts.md#steps-to-install-an-openshift-cluster-with-sts)

## Steps to Create<a name="steps-create"></a>

### Set the environment variables

> considering that the installer directory is the same you are running this command

```bash
export CLUSTER_NAME=$(awk '/infrastructureName: / {print $2}' manifests/cluster-infrastructure-02-config.yml)
export CLUSTER_REGION=$(awk '/region: / {print $2}' manifests/cluster-infrastructure-02-config.yml)

export DIR_CCO="${PWD}/_output"
export OIDC_BUCKET_NAME="${CLUSTER_NAME}-oidc"
export OIDC_BUCKET_CONTENT="${DIR_CCO}/bucket-content"

mkdir -p ${OIDC_BUCKET_CONTENT}
```

### Create the Origin Access Identity<a name="step-create-oai"></a>

Steps to create the Origin Access Identity (OAI) to be used to access the bucket through CloudFront Distribution:

- Create the OAI and set the variable `OAI_CLOUDFRONT_ID`:

```bash
aws cloudfront create-cloud-front-origin-access-identity \
    --cloud-front-origin-access-identity-config \
    CallerReference="${OIDC_BUCKET_NAME}",Comment="OAI-${OIDC_BUCKET_NAME}"

export OAI_CLOUDFRONT_ID=$(aws cloudfront \
    list-cloud-front-origin-access-identities \
    --query "CloudFrontOriginAccessIdentityList.Items[?Comment==\`OAI-${OIDC_BUCKET_NAME}\`].Id" \
    --output text)
```

### Create the Bucket<a name="step-create-bucket"></a>

- Create the private Bucket

```bash
aws s3api create-bucket \
    --bucket ${OIDC_BUCKET_NAME} \
    --region ${CLUSTER_REGION} \
    --create-bucket-configuration LocationConstraint=${CLUSTER_REGION} \
    --acl private
```

- Create the respective tags on the Bucket (Recommended if you would like to use the `ccoctl` to delete resources)

```bash
aws s3api put-bucket-tagging \
    --bucket ${OIDC_BUCKET_NAME} \
    --tagging "TagSet=[{Key=Name,Value=${OIDC_BUCKET_NAME}},{Key=openshift.io/cloud-credential-operator/${CLUSTER_NAME},Value=owned}]"
```

- Download the s3 bucket policy [template](./sts-oidc-bucket-policy.json.tpl) that restricts access to CloudFront Origin Access Identity (OAI)

```bash
wget https://raw.githubusercontent.com/openshift/cloud-credential-operator/master/docs/sts-oidc-bucket-policy.json.tpl
```

- Create the Bucket Policy configuration (cli-input-json) allowing OAI to retrieve objects

```bash
cat sts-oidc-bucket-policy.json.tpl \
   | envsubst \
   > ${DIR_CCO}/oidc-bucket-policy.json
```

- Apply the policy to the Bucket to block public access

```bash
aws s3api put-bucket-policy \
    --bucket ${OIDC_BUCKET_NAME} \
    --policy file://${DIR_CCO}/oidc-bucket-policy.json

aws s3api put-public-access-block \
    --bucket ${OIDC_BUCKET_NAME} \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

## Create CloudFront Distribution<a name="step-create-cloudfront-dist"></a>

- Download the [CloudFront Distribution template](./sts-oidc-cloudfront.json.tpl)

```bash
wget https://raw.githubusercontent.com/openshift/cloud-credential-operator/master/docs/sts-oidc-cloudfront.json.tpl
```

- Create a CloudFront Distribution configuration (cli-input-json)

```bash
cat sts-oidc-cloudfront.json.tpl \
   | envsubst \
   > ${DIR_CCO}/oidc-cloudfront.json
```

- Create the CloudFront Distribution with Tags

```bash
aws cloudfront create-distribution-with-tags \
    --distribution-config-with-tags \
    file://${DIR_CCO}/oidc-cloudfront.json
```

- Wait until the Distribution resource has been created

- Get the CloudFront's Distribution URL

```bash
export CLOUDFRONT_URI=$(aws cloudfront list-distributions \
    --query "DistributionList.Items[?Comment==\`${CLUSTER_NAME}\`].DomainName" \
    --output text)

echo ${CLOUDFRONT_URI}
```

### Generate OIDC configuration and keys<a name="step-gen-oidc"></a>

- Generate the key pair used to create the service account tokens

```bash
./ccoctl aws create-key-pair \
    --output-dir ${DIR_CCO}
```

- Generate the OpenID configuration

```bash
./ccoctl aws create-identity-provider \
    --name=${CLUSTER_NAME} \
    --region=${CLUSTER_REGION} \
    --public-key-file=${DIR_CCO}/serviceaccount-signer.public \
    --output-dir=${DIR_CCO}/ \
    --dry-run
```

- Update the CloudFront URI's endpoint to the CloudFront distribution's address:

A. Patch the issuer URL on the OpenID configuration file `/.well-known/openid-configuration`

```bash
mkdir -p ${OIDC_BUCKET_CONTENT}/.well-known
cat ${DIR_CCO}/02-openid-configuration \
    | sed "s/https:\/\/${CLUSTER_NAME}[a-z.-].*\//https:\/\/${CLOUDFRONT_URI}\//" \
    | sed "s/https:\/\/${CLUSTER_NAME}[a-z.-].*/https:\/\/${CLOUDFRONT_URI}\",/" \
    > ${OIDC_BUCKET_CONTENT}/.well-known/openid-configuration
```

B. Copy `keys.json`

```bash
cp -v ${DIR_CCO}/03-keys.json \
    ${OIDC_BUCKET_CONTENT}/keys.json
```

C. Patch the issuer url on `Authentication` CRD in `cluster-authentication-02-config.yaml`

```bash
sed -i "s/https:\/\/[a-z.-].*/https:\/\/${CLOUDFRONT_URI}/" \
    ${DIR_CCO}/manifests/cluster-authentication-02-config.yaml
```

D. Update the IdP OIDC object configuration

```bash
sed -i "s/https:\/\/[a-z.-].*/https:\/\/${CLOUDFRONT_URI}\",/" \
    ${DIR_CCO}/04-iam-identity-provider.json
```

> Check the output of `jq . ${DIR_CCO}/04-iam-identity-provider.json`

- Upload the bucket content

```bash
aws s3 sync ${OIDC_BUCKET_CONTENT}/ \
    s3://${OIDC_BUCKET_NAME}
```

- Make sure you can access the content through the public URL

> NOTE: CloudFront can take some time to deploy the distribution. Please be sure the distribution has been deployed and it's available before running this step (`Status=Enabled` and `Last Modified!=Deploying`). You can access the [CloudFront Console](https://us-east-1.console.aws.amazon.com/cloudfront/) to check it.

```bash
curl https://${CLOUDFRONT_URI}/keys.json
curl https://${CLOUDFRONT_URI}/.well-known/openid-configuration
```

### Create the OpenID Connector identity provider<a name="step-create-oidc"></a>

- Create the IAM OpenID Connect identity provider

```bash
aws iam create-open-id-connect-provider \
    --cli-input-json file://${DIR_CCO}/04-iam-identity-provider.json \
    > ${DIR_CCO}/04-iam-identity-provider-object.json 
```

- Get the ARN of the IAM OpenID Connect identity provider created above

```bash
OIDC_ARN=$(jq -r .OpenIDConnectProviderArn \
    ${DIR_CCO}/04-iam-identity-provider-object.json)

echo ${OIDC_ARN}
```

### Create IAM Roles<a name="step-create-iam-roles"></a>

- Extract `CredentialRequests` from the release image

```bash
./oc adm release extract \
    --credentials-requests \
    --cloud=aws \
    --to=${DIR_CCO}/credrequests \
    ${RELEASE_IMAGE}
```

- Create IAM Roles for the OpenShift components

```bash
./ccoctl aws create-iam-roles \
    --name=${CLUSTER_NAME} \
    --region=${CLUSTER_REGION}\
    --credentials-requests-dir=${DIR_CCO}/credrequests \
    --identity-provider-arn=${OIDC_ARN} \
    --output-dir ${DIR_CCO}
```

We have now created IAM OpenID Connect identity provider and IAM roles, you can return to [step 8](./sts.md#steps-to-install-an-openshift-cluster-with-sts) to continue with installation in STS mode. 

## Steps to Delete<a name="steps-delete"></a>

These steps should be followed after you've removed the resources created by ccoctl described in [the delete section](./ccoctl.md#aws-delete).

Requirements:
- You should have set the CloudFront Distribution `Comment` as `${CLUSTER_NAME}`, as described in the section above. Otherwise, you should specify the value you've set when creating the CloudFront Distribution.
- You should have set the CloudFront Origin Access Identity (OAI) with the field `Comment` with the value `OAI-${OIDC_BUCKET_NAME}`. Otherwise, you should specify the value you've set when creating the CloudFront OAI.

### Remove the Bucket<a name="step-bucket"></a>

If the `ccoctl delete` command failed due to non-empty Bucket (`BucketNotEmpty`), you should follow those steps to complete the Bucket removal.

- Remove the Bucket objects

```bash
aws s3api delete-object \
    --bucket ${OIDC_BUCKET_NAME} \
    --key ".well-known/openid-configuration"

aws s3api delete-object \
    --bucket ${OIDC_BUCKET_NAME} \
    --key "keys.json"
```

- Remove the Bucket using `ccoctl`

```bash
./ccoctl aws delete \
    --name=${CLUSTER_NAME} \
    --region=${CLUSTER_REGION}
```

### Remove the CloudFront Distribution<a name="step-delete-dist"></a>

CloudFront Distributions can be removed only when it is disabled. To do so, you need to get the current configuration, setting the field `Enabled` to `false`, apply the new configuration, then remove the Distribution.

- Get the CloudFront Distribution ID

```bash
DISTRIBUTION_ID=$(aws cloudfront list-distributions \
    --query "DistributionList.Items[?Comment==\`${CLUSTER_NAME}\`].Id" \
    --output text)
```

- Get the CloudFront Distribution Config `ETag`

```bash
ETAG=$(aws cloudfront get-distribution-config \
    --id ${DISTRIBUTION_ID} \
    | jq -r '.ETag')
```

- Get the CloudFront Distribution Configuration, setting the `Enabled` field to `false`

```bash
aws cloudfront get-distribution-config --id ${DISTRIBUTION_ID} \
    | jq '.DistributionConfig' \
    | jq '.Enabled=false' \
    > ${DIR_CCO}/oidc-cloudfront-to-delete.json
```

- Apply the new Distribution configuration

```bash
ETAG=$(aws cloudfront update-distribution \
    --id ${DISTRIBUTION_ID} \
    --if-match ${ETAG} \
    --distribution-config file://${DIR_CCO}/oidc-cloudfront-to-delete.json \
    | jq -r '.ETag')
```

- Get the new ETag (it's also returned on the last command).

> The last command updates the `ETAG` variable referencing to a new configuration (Disabled distribution). If you didn't note it you need to re-run the `get-distribution-config` command, as desribed above.

- Delete the CloudFront Distribution

```bash
aws cloudfront delete-distribution \
    --id ${DISTRIBUTION_ID} \
    --if-match ${ETAG}
```

### Remove the Origin Access Identity (OAI)<a name="step-delete-oai"></a>

- Get the OAI ID

```bash
OAI_CLOUDFRONT_ID=$(aws cloudfront \
    list-cloud-front-origin-access-identities \
    --query "CloudFrontOriginAccessIdentityList.Items[?Comment==\`OAI-${OIDC_BUCKET_NAME}\`].Id" \
    --output text)
```

- Get the OAI ETag by ID

```bash
OAI_ETAG=$(aws cloudfront \
    get-cloud-front-origin-access-identity-config \
    --id ${OAI_CLOUDFRONT_ID} \
    | jq -r .ETag)
```

- Remove the OAI by ID

```bash
aws cloudfront \
    delete-cloud-front-origin-access-identity \
    --id ${OAI_CLOUDFRONT_ID} \
    --if-match ${OAI_ETAG}
```

# OpenShift Cloud Credential Operator

The cloud credential operator is a controller that will sync on
CredentialsRequest custom resources. CredentialsRequests allow OpenShift
components to request fine grained credentials for a particular cloud provider.
(as opposed to using the admin credentials, or elevated permissions granted via
instance roles)

# Design Principles

  * The controller should be able to run in either a cluster itself, or in a centralized management cluster, most likely along side [Hive](https://github.com/openshift/hive).
  * Controller expects access to a set of credentials we refer to as the "admin" credentials.
  * If the admin credentials are missing, but all credentials requests are fulfilled and valid, this is considered a valid state. (i.e. the admin creds were removed from the cluster after use)
  * If the admin credentials are able to create additional credentials, we will create fine grained permissions as defined in the credentials request. (best practice)
  * If the admin credentials cannot create additional credentials, but do themselves fulfill the requirements of the credentials request, they will be used. (with logged warnings and a condition on the credentials request)
  * If the admin credentials fulfill neither of the above requirements, the controller will fail to generate the credentials, report failure back to the Cluster Version Operator, and thus block upgrading. The installer will also perform this check early to inform the user their cluster will not function.

# Cloud Providers

Currently the operator supports AWS, GCP, Azure, VMWare, OpenStack and oVirt.

## Credentials Root Secret Formats

Each cloud provider utilizes a credentials root secret in the kube-system
namespace (by convention), which is then used to satisfy all
CredentialsRequests and create their respective Secrets. (either by minting new
credentials (mint mode), or by copying the credentials root secret (passthrough
mode))

The format for the secret varies by cloud, and is also used for each CredentialsRequest Secret.

### AWS

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: kube-system
  name: aws-creds
data:
  aws_access_key_id: Base64encodeAccessKeyID
  aws_secret_access_key: Base64encodeSecretAccessKey
```

### Azure
```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: kube-system
  name: azure-credentials
data:
  azure_subscription_id: Base64encodeSubscriptionID
  azure_client_id: Base64encodeClientID
  azure_client_secret: Base64encodeClientSecret
  azure_tenant_id: Base64encodeTenantID
  azure_resource_prefix: Base64encodeResourcePrefix
  azure_resourcegroup: Base64encodeResourceGroup
  azure_region: Base64encodeRegion
```

### GCP

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: kube-system
  name: gcp-credentials
data:
  service_account.json: Base64encodeServiceAccount
```

### OpenStack

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: kube-system
  name: openstack-credentials
data:
  clouds.yaml: Base64encodeCloudCreds
  clouds.conf: Base64encodeCloudCredsINI
```

### Ovirt

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: kube-system
  name: ovirt-credentials
data:
  ovirt_url: Base64encodeURL
  ovirt_username: Base64encodeUsername
  ovirt_password: Base64encodePassword
  ovirt_cafile: Base64encodeCAFile
  ovirt_insecure: Base64encodeInsecure
  ovirt_ca_bundle: Base64encodeCABundle
```

### VSphere:

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: kube-system
  name: vsphere-creds
data:
 {{VCenter.username}}: Base64encodeUsername
 {{VCenter.password}}: Base64encodePassword
```

Source of templates:
  * https://github.com/openshift/installer/blob/master/data/data/manifests/openshift/cloud-creds-secret.yaml.template

# Modes of Operation

## 1. Mint Mode

The default and recommended best practice for running OpenShift is to run the installer with an admin level cloud credential. The admin credential is stored in kube-system namespace and then used by the cloud credential operator to process the CredentialRequests in the cluster and create new users for each with fine grained permissions.

Pros:
  * Each cluster component has only the permissions it needs.
  * Automatic on-going reconciliation for cloud credentials including upgrades, which may require additional credentials or permissions.

Cons:
  * Requires admin credential storage in a cluster kube-system secret. (however if a user has access to all secrets in your cluster, you are severely compromised regardless)

Supported clouds: AWS, GCP, Azure

### 1.1 Mint Mode With Removal/Rotation Of Admin Credential

In this mode a user installs OpenShift with an admin credential per the normal mint mode, but removes the admin credential Secret from the cluster post-installation. The cloud credential operator makes it's own request for a read-only credential that allows it to verify if all CredentialsRequests have their required permissions, thus the admin credential is not needed unless something needs to be changed. (i.e. upgrade) Once removed the associated credential could then be destroyed on the underlying cloud if desired.

Prior to upgrade, the admin credential should be restored. In the future upgrade may be blocked if the credential is not present. (see the Secret format's above)

Pros:
  * Admin credential is not stored in the cluster permanently and does not need to be long lived.

Cons:
  * Still requires admin credential in the cluster for brief periods of time.
  * Requires manually re-instating the Secret with admin credentials for each upgrade.

Supported clouds: AWS, GCP

## 2. Passthrough Mode

In this mode a user installs OpenShift with a single credential that *is not* an admin and cannot mint additional credentials, but itself has enough permissions to perform the installation as well as all operations needed by all components in the cluster. The cloud credential operator then shares this credential to each component.

Your passthrough mode credential will need to be manually maintained if CredentialsRequests change over time as the cluster is upgraded. This should be checked prior to every upgrade, and in the future you may be required to confirm you have done so a change in CredentialsRequests is detected.

By default the permissions needed only for installation are required, however it is possible to reduce the permissions on your credential post-install to just what is needed to run the cluster. (as defined by the CredentialsRequests in the current release image) See the secret formats above for details on how to do this.

Pros:
  * Does not require installing or running with an admin credential.

Cons:
  * Includes broad permissions only needed at install time, unless manual action is taken to reduce permissions post-install.
  * Credential permissions may need to be manually updated prior to any upgrade.
  * Each component has permissions used by all other components.

Supported clouds: AWS, GCP, Azure, VMWare, OpenStack, oVirt

## 3. Manual Credentials Management

In this mode a user manually performs the job of the cloud credential operator. This requires examining the CredentialsRequests in an OpenShift 4 release image, creating credentials in the underlying cloud provider, and finally creating Kubernetes Secrets in the correct namespaces to satisfy all CredentialsRequests for the cluster's cloud provider.

Pros:
  * Admin credential never stored in the cluster.
  * Each cluster component has only the permissions it needs.

Cons:
  * Manual process required for install and every upgrade to reconcile permissions with the new release image.

Supported clouds: AWS

[Documentation](./docs/mode-manual-creds.md)

##  4. Automated Short Lived Tokens

WARNING: In development functionality for AWS only, final state is not 100% known.

This future enhancement will allow the use of short lived Amazon STS tokens. In this mode the credentials operator will create ServiceAccounts (rather than the usual secrets), annotated such that the AWS pod identity webhook will manage tokens automatically. See this [enhancement](https://github.com/openshift/enhancements/pull/260)

Pros:
  * Each cluster component has only the permissions it needs.
  * Automatic on-going reconciliation for cloud credentials including upgrades.

Cons:
  * Requires admin credential storage in a cluster kube-system secret. (if this is readable however, your cluster is severely compromised regardless)

Future supported clouds: AWS

## Support Matrix
Cloud | Mint | Mint + Remove Admin Cred | Passthrough | Manual | Token
--- | --- | --- | --- | --- | ---
AWS | Y | 4.4+ | Y | 4.3+ | 4.6+ (expected)
Azure | Y | N | Y | unknown | N
GCP | Y | 4.7+ | Y | unknown | N
OpenStack | N | N | Y | N | N
oVirt | N | N | Y | N | N
VMWare | N | N | Y | N | N

# Developer Instructions

Login to a cluster with admin credentials:

```
$ make install
$ make run
```

NOTE: To keep the in-cluster versions of the code from conflicting with your local copy, you should scale down the deployments for cloud-credential-operator and cluster-version-operator

```
$ kubectl scale -n openshift-cloud-credential-operator deployment.v1.apps/cloud-credential-operator --replicas=0
$ kubectl scale -n openshift-cluster-version deployment.v1.apps/cluster-version-operator --replicas=0
```

## Deploying in cluster

 1. export IMG=quay.io/dgoodwin/cloud-credential-operator:latest
   * You can upload to a personal repo if you wish to build images from source.
 1. make buildah-push
 1. make deploy

Cred Minter should now be running in openshift-cloud-credential-operator.

# Credentials Requests

The primary custom resource used by this operator is the CredentialsRequest, which allows cluster components to request fine grained credentials.

CredentialRequests spec consist of:
 1. secretRef - Points to the secret where the credentials should be stored once generated. Can be in a separate namespace from the CredentialsRequest where it can be used by pods. If that namespace does not yet exist, the controller will immediately sync when it is created.
 2. providerSpec - Contains the [cloud provider specific credentials specification](https://github.com/openshift/cloud-credential-operator/tree/master/pkg/apis/cloudcredential/v1).

Once created, assuming admin credentials are available, the controller will provision a user, access key, and user policy in AWS. The access and secret key will be stored in the target secret specified above.

You can freely edit a CredentialsRequest to adjust permissions and the controller will reconcile those changes out to the respective user policy. (assuming admin credentials)


## AWS Sample

```yaml
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-image-registry
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: installer-cloud-credentials
    namespace: openshift-image-registry
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      - s3:CreateBucket
      - s3:DeleteBucket
      resource: "*"
```

## Azure Sample

```yaml
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-image-registry
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: installer-cloud-credentials
    namespace: openshift-image-registry
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AzureProviderSpec
    roleBindings:
      - role: Storage Account Contributor
      - role: Storage Blob Data Contributor
```

List of Azure built in roles: https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles

# For OpenShift Second Level Operators

 1. Add CredentialsRequests objects to your CVO manifests and deployed via the release payload. Please do not create them in operator code as we want to use the release manifest for auditing and dynamically checking permissions.
 1. The cred operator launches early (runlevel 30) so should be available when your component's manifests are applied.
 1. Your CredentialsRequests should be created in the openshift-cloud-credential-operator namespace.
 1. Your component should tolerate the credentials secret not existing immediately.
 1. Your component should tolerate the credentials secret periodically being rotated.


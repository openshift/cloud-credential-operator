# OpenShift Credentials Minter

Cred Minter is a controller that will sync on a CredentailsRequest custom
resource definition. CredentialsRequests allow OpenShift components to
request fine grained credentials for a particular cloud provider.

## Design Principles

  * The controller should be able to run in either a cluster itself, or in a centralized management cluster, most likely along side [Hive](https://github.com/openshift/hive).
  * Controller expects access to a set of credentials we refer to as the "admin" credentials.
  * If the admin credentials are missing, but all credentials requests are fulfilled and valid, this is considered a valid state. (i.e. the admin creds were removed from the cluster after use)
  * If the admin credentials are able to create additional credentials, we will create fine grained permissions as defined in the credentials request.
  * If the admin credentials cannot create additional credentials, but do themselves fulfill the requirements of the credentials request, they will be used. (with logged warnings and a condition on the credentials request)
  * If the admin credentials fulfill neither of the above requirements, the controller will fail to generate the credentials, report failure back to the Cluster Version Operator, and thus block upgrading.

## AWS

Currently AWS is the only supported cloud provider. If running in-cluster, your credentials are expected to exist in kube-system/aws-creds with the keys aws_access_key_id and aws_secret_access_key.

# Running from source

Login to a cluster with admin credentials:

```
$ make install
$ make run
```

# Deploying in cluster

 1. export IMG=quay.io/dgoodwin/cloud-credential-operator:latest
   * You can upload to a personal repo if you wish to build images from source.
 1. make buildah-push
 1. make deploy

Cred Minter should now be running in openshift-cloud-credential-operator.

# Obtaining Credentials

A sample credentials request looks like:

```yaml
apiVersion: cloudcredential.openshift.io/v1beta1
kind: CredentialsRequest
metadata:
  name: openshift-image-registry
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: installer-cloud-credentials
    namespace: openshift-image-registry
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1beta1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      - s3:CreateBucket
      - s3:DeleteBucket
      resource: "*"
```

Once created, assuming admin credentials are available, the controller will provision a user, access key, and user policy in AWS. The access and secret key will be stored in the target secret specified above.

Target secrets can be in another namespace, as it would need to be to be used by pods. If this namespace does not yet exist, the controller will immediately sync when it sees that namespace being created.

You can freely edit a CredentialsRequest to adjust permissions and the controller will reconcile those changes out to the respective user policy. (assuming admin credentials)

## For OpenShift Components

 1. This repo is to be the central repository for the definition of all CredentialsRequests needed for OpenShift components.
 1. YAML definitions live in the  manifests/ directory with the "03-cred-" prefix.
 1. All OpenShift CredentialsRequests should be created in openshift-cloud-credential-operator namespace.
 1. These will be deployed with the cloud-credential-operator via the release image payload.

# Future Work

  1. Integration with the OpenShift Installer.
  1. Cred Minter Operator.
  1. CI + dist-git image publishing.

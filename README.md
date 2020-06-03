# OpenShift Credentials Minter

Cred Minter is a controller that will sync on a CredentailsRequest custom
resource definition. CredentialsRequests allow OpenShift components to
request fine grained credentials for a particular cloud provider.

## About

OpenShift is transitioning to a model where components that require cloud credentials are given generated fine grained credentials with permissions only for the specific operations that component needs. (as opposed to using the admin credentials, or elevated permissions granted via instance roles)

The OpenShift installer will validate the users credentials, and the user has two options:

 1. Install with administrator credentials. (technically only the ability to grant additional credentials is required but administrator is likely the most logical way to grant this as if you can create credentials, you are an administrator) This is the recommended best path. These credentials can be removed from the cluster until changes to your credentials are required, likely for an upgrade, at which point they need to be restored.
 1. Install with a set of credentials that has *all* permissions needed for *all* OpenShift components. If this path is taken, those credentials will be shared by all components, as the credential operator cannot mint new credentials. The master list of all required permissions is assembled (manually) from the credentials requests defined in the various manifests/ dirs for the OpenShift components that depend on the credential operator.

If the installer finds that the credentials in use fit neither of these two options, it will fail, as the cluster will not function.

NOTE: at present, only some components have transitioned to this new model, the rest are expected to follow in the coming release.

## Design Principles

  * The controller should be able to run in either a cluster itself, or in a centralized management cluster, most likely along side [Hive](https://github.com/openshift/hive).
  * Controller expects access to a set of credentials we refer to as the "admin" credentials.
  * If the admin credentials are missing, but all credentials requests are fulfilled and valid, this is considered a valid state. (i.e. the admin creds were removed from the cluster after use)
  * If the admin credentials are able to create additional credentials, we will create fine grained permissions as defined in the credentials request. (best practice)
  * If the admin credentials cannot create additional credentials, but do themselves fulfill the requirements of the credentials request, they will be used. (with logged warnings and a condition on the credentials request)
  * If the admin credentials fulfill neither of the above requirements, the controller will fail to generate the credentials, report failure back to the Cluster Version Operator, and thus block upgrading. The installer will also perform this check early to inform the user their cluster will not function.

## Cloud Credentials
If running in-cluster, your credentials are expected to exist in kube-system namespace.
Credentials stored in a secret that is created per deployment infrastructure.
Here are the available options:
  1. AWS:
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
  2. Azure:
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
  3. GCP:
  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    namespace: kube-system
    name: gcp-credentials
  data:
    service_account.json: Base64encodeServiceAccount
  ```
  4. OpenStack:
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
  5. Ovirt:
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
  6. VSphere:
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

# Running from source

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

# Deploying in cluster

 1. export IMG=quay.io/dgoodwin/cloud-credential-operator:latest
   * You can upload to a personal repo if you wish to build images from source.
 1. make buildah-push
 1. make deploy

Cred Minter should now be running in openshift-cloud-credential-operator.

# Obtaining Credentials

In order to obtain credentials you need to create a credentials request.
Credentials request constists of: 
 1. secretRef - Points to the secret where the credentials should be stored once generated. 
  * secretRef can be in another namespace, as it would need to be used by pods.
  * If secretRef's namespace does not yet exist, the controller will immediately sync when it sees that namespace being created.
 2. providerSpec - Contains the cloud provider specific credentials specification.
  * See in APIs: https://github.com/jeniawhite/cloud-credential-operator/tree/master/pkg/apis/cloudcredential/v1

Examples of credentials request for the different platforms:
  1. AWS:
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
  Once created, assuming admin credentials are available, the controller will provision a user, access key, and user policy in AWS. The access and secret key will be stored in the target secret specified above.
  
  You can freely edit a CredentialsRequest to adjust permissions and the controller will reconcile those changes out to the respective user policy. (assuming admin credentials)

  2. Azure:
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

## For OpenShift Components

 1. Add CredentialsRequests objects to your CVO manifests and deployed via the release payload. Please do not create them in operator code as we want to use the release manifest for auditing and dynamically checking permissions.
 1. The cred operator launches early (runlevel 30) so should be available when your component comes up and issues it's credentials request.
 1. Your CredentialsRequests should be created in the openshift-cloud-credential-operator namespace.
 1. Your component should tolerate the credentials secret not existing immediately.

# Adding A New Cloud Provider

This repository uses an actuator pattern to allow plugging in additional cloud providers.

The rough steps to add a new cloud provider would be:

 1. Update the API to cover how credentials/permissions are defined on the new provider. (see AWS types [here](https://github.com/openshift/cloud-credential-operator/blob/master/pkg/apis/cloudcredential/v1/aws_types.go)) These types are embedded into the main CredentialsRequest as a RawExtension.
 1. Implement the very simple [Actuator interface](https://github.com/openshift/cloud-credential-operator/blob/master/pkg/controller/credentialsrequest/actuator/actuator.go). ([AWS implementation](https://github.com/openshift/cloud-credential-operator/tree/master/pkg/aws/actuator))
 1. Instantiate your actuator when we detect we're running on that cloud provider, which happens in the [AddToManager](https://github.com/openshift/cloud-credential-operator/blob/master/pkg/controller/controller.go#L49) function.
 1. Coordinate with OpenShift teams who use and ship CredentialsRequests. (machine-api, registry, ingress)

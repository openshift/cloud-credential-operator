Cloud Credential Operator can be disabled prior to install in environments where the cloud IAM APIs are not reachable.

  * Clone a release image so we can layer in our modification to disable the cloud credential operator at install time:
    * `export ctr=$(buildah from registry.svc.ci.openshift.org/ocp/release:4.3.0-0.ci-2019-10-28-103949)`
  * Create a local file with the new contents of the configmap we want, the only change here is disabled=true.
    * ```apiVersion: v1
kind: ConfigMap
metadata:
  name: cloud-credential-operator-config
  namespace: openshift-cloud-credential-operator
  annotations:
    release.openshift.io/create-only: "true"
data:
  disabled: "true"
```
  * Add our custom manifest file to overwrite the original:
    * `buildah add $ctr configmap.yaml release-manifests/0000_50_cloud-credential-operator_01_operator_configmap.yaml`
  * Commit the new image and push to a registry:
    * `buildah commit "$ctr" quay.io/myuser/origin-release:latest`
    * `buildah push quay.io/myuser/origin-release:latest`
  * Identify all CredentialsRequests in your release image that target the cloud you are deploying on. You will need to manually create credentials that provide the permissions in each of these requests, base64 encode them, and store them in secrets with the name and namespace defined in the CredentialsRequest target secret.
    * It may help to extract these locally to grep, but an example is provided below. (i.e. `oc adm release extract registry.svc.ci.openshift.org/ocp/release:4.3.0-0.ci-2019-10-23-103858`, and then grep for "CredentialsRequest")
  * Create credentials in AWS with permissions matching each CredentialsRequest. It is possible (though not ideal) to use one set of credentials for all components if desired.
  * Create the required secrets as installer manifests, as we do not want to bake credentials into a published release image.
    * `OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE=quay.io/myuser/origin-release:latest ./bin/openshift-install create manifests --dir=clusters/aws`
    * Add a Secret yaml file to the clusters manifests dir for each CredentialsRequest identified in the step above. Each access key ID and secret access key should be base64 encoded.
```
$ cat mycluster/manifests/openshift-image-registry.yaml
apiVersion: v1
data:
  aws_access_key_id: redacted
  aws_secret_access_key: redacted
kind: Secret
metadata:
  name: installer-cloud-credentials
  namespace: openshift-image-registry
type: Opaque

$ cat mycluster/manifests/openshift-ingress-operator.yaml
apiVersion: v1
data:
  aws_access_key_id: redacted
  aws_secret_access_key: redacted
kind: Secret
metadata:
  name: cloud-credentials
  namespace: openshift-ingress-operator
type: Opaque

$ cat clusters/aws/openshift-machine-api.yaml
apiVersion: v1
data:
  aws_access_key_id: redacted
  aws_secret_access_key: redacted
kind: Secret
metadata:
  name: aws-cloud-credentials
  namespace: openshift-machine-api
type: Opaque
```
  * Create your cluster: `OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE=quay.io/myuser/origin-release:latest ./bin/openshift-install create cluster --dir=clusters/aws`

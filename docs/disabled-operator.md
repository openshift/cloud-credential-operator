Cloud Credential Operator can be disabled prior to install in environments where the cloud IAM APIs are not reachable.

  * Run the OpenShift installer to generate manifests:
    * `openshift-install create manifests --dir=mycluster`
  * Insert a ConfigMap into the manifests directory so the the Cloud Credential Operator will be disabled:
    * ```
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name: cloud-credential-operator-config
        namespace: openshift-cloud-credential-operator
        annotations:
          release.openshift.io/create-only: "true"
      data:
        disabled: "true"
      ```
  * Identify all CredentialsRequests in your release image that target the cloud you are deploying on. You will need to manually create credentials that provide the permissions in each of these requests, base64 encode them, and store them in secrets with the name and namespace defined in the CredentialsRequest target secret.
    * It may help to extract these locally to grep, but an example is provided below. (i.e. `oc adm release extract registry.svc.ci.openshift.org/ocp/release:4.3.0-0.ci-2019-10-23-103858`, and then grep for "CredentialsRequest")
  * Create credentials in AWS with permissions matching each CredentialsRequest. It is possible (though not ideal) to use one set of credentials for all components if desired.
  * Create the required secrets as installer manifests, as we do not want to bake credentials into a published release image.
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

$ cat mycluster/manifests/openshift-machine-api.yaml
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
  * Create your cluster by running the OpenShift installer: `openshift-install create cluster --dir=mycluster`

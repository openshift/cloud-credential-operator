# Manual Mode

Cloud Credential Operator can be put into manual mode prior to install in environments where the cloud IAM APIs are not reachable, or the administrator simply prefers not to store an admin level credential Secret in the cluster kube-system Namespace.

Run the OpenShift installer to generate manifests:

```bash
$ openshift-install create manifests --dir=mycluster
```

Insert a ConfigMap into the manifests directory so the the Cloud Credential Operator will be be placed in manual mode:

```bash
$ cat <<EOF > mycluster/manifests/cco-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloud-credential-operator-config
  namespace: openshift-cloud-credential-operator
  annotations:
    release.openshift.io/create-only: "true"
data:
  disabled: "true"
EOF
```

Remove the admin credential secret created using your local cloud credentials. This will prevent your admin credential from ever being stored in the cluster.

```bash
$ rm mycluster/openshift/99_cloud-creds-secret.yaml
```

Obtain the OpenShift release image your openshift-install binary is built to use:

```bash
$ bin/openshift-install version
release image quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64
```

Now you must locate all CredentialsRequests in this release image that target the cloud you are deploying on.

```bash
$ oc adm release extract quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64 --to ./release-image
```

To locate the CredentialsRequests in the extracted file you can run a command such as:

```bash
$ grep -l "apiVersion: cloudcredential.openshift.io" * | xargs cat
```

NOTE: there will soon be an oc adm release command to scan for these and display them (4.6)

This displays the details for each request. Remember to ignore any CredentialsRequests where the spec.providerSpec.kind does not match the cloud provider you will be installing to.

Sample CredentialsRequest:

```yaml
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: cloud-credential-operator-iam-ro
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: cloud-credential-operator-iam-ro-creds
    namespace: openshift-cloud-credential-operator
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      - iam:GetUser
      - iam:GetUserPolicy
      - iam:ListAccessKeys
      resource: "*"
```

You must now create Secret yaml files in your openshift-install manifests directory generated earlier. The Secrets must be stored in the namespace and name defined in each request.spec.secretRef. The format for the Secret data varies by cloud provider, please see the [Admin Credentials Secret Format](../README.md) in the README for examples.

### Azure Credentials Secret Format

On Azure, the Credentials Secret Format includes two properties which must contain the cluster's infrastructure ID, generated randomly for each cluster install. This value can be found after running create manifests:

```bash
$ cat .openshift_install_state.json | jq '."*installconfig.ClusterID".InfraID' -r
mycluster-2mpcn
```

This value would be used in the secret data as follows:

```yaml
azure_resource_prefix: mycluster-2mpcn
azure_resourcegroup: mycluster-2mpcn-rg
```

## Create Your Cluster

Finally, proceed with cluster creation:

```bash
$ openshift-install create cluster --dir=mycluster
```

It is important to note that before performing an upgrade, you may need to adjust your credentials if permissions have changed in the next release. In the future, the Cloud Credential Operator may prevent you from upgrading until you have indicated that you have addressed updated permissions.

## Upgrades

In OpenShift 4.6+ we plan to add additional code to help prevent situations where a user may enter an upgrade that will fail because their manually maintained credentials have not been updated to match the CredentialsRequests in the upcoming release image. In the meantime we are monitoring to ensure no upgrade breaking credentials changes go in.

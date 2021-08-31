# Manual Mode

Cloud Credential Operator can be put into manual mode prior to install in environments where the cloud IAM APIs are not reachable, or the administrator simply prefers not to store an admin level credential Secret in the cluster kube-system Namespace. Depending on the cluster's cloud credentials configuration (eg AWS STS, GCP workload identity, etc), the `ccoctl` [tool](https://github.com/openshift/cloud-credential-operator/blob/master/docs/ccoctl.md) may help automate many of these steps.

Run the OpenShift installer to generate manifests:

```bash
$ openshift-install create install-config --dir=mycluster
```

Indicate that the cluster should be set up for Manual mode:

```bash
$ echo "credentialsMode: Manual" >> ./mycluster/install-config.yaml
```

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

## Upgrades

It is important to note that before performing an upgrade from one minor version to the next (ie 4.7.x to 4.8.y), you may need to adjust your credentials if permissions have changed in the next release. The Cloud Credential Operator will mark itself Upgradeable=False when configured for Manual mode until you have completed the following steps. The Upgradeable=False status *does not* affect z-stream upgrades (ie 4.7.4 to 4.7.5).

> Note: As noted above, the `ccoctl` [tool](https://github.com/openshift/cloud-credential-operator/blob/master/docs/ccoctl.md) can help automate many of these steps if your cloud credentials configuration is supported by the tool.

Before upgrade from one minor version to the next, the cluster admin(s) should review the bundle of CredentialsRequest objects from the version being upgraded to. First extract the CredentialsRequest objects for the cluster's cloud:

```bash
$ oc adm release extract --credentials-requests --cloud=aws|azure|gcp quay.io/openshift-release-dev/ocp-release:4.8.3-x86_64
```

Review each extracted CredentialsRequests and ensure the appropriate permissions are granted to each set of credentials held in each Secret. Create new Secrets/credentials in the cluster in the appropriate namespace for any new components requiring cloud credentials in the OpenShift release being upgraded to.

One the list of CredentialsRequests has been processed and/or verified, signal to the cluster that it is safe to upgrade by applying the appropriate annotation to the Cloud Credential Operator's config resource:

```bash
oc patch cloudcredential.operator.openshift.io/cluster --patch '{"metadata":{"annotations": {"cloudcredential.openshift.io/upgradeable-to": "4.8"}}}' --type=merge
```

Set the "upgradeable-to" annotation value to correspond with the OpenShift minor version that the admin has prepared the cluster's cloud credentials for.

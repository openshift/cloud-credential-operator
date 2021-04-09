# Cloud Credential Operator utility

To assist with the creating and maintenance of cloud credentials from outside of the cluster (necessary when CCO is put in "Manual" mode), the `ccoctl` tool provides various commands to help with the creation and management of cloud credentials.

## AWS

### Global flags

By default, the tool will output to the directory the command(s) were run in. To specify a directory, use the `--output-dir` flag.

Commands which would otherwise make AWS API calls can be passed the `--dry-run` flag to have `ccoctl` place JSON files on the local filesystem instead of creating/modifying any AWS resources. These JSON files can be reviewed/modified and then applied with the aws CLI tool (using the `--cli-input-json` parameters).

### Creating RSA keys

To generate keys for use when setting up the cluster's OpenID Connect provider, run

```bash
$ ccoctl aws create-key-pair
```

This will write out public/private key files named `serviceaccount-signer.private` and `serviceaccount-signer.public`.

### Creating OpenID Connect Provider

To set up an OpenID Connect provider in the cloud, run

```bash
$ ccoctl aws create-identity-provider --name=<name> --region=<aws-region> --public-key=/path/to/public/key/file

```

where `name` is the name used to tag and account any cloud resources that are created. `region` is the aws region in which cloud resources will be created and `public-key` is the path to a public key file generated using `ccoctl create-key-pair` command.

The above command will write out discovery document file named `02-openid-configuration` and JSON web key set file named `03-keys.json` when `--dry-run` flag is set.

### Creating IAM Roles

To create IAM Roles for each in-cluster component, you need to first extract the list of CredentialsRequest objects from the OpenShift release image

```bash
$ oc adm release extract --credentials-requests --cloud=aws --to=./credrequests quay.io/path/to/openshift-release:version
```

Then you can use `ccoctl` to process each CredentialsRequest object in the `./credrequests` directory (from the example above)

```bash
$ ccoctl aws create-iam-roles --name=<name> --region=<aws-region> --credentials-requests-dir=<path-to-directory-with-list-of-credentials-requests> --identity-provider-arn=<arn-of-identity-provider-created-in-previous-step>
```

This will create one IAM Role for each CredentialsRequest with a trust policy tied to the provided Identity Provider, and a permissions policy as defined in each CredentialsRequest object from the OpenShift release image.

It will also populate the `<output-dir>/manifests` directory with Secret files for each CredentialsRequest that was processed. These can be provided to the installer so that the appropriate Secrets are available for each in-cluster component needing to make cloud API calls.

### Creating all the required resources together

To create all the above mentioned resources in one go, run

```bash
$ oc adm release extract --credentials-requests --cloud=aws --to=./credrequests quay.io/path/to/openshift-release:version
```

Then you can use `ccoctl` to process all CredentialsRequest objects in the `./credrequests` directory (from the example above)

```bash
$ ccoctl aws create-all --name=<name> --region=<aws-region> --credentials-requests-dir=<path-to-directory-with-list-of-credentials-requests>
```

### Deleting resources

To delete resources created by ccoctl, run

```bash
$ ccoctl aws delete --name=<name> --region=<aws-region>

```

where `name` is the name used to tag and account any cloud resources that were created. `region` is the aws region in which cloud resources were created.

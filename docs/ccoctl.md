# Cloud Credential Operator utility

To assist with the creating and maintenance of cloud credentials from outside the cluster (necessary when CCO is put in "Manual" mode), the `ccoctl` tool provides various commands to help with the creation and management of cloud credentials.

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
$ ccoctl aws create-identity-provider --name=<name> --region=<aws-region> --public-key-file=/path/to/public/key/file

```

where `name` is the name used to tag and account any cloud resources that are created. `region` is the aws region in which cloud resources will be created and `public-key-file` is the path to a public key file generated using `ccoctl aws create-key-pair` command.

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

## GCP

### Global flags

By default, the tool will output to the directory the command(s) were run in. To specify a directory, use the `--output-dir` flag.

Commands which would otherwise make GCP API calls can be passed the `--dry-run` flag to have `ccoctl` place bash scripts on the local filesystem instead of creating/modifying any GCP resources. These scripts can be reviewed/modified and then run to create cloud resources.

### Creating RSA keys

To generate keys for use when setting up the cluster's OpenID Connect provider, run

```bash
$ ccoctl gcp create-key-pair
```

This will write out public/private key files named `serviceaccount-signer.private` and `serviceaccount-signer.public`.

### Creating Workload Identity Pool

To set up a workload identity pool in the cloud, run 

```bash
$ ccoctl gcp create-workload-identity-pool --name=<name> --project=<gcp-project-id>
```

where `name` is the name prefix for any cloud resources that are created. `project` is the ID of the gcp project.

### Creating Workload Identity Provider

To set up a Workload Identity Provider in the cloud, run

```bash
$ ccoctl gcp create-workload-identity-provider --name=<name> --region=<gcp-region> --project=<gcp-project-id> --public-key-file=/path/to/public/key/file --workload-identity-pool=<pool-id>
```

where `name` is the name prefix for any cloud resources that are created. `region` is the gcp region in which the Google Cloud Storage will be created. `project` is the ID of the gcp project. `workload-identity-pool` is the ID of the pool created using `ccoctl gcp create-workload-identity-pool`. The new provider will be created in this pool.

The above command will write out discovery document file named `02-openid-configuration` and JSON web key set file named `03-keys.json` when `--dry-run` flag is set.


### Creating IAM Service Accounts

To create IAM Service Account for each in-cluster component, you need to first extract the list of CredentialsRequest objects from the OpenShift release image

```bash
$ oc adm release extract --credentials-requests --cloud=gcp --to=./credrequests quay.io/path/to/openshift-release:version
```

Then you can use `ccoctl` to process each CredentialsRequest object in the `./credrequests` directory (from the example above)

```bash
$ ccoctl gcp create-service-accounts --name=<name> --project=<gcp-project-id> --credentials-requests-dir=<path-to-directory-with-list-of-credentials-requests> --workload-identity-pool=<pool-id> --workload-identity-provider=<provider-id>
```

where `name` is the name prefix for any cloud resources that are created. `project` is the ID of the gcp project. `public-key-file` is the path to a public key file generated using `ccoctl gcp create-key-pair` command. `workload-identity-pool` is the ID of the pool created using `ccoctl gcp create-workload-identity-pool` command. `workload-identity-provider` is the ID of the provider created using `ccoctl gcp create-workload-identity-provider` command.

This will create one IAM Service Account for each CredentialsRequest along with appropriate project policy bindings as defined in each CredentialsRequest object from the OpenShift release image.

It will also populate the `<output-dir>/manifests` directory with Secret files for each CredentialsRequest that was processed. These can be provided to the installer so that the appropriate Secrets are available for each in-cluster component needing to make cloud API calls.

### Creating all the required resources together

To create all the above mentioned resources in one go, run

```bash
$ oc adm release extract --credentials-requests --cloud=gcp --to=./credrequests quay.io/path/to/openshift-release:version
```

Then you can use `ccoctl` to process all CredentialsRequest objects in the `./credrequests` directory (from the example above)

```bash
$ ccoctl gcp create-all --name=<name> --region=<gcp-region> --project=<gcp-project-id> --credentials-requests-dir=<path-to-directory-with-list-of-credentials-requests>
```

### Deleting resources

To delete resources created by ccoctl, run

```bash
$ ccoctl gcp delete --name=<name> --project=<gcp-project-id>

```

where `name` is the name prefix used to create cloud resources. `project` is the ID of the gcp project.

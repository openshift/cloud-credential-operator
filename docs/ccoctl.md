# Cloud Credential Operator utility

To assist with the creating and maintenance of cloud credentials from outside of the cluster (necessary when CCO is put in "Manual" mode), the `ccoctl` tool provides various commands to help with the creation and management of cloud credentials.

## Global flags

By default, the tool will output to the directory the command(s) were run in. To specify a directory, use the `--output-dir` flag.

## Creating RSA keys

To generate keys for use when setting up the cluster's OpenID Connect provider, run

```bash
$ ccoctl create key-pair
```

This will write out public/private key files named `serviceaccount-signer.private` and `serviceaccount-signer.public`.

## Creating OpenID Connect Provider

To set up an OpenID Connect provider in the cloud, run

```bash
$ ccoctl create identity-provider --infra-name=<infra-name> --region=<aws-region> --public-key=/path/to/public/key/file

```

where `infra-name` is the name used to tag and account cloud resources that are created. `region` is the aws region in which cloud resources will be created and `public-key` is the path to a public key file generated using `ccoctl create key-pair` command.

The above command will write out discovery document file named `oidc-configuration` and JSON web key set file named `keys.json`.

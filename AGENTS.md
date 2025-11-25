# AGENTS.md

Instructions for AI agents working on the Cloud Credential Operator project.

## Project Overview
The Cloud Credential Operator (CCO) is an OpenShift Operator that manages cloud provider credentials. It allows other Operators to request credentials with specific permissions via `CredentialsRequest` custom resources.

## Common development commands
The project uses `make` for automation.

### Development
```bash
make update # updates generated code
make build # compiles the project binaries
make clean # cleans up build artifacts
```

### Testing
```bash
make test # runs unit tests
make verify # verifies generated code and formatting.
```

## Architecture

### File Structure

- **`bindata/`**: Static assets compiled into the binary (e.g., default CredentialsRequests).
- **`cmd/`**: Binary entry points
- **`docs/`**: Developer and user documentation.
- **`hack/`**: Developer tools.
- **`manifests/`**: Kubernetes YAML manifests for deploying the operator.
- **`pkg/`**: Package Source Code
- **`test/`**: Code additional testing

#### Entry Points (`cmd/`)
- **`cmd/cloud-credential-operator/`**: Main entry point for the operator.
- **`cmd/ccoctl/`**: CLI tool for creating and managing cloud credentials outside the cluster.

#### Package Source Code (`pkg/`)
- **`pkg/apis/`**: Kubernetes Custom Resource Definitions (CRDs) and API types.
- **`pkg/assets/`**: Generated assets.
- **`pkg/cmd/`**: Logic for command-line commands.
- **`pkg/operator/`**: Operator Controllers.
- **`pkg/{aws,azure,gcp,ibmcloud,kubevirt,openstack,ovirt,vsphere}/`**: Cloud provider-specific implementations.
- **`pkg/util/`**: Utility functions.
- **`pkg/version/`**: Logic for Operator version.

#### Operator Controllers (`pkg/operator/`)
- **`pkg/operator/cleanup`**: Cleans up stale `CredentialRequests`
- **`pkg/operator/credentialsrequest`**: Reconciles CredentialRequests, creating and updating cloud credentials as necessary while ensuring the associated Kubernetes secret remains up to date.
- **`pkg/operator/loglevel`**: Ensures the Operator is using the latest log level as specified in the operator config manifest.
- **`pkg/operator/metrics`**: Calculates and publishes Prometheus metrics.
- **`pkg/operator/podidentity`**: Ensures the pod identity webhook is deployed when appropriate.
- **`pkg/operator/secretannotator`**: Ensures the `cloudcredential.openshift.io/mode` annotation is set on the root credential secret based on the credentials mode and permissions granted to the cloud credential specified in the root credential.
- **`pkg/operator/status`**: Reconciles the status (`Available`, `Degraded`, `Progressing`, and `Upgradeable`) of the Operator based on the status of all CredentialRequests.

### Operator Modes
The actions preformed by the operator for each `CredentialRequest` is based on the mode of the operator.

- **`Manual`** The operator will not manage cloud credentials or associated secrets.
- **`Mint`**: The operator will create and manage cloud credentials and associated secrets.
- **`Passthrough`**: The operator will reuse the root credential for all associated secrets.

### Short Term Tokens
When in Manual mode, the operator can be further configured to integrate with cloud providers using short term token authentication (OIDC). The `ccoctl` binary is designed to run off of the cluster. It configures the cloud credentials requested by the `CredentialRequests` and produces the secret manifests that are to be applied to the cluster.

## Git Commit Instructions
- All commits should follow a standard format to ensure clarity and traceability.
- Title format: <Subsystem>: <Title>
- Include a footer annotation when AI tools were used to generate or significantly assist.

### Example
```text
ccoctl: Add support for new cloud provider region

This updates the AWS provider to support the new region by adding it to the
validation list and updating the relevant constants.

Assisted-by: <AI Model Name>`
```

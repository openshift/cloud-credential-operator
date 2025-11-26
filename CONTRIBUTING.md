# Contributing to Cloud Credential Operator

Thank you for your interest in contributing to the Cloud Credential Operator (CCO)! We welcome contributions from the community.

## Project Overview

The Cloud Credential Operator is an OpenShift Operator that manages cloud provider credentials. It allows other Operators to request credentials with specific permissions via `CredentialsRequest` custom resources.

For a detailed design overview and modes of operation, please refer to the [README.md](README.md).

## Getting Started

### Prerequisites

- Go (version specified in `go.mod`)
- Make

### Development Environment

You can build the project binaries using the provided `make` targets.

```bash
# Update generated code
make update

# Compile the project binaries
make build

# Clean up build artifacts
make clean
```

## Testing

Before submitting a Pull Request, ensure that all tests pass and the code is verified.

```bash
# Verify generated code and formatting
make verify

# Run unit tests
make test
```

## Project Structure

Understanding the project structure will help you navigate the codebase:

- **`bindata/`**: Static assets compiled into the binary.
- **`cmd/`**: Binary entry points.
  - `cmd/cloud-credential-operator/`: Main operator entry point.
  - `cmd/ccoctl/`: CLI tool for managing credentials outside the cluster.
- **`docs/`**: Developer and user documentation.
- **`hack/`**: Developer scripts and tools.
- **`manifests/`**: Kubernetes YAML manifests for deploying the operator.
- **`pkg/`**: Package source code.
  - `pkg/apis/`: Kubernetes CRDs and API types.
  - `pkg/operator/`: Operator controllers logic.
  - `pkg/{aws,azure,gcp,ibmcloud,kubevirt,openstack,ovirt,vsphere}/`: Cloud provider-specific implementations.

## Pull Requests

### Commit Messages

All git commits should follow a standard format to ensure clarity and traceability.

**Title format**: `<Subsystem>: <Title>`

**Example**:
```text
ccoctl: Add support for new cloud provider region

This updates the AWS provider to support the new region by adding it to the
validation list and updating the relevant constants.
```

### AI Attribution

If AI tools were used to generate or significantly assist with the code or documentation, please include a footer annotation in the commit message:

```text
Assisted-by: <AI Model Name>
```

### Submission Checklist

- [ ] Run `make update` to ensure generated code is up to date.
- [ ] Run `make test` to ensure no regressions.
- [ ] Run `make verify` to ensure code formatting and standards.
- [ ] Ensure commit messages follow the project standards.


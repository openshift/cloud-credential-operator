# Cloud Credential Operator - Development Guide

> **Generic Development Practices**: See [Tier 1 Development Practices](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/development) for Go standards, controller-runtime patterns, and CI/CD workflows.

This guide covers **CCO-specific** development practices.

## Quick Start

### Prerequisites

- Go 1.23+ (check go.mod for exact version)
- Access to OpenShift cluster with cloud provider (AWS, Azure, GCP, etc.)
- `KUBECONFIG` environment variable set
- Container build tool (Podman or Docker)
- Cloud credentials for testing (AWS, Azure, or GCP)

### Build Binaries

```bash
# Build operator
make build

# Build ccoctl CLI
make ccoctl

# Build all binaries
make cloud-credential-operator ccoctl cloud-credential-tests-ext

# Or use go directly
go build -o _output/cloud-credential-operator ./cmd/cloud-credential-operator
go build -o _output/ccoctl ./cmd/ccoctl
```

**Binaries output**: `./_output/` or build in place

## Repository Structure

```text
cmd/
├── cloud-credential-operator/  # Main operator binary
├── ccoctl/                     # Off-cluster CLI tool
└── cloud-credential-tests-ext/ # Extended test suite

pkg/
├── operator/                   # Controllers
│   ├── credentialsrequest/     # Core CredentialsRequest controller
│   ├── secretannotator/        # Root secret annotator
│   ├── status/                 # ClusterOperator status
│   ├── cleanup/                # Stale CR cleanup
│   ├── podidentity/            # Pod identity webhook
│   ├── awspodidentity/         # AWS-specific pod identity
│   ├── loglevel/               # Log level sync
│   └── metrics/                # Prometheus metrics
├── aws/                        # AWS actuator & ccoctl
├── azure/                      # Azure actuator & ccoctl
├── gcp/                        # GCP actuator & ccoctl
├── ibmcloud/                   # IBM Cloud actuator
├── kubevirt/                   # KubeVirt actuator
├── openstack/                  # OpenStack actuator
├── ovirt/                      # oVirt actuator
├── vsphere/                    # vSphere actuator
├── apis/cloudcredential/v1/    # CredentialsRequest CRD
├── cmd/                        # ccoctl commands
└── util/                       # Utilities

manifests/                      # Operator deployment manifests
test/                           # Test suites
bindata/                        # Embedded assets
```

## Development Workflow

### 1. Local Development

Edit code, build binaries locally:

```bash
# Update generated code (after API changes)
make update

# Build binaries
make build
```

Run unit tests:

```bash
# All unit tests
make test

# Specific package
go test -v ./pkg/operator/credentialsrequest/...

# With coverage
go test -cover ./pkg/...
```

Verify code quality:

```bash
# Run linting, formatting, vet
make verify

# Auto-fix formatting
make update
```

### 2. Testing on Cluster

**Option A: Replace running operator pod**

```bash
# Build image
podman build -t quay.io/[user]/cloud-credential-operator:dev .

# Push to registry
podman push quay.io/[user]/cloud-credential-operator:dev

# Update deployment to use dev image
oc set image deployment/cloud-credential-operator \
  cloud-credential-operator=quay.io/[user]/cloud-credential-operator:dev \
  -n openshift-cloud-credential-operator
```

**Option B: Run operator locally against cluster**

```bash
# Scale down in-cluster operator
oc scale deployment cloud-credential-operator --replicas=0 \
  -n openshift-cloud-credential-operator

# Run locally with KUBECONFIG
./_output/cloud-credential-operator \
  --kubeconfig=$KUBECONFIG \
  --namespace=openshift-cloud-credential-operator \
  --log-level=debug
```

**Testing ccoctl**:

```bash
# Build ccoctl
make ccoctl

# Extract CredentialsRequests from release
oc adm release extract --credentials-requests --to ./credrequests

# Run ccoctl (example for AWS)
./_output/ccoctl aws create-all \
  --name test-cluster \
  --region us-east-1 \
  --credentials-requests-dir ./credrequests \
  --output-dir ./manifests
```

### 3. Debugging

**View operator logs**:
```bash
oc logs -f deployment/cloud-credential-operator \
  -n openshift-cloud-credential-operator
```

**Exec into operator pod**:
```bash
oc exec -it deployment/cloud-credential-operator \
  -n openshift-cloud-credential-operator -- /bin/bash
```

**Debug with delve**:
```bash
# Build with debug symbols
go build -gcflags="all=-N -l" -o _output/cloud-credential-operator \
  ./cmd/cloud-credential-operator

# Run with delve
dlv exec ./_output/cloud-credential-operator -- \
  --kubeconfig=$KUBECONFIG \
  --namespace=openshift-cloud-credential-operator
```

**Check CredentialsRequest status**:
```bash
# List all CredentialsRequests
oc get credentialsrequests -A

# Describe specific CR
oc describe credentialsrequest [name] -n openshift-cloud-credential-operator

# Check ClusterOperator status
oc get clusteroperator cloud-credential -o yaml
```

## Code Organization

### Controllers

Location: `pkg/operator/[name]/`

**Key Controllers**:
- **credentialsrequest**: Core logic for provisioning cloud credentials
- **secretannotator**: Annotates root credential secret with detected mode
- **status**: Aggregates CR statuses to ClusterOperator
- **cleanup**: Removes stale CredentialsRequests
- **podidentity**: Deploys pod identity webhook (Manual + OIDC mode)

**Pattern**:
- `controller.go` - Controller setup, watches, Add() function
- `actuator.go` - Reconcile logic (credentialsrequest only)
- `*_test.go` - Unit tests

**Generic controller patterns**: See [Tier 1](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/controller-runtime.md)

### Cloud Provider Actuators

Location: `pkg/{aws,azure,gcp,...}/`

Each cloud provider has:
- `actuator.go` - Implements `Actuator` interface (Create, Update, Delete, Exists)
- `types.go` - Cloud-specific ProviderSpec types
- `*_test.go` - Unit tests with mocked cloud APIs

**Adding new provider**:
1. Create `pkg/[provider]/actuator.go` implementing `Actuator` interface
2. Add provider types in `pkg/apis/cloudcredential/v1/types_[provider].go`
3. Register actuator in `pkg/operator/credentialsrequest/actuator.go`
4. Add ccoctl support in `pkg/cmd/[provider]/`

### ccoctl Commands

Location: `pkg/cmd/[provider]/`

Each cloud provider has ccoctl commands:
- `create_all.go` - Main command to create OIDC provider + IAM roles
- `create_iam_roles.go` - Create IAM roles
- `create_oidc_provider.go` - Create OIDC provider

Commands use cobra framework; registered in `cmd/ccoctl/main.go`.

## Common Tasks

### Add New CRD Field

1. Edit `pkg/apis/cloudcredential/v1/types_*.go`
2. Add field to spec or status struct
3. Run `make update` to regenerate code
4. Update controller logic to handle new field
5. Add tests

Example:
```go
// In types_credentialsrequest.go
type CredentialsRequestSpec struct {
    // ... existing fields ...
    NewField string `json:"newField,omitempty"`
}
```

### Add New Controller

1. Create `pkg/operator/[name]/controller.go`
2. Implement controller setup and Reconcile logic
3. Register in `cmd/cloud-credential-operator/main.go`:
   ```go
   import "[name]controller" "github.com/openshift/cloud-credential-operator/pkg/operator/[name]"
   
   // In main()
   if err := [name]controller.Add(mgr, cfg); err != nil {
       return err
   }
   ```
4. Add unit tests in `pkg/operator/[name]/*_test.go`
5. Add E2E tests in `test/e2e/`

### Add Cloud Provider Support

1. Create `pkg/[provider]/actuator.go` implementing `Actuator`
2. Add provider types in `pkg/apis/cloudcredential/v1/types_[provider].go`
3. Update mode detection in `pkg/operator/credentialsrequest/actuator.go`
4. Add ccoctl commands in `pkg/cmd/[provider]/`
5. Add tests with mocked cloud APIs
6. Update documentation

### Update Dependencies

```bash
# Update specific dependency
go get k8s.io/client-go@v0.XX.Y

# Update all dependencies
go get -u ./...

# Tidy and vendor
go mod tidy
go mod vendor

# Regenerate generated code
make update
```

## Build & Release

### Local Build

```bash
# Build operator image
podman build -t cloud-credential-operator:local .

# Build ccoctl only (standalone binary)
make ccoctl
```

### CI Build

CCO images are built by OpenShift CI (Prow) on PR merge.

**Configuration**: `.ci-operator.yaml`, `Dockerfile`

**Images produced**:
- `cloud-credential-operator` - Operator image
- `ccoctl` - Extracted via `oc adm release extract --command=ccoctl`

### Release Process

CCO is released as part of OpenShift release image. See [OpenShift Release Process](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/development).

**Release artifacts**:
- Operator runs in `openshift-cloud-credential-operator` namespace
- ccoctl binary embedded in release image

## Component-Specific Notes

### Cloud Credentials for Testing

**AWS**:
- Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` env vars
- Or use `~/.aws/credentials`

**Azure**:
- Set `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
- Or use `az login`

**GCP**:
- Set `GOOGLE_APPLICATION_CREDENTIALS` to service account key file
- Or use `gcloud auth application-default login`

### Mode Detection Logs

To see mode detection, check operator logs at startup:
```bash
oc logs deployment/cloud-credential-operator -n openshift-cloud-credential-operator | grep -i mode
```

### Working with CredentialsRequests

**Create test CredentialsRequest**:
```yaml
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: test-cr
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: test-creds
    namespace: default
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action: ["s3:ListBucket"]
      resource: "*"
```

**Watch reconciliation**:
```bash
oc get credentialsrequest test-cr -w
```

### Debugging Mode Detection

If mode detection fails:
1. Check root credential secret exists (`aws-creds`, `azure-credentials`, `gcp-credentials` in `kube-system`)
2. Check cloud API connectivity (operator logs)
3. Check root credential permissions (try cloud API call manually)
4. Check `ClusterOperator/cloud-credential` status for detailed errors

### Local Development Without Cloud

For development that doesn't require cloud API calls (e.g., status controller, cleanup controller):
1. Use fake Kubernetes client in tests
2. Mock cloud actuator interface
3. Test with Manual mode (no cloud API calls)

## See Also

- [Testing Guide](./CCO_TESTING.md)
- [Architecture](./architecture/components.md)
- [CredentialsRequest CRD](./domain/credentialsrequest.md)
- [Component ADRs](./decisions/)
- [Tier 1 Development Practices](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/development)

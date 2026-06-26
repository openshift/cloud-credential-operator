# Cloud Credential Operator Architecture

Component-specific architecture for CCO. For generic operator patterns, see [Tier 1](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns.md).

## Repository Structure

```
cloud-credential-operator/
├── cmd/
│   ├── cloud-credential-operator/    # Main operator binary
│   └── ccoctl/                        # Off-cluster CLI tool
├── pkg/
│   ├── apis/cloudcredential/v1/       # CredentialsRequest CRD
│   ├── operator/                      # Controllers
│   ├── aws/                           # AWS actuator
│   ├── azure/                         # Azure actuator
│   ├── gcp/                           # GCP actuator
│   ├── ibmcloud/                      # IBM Cloud actuator
│   ├── kubevirt/                      # KubeVirt actuator
│   ├── nutanix/                       # Nutanix actuator
│   ├── openstack/                     # OpenStack actuator
│   ├── ovirt/                         # oVirt actuator
│   ├── powervs/                       # PowerVS actuator
│   ├── vsphere/                       # vSphere actuator
│   └── cmd/                           # CLI commands (ccoctl)
├── manifests/                         # Operator deployment manifests
└── test/                              # Test suites
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                  Cloud Credential Operator               │
│                                                           │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────┐ │
│  │ credentialsreq │  │ secretannotator│  │  status   │ │
│  │   controller   │  │   controller   │  │ controller│ │
│  └───────┬────────┘  └────────────────┘  └───────────┘ │
│          │                                                │
│          ├─> Mode Detection (Mint/Passthrough/Manual)    │
│          │                                                │
│          ├─> Cloud Provider Actuator                     │
│          │   ┌─────────────────────────────────────┐    │
│          └─> │ AWS │ Azure │ GCP │ IBM │ ... │     │    │
│              └─────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                          │
                          v
              ┌────────────────────────┐
              │   Cloud Provider API   │
              │  (IAM, Service Acct)   │
              └────────────────────────┘
```

## Controllers

CCO runs multiple controllers, each with specific responsibilities.

### credentialsrequest Controller

**Purpose**: Core controller that reconciles CredentialsRequest CRs.

**Reconciliation Flow**:
1. Detect cluster mode (Mint/Passthrough/Manual)
2. Select cloud provider actuator based on platform detection
3. Call actuator to provision/update credentials
4. Create/update target Secret
5. Update CredentialsRequest status

**Key Logic**:
- **Mode Detection** (`pkg/operator/credentialsrequest/actuator.go`):
  - Attempts cloud API call (can mint?)
  - Checks root credential permissions (passthrough viable?)
  - Checks if all secrets pre-exist (manual mode?)
- **Cloud Actuator** (`pkg/{aws,azure,gcp,...}/actuator.go`):
  - Provisions IAM resources (users, roles, policies, service accounts)
  - Formats credentials for target Secret
  - Handles provider-specific quirks

**Finalizer**: `cloudcredential.openshift.io/deprovision` ensures cloud resource cleanup before CR deletion.

### secretannotator Controller

**Purpose**: Annotates root credential secret with detected mode.

**Annotation**: `cloudcredential.openshift.io/mode` = `mint` | `passthrough` | `manual` | `manual-pod-identity`

**Why**: Allows other components to understand cluster credential mode without re-detecting.

### status Controller

**Purpose**: Aggregates CredentialsRequest statuses and updates ClusterOperator status.

**Logic**:
- Watches all CredentialsRequests
- Computes overall `Available`, `Degraded`, `Progressing`, `Upgradeable` conditions
- Updates `ClusterOperator/cloud-credential` resource

**Example**: If any CredentialsRequest has `CredentialsProvisionFailure`, ClusterOperator becomes `Degraded`.

### cleanup Controller

**Purpose**: Removes stale CredentialsRequests that no longer match installed components.

**Trigger**: Component removal (operator deleted)

### podidentity Controller

**Purpose**: Deploys pod identity webhook for OIDC-based authentication (Manual + OIDC mode).

**When Active**: Cluster in Manual mode with `authentication.spec.serviceAccountIssuer` configured.

**Webhook Function**: Injects cloud-specific environment variables and volume mounts into pods using annotated ServiceAccounts.

### awspodidentity Controller

**Purpose**: AWS-specific pod identity webhook configuration.

**Injects**:
- `AWS_ROLE_ARN` env var
- `AWS_WEB_IDENTITY_TOKEN_FILE` env var
- Token volume mount

### loglevel Controller

**Purpose**: Syncs operator log level from cluster OperatorConfig.

### metrics Controller

**Purpose**: Exposes Prometheus metrics:
- `cco_credentials_requests_total`
- `cco_credentials_mode` (gauge: 0=unknown, 1=mint, 2=passthrough, 3=manual)

## Modes

CCO operates in one of four modes, auto-detected at startup.

### Mint Mode

**Behavior**: Creates fine-grained cloud credentials with exact permissions from CredentialsRequest.

**Requirements**:
- Root credential has IAM creation permissions
- Examples: AWS admin with `iam:CreateUser`, Azure with Application Administrator role

**Cloud Resources Created**:
- AWS: IAM users with inline policies
- Azure: Service principals with custom role assignments
- GCP: Service accounts with IAM bindings

**Advantages**: Least-privilege credentials, credential lifecycle tied to CR lifecycle.

**Disadvantages**: Requires powerful root credential (often removed post-install).

### Passthrough Mode

**Behavior**: Copies root credential to all CredentialsRequest target secrets.

**Requirements**:
- Root credential satisfies permissions of all CredentialsRequests
- No IAM creation capability

**Advantages**: Simple, no cloud API dependency.

**Disadvantages**: All components share same credential (overprivileged), root credential cannot be removed.

### Manual Mode

**Behavior**: No credential management. User pre-provisions all secrets.

**Requirements**:
- All CredentialsRequest target secrets exist
- Secrets contain valid credentials

**Advantages**: Full control, air-gapped installs, custom credential management.

**Disadvantages**: Manual secret management burden.

### Manual + OIDC (Pod Identity)

**Behavior**: Short-lived token-based authentication. CCO creates secrets with cloud config; pods use ServiceAccount tokens.

**Requirements**:
- Cluster OIDC provider configured (`authentication.spec.serviceAccountIssuer`)
- Cloud IAM configured for OIDC (via `ccoctl`)

**Cloud Mechanisms**:
- AWS: STS AssumeRoleWithWebIdentity
- Azure: Workload Identity
- GCP: Workload Identity

**Advantages**: Zero long-lived credentials in cluster, best security posture.

**Disadvantages**: Complex setup (requires `ccoctl` + cloud IAM config).

## Cloud Provider Actuators

Each cloud provider has an actuator implementing the `Actuator` interface:

```go
type Actuator interface {
    Create(ctx context.Context, cr *CredentialsRequest) error
    Update(ctx context.Context, cr *CredentialsRequest) error
    Delete(ctx context.Context, cr *CredentialsRequest) error
    Exists(ctx context.Context, cr *CredentialsRequest) (bool, error)
}
```

### AWS Actuator (`pkg/aws/actuator.go`)

**Mint Mode**:
1. Parses `AWSProviderSpec` from CR
2. Creates IAM user with generated name
3. Attaches inline policy with requested permissions
4. Creates access key
5. Stores `aws_access_key_id` and `aws_secret_access_key` in Secret

**Manual + OIDC**:
1. Parses `stsIAMRoleARN` from `AWSProviderSpec`
2. Creates Secret with:
   - `role_arn`: IAM role ARN
   - `web_identity_token_file`: Path to projected ServiceAccount token

**Passthrough**: Copies `aws-creds` secret from `kube-system`.

### Azure Actuator (`pkg/azure/actuator.go`)

**Mint Mode**:
1. Creates service principal (app registration)
2. Assigns custom role with requested permissions
3. Generates client secret
4. Stores `azure_client_id`, `azure_client_secret`, `azure_tenant_id` in Secret

**Manual + OIDC**:
1. Creates Secret with `azure_federated_token_file` path
2. Cloud SDK uses Workload Identity Federation

**Passthrough**: Copies `azure-credentials` secret from `kube-system`.

### GCP Actuator (`pkg/gcp/actuator.go`)

**Mint Mode**:
1. Creates GCP service account
2. Grants IAM roles (from `GCPProviderSpec`)
3. Creates service account key (JSON)
4. Stores `service_account.json` in Secret

**Manual + OIDC**:
1. Creates Secret with workload identity config
2. ServiceAccount annotation links to GCP service account

**Passthrough**: Copies `gcp-credentials` secret from `kube-system`.

### Other Providers

Similar patterns for IBM Cloud, KubeVirt, Nutanix, OpenStack, oVirt, PowerVS, vSphere.

## ccoctl CLI Tool

**Location**: `cmd/ccoctl/`

**Purpose**: Off-cluster credential management for Manual + OIDC mode.

**Commands**:
- `ccoctl aws create-all`: Creates AWS OIDC provider, IAM roles, policies
- `ccoctl azure create-all`: Creates Azure workload identity resources
- `ccoctl gcp create-all`: Creates GCP workload identity bindings

**Workflow**:
1. Extract CredentialsRequests from release image
2. Create cloud IAM resources (OIDC providers, roles with trust policies)
3. Generate secret manifests with cloud config
4. User applies manifests to cluster

**Why Off-Cluster**: Manual mode means no admin credentials in cluster; `ccoctl` uses admin creds externally.

## Data Flow

### Mint Mode Flow

```
1. Component creates CredentialsRequest
2. credentialsrequest controller detects CR
3. Controller calls cloud actuator.Create()
4. Actuator creates cloud IAM resource (user/role)
5. Actuator creates Secret with credentials
6. Controller updates CR status (Provisioned: true)
7. Component uses credentials from Secret
```

### Manual + OIDC Flow

```
1. Admin runs `ccoctl <cloud> create-all` (off-cluster)
   - Creates cloud OIDC provider + IAM roles
   - Generates secret manifests
2. Admin applies secret manifests to cluster
3. Component creates CredentialsRequest (CR)
4. credentialsrequest controller detects CR
5. Controller creates/updates Secret with cloud config (role ARN, token path)
6. podidentity webhook injects env vars into component pod
7. Component pod uses ServiceAccount token + cloud config
8. Cloud SDK exchanges token for temporary credentials
```

## Platform Detection

CCO detects cloud platform via:
1. `Infrastructure.status.platformStatus.type` (primary)
2. `Infrastructure.status.platform` (legacy)
3. Node provider ID prefixes (fallback)

**Platforms**: AWS, Azure, GCP, IBMCloud, KubeVirt, Nutanix, OpenStack, oVirt, PowerVS, VSphere

## Key Decision Points

### Mode Selection

**Detection Logic** (`pkg/operator/credentialsrequest/actuator.go`):
1. Check if root secret exists
   - No → Manual mode
2. Try cloud API call (read-only)
   - Fails → Manual mode (or error)
3. Try IAM creation API
   - Success → Mint mode
4. Check root credential permissions vs all CredentialsRequests
   - Sufficient → Passthrough mode
   - Insufficient → Error (blocks upgrade)

### Secret Ownership

CCO only deletes secrets it created (has `cloudcredential.openshift.io/credentials-request` annotation). Pre-existing secrets (manual mode) are never deleted.

## Component Relationships

```
CredentialsRequest (CR)
  ├─ Referenced by Component (e.g., image-registry, ingress)
  ├─ Reconciled by credentialsrequest controller
  ├─ Target Secret created/updated
  └─ Status aggregated by status controller

Root Credential Secret (kube-system)
  ├─ Used by cloud actuators (mint/passthrough)
  ├─ Annotated by secretannotator controller
  └─ May be removed after install (mint mode only)

ClusterOperator (cloud-credential)
  └─ Status set by status controller

Pod Identity Webhook
  ├─ Deployed by podidentity controller
  └─ Mutates pods using OIDC ServiceAccounts
```

## Scalability

**CredentialsRequest Count**: Typical cluster has 10-15 CRs (one per component needing credentials).

**Reconciliation**: Each controller reconciles independently; no global locking.

**Cloud API Rate Limits**: Actuators implement backoff/retry.

## For Generic Patterns

See [Tier 1](https://github.com/openshift/enhancements/tree/master/ai-docs/practices):
- [Controller Runtime](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/controller-runtime.md)
- [Status Conditions](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/status-conditions.md)
- [Webhooks](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/webhooks.md)

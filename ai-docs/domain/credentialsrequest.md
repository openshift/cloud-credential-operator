# CredentialsRequest

**API Group**: `cloudcredential.openshift.io/v1`  
**Kind**: `CredentialsRequest`  
**Scope**: Namespaced

## Purpose

Allows OpenShift components to request fine-grained cloud credentials without using admin credentials. CCO provisions cloud-provider-specific credentials and stores them in the requested Secret.

**Key Principle**: Declarative credential management - components declare required permissions; CCO handles provisioning based on cluster mode.

## Spec Structure

```go
type CredentialsRequestSpec struct {
    SecretRef           ObjectReference  // Target secret for credentials
    ProviderSpec        *RawExtension    // Cloud-specific permissions (e.g., AWS IAM policy)
    ServiceAccountNames []string         // ServiceAccounts using these credentials (for OIDC)
    CloudTokenPath      string           // Path to mounted JWT token (for STS/Workload Identity)
}
```

## Key Concepts

### Mode-Dependent Behavior

CCO behavior depends on detected cluster mode:

- **Mint Mode**: Creates cloud IAM user/role with permissions from `ProviderSpec`, stores credentials in `SecretRef`
- **Passthrough Mode**: Copies root credential to `SecretRef` (warns if permissions exceed root)
- **Manual Mode**: No-op; user pre-provisions secret
- **Manual + OIDC**: CCO populates secret with token path and cloud config (AWS STS, Azure Workload Identity, GCP Workload Identity)

### Provider-Specific ProviderSpec

`ProviderSpec` is cloud-specific and defines requested permissions:

- **AWS**: IAM policy statements (JSON)
- **Azure**: Role definitions
- **GCP**: Predefined or custom roles

### ServiceAccount Integration (OIDC)

`ServiceAccountNames` and `CloudTokenPath` enable token-based auth:

1. Component ServiceAccount has projected token at `CloudTokenPath`
2. CCO creates secret with cloud config referencing token file
3. Cloud SDK uses token for temporary credentials (AWS STS AssumeRoleWithWebIdentity, Azure Workload Identity, GCP Workload Identity)

## Lifecycle

1. **Creation**: 
   - CCO detects mode (checks root credential capabilities)
   - Provisions credentials via cloud provider actuator
   - Creates/updates `SecretRef` secret
   - Sets `Provisioned: true` in status

2. **Update**: 
   - CCO detects spec changes (generation diff)
   - Updates cloud credentials if needed (policy changes)
   - Syncs secret
   - Updates `LastSyncTimestamp` and `LastSyncGeneration`

3. **Deletion**: 
   - Finalizer `cloudcredential.openshift.io/deprovision` ensures cleanup
   - Deletes cloud credentials (mint mode only)
   - Removes secret (if owned)
   - Removes finalizer

## Example: AWS Image Registry Credentials (Mint Mode)

```yaml
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-image-registry
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: installer-cloud-credentials
    namespace: openshift-image-registry
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      - s3:CreateBucket
      - s3:DeleteBucket
      - s3:PutBucketTagging
      - s3:GetBucketTagging
      - s3:PutObject
      - s3:GetObject
      - s3:DeleteObject
      resource: "*"
```

**Use case**: Image registry needs S3 bucket access. In mint mode, CCO creates IAM user with these exact permissions.

## Example: AWS with STS (Manual + OIDC)

```yaml
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-image-registry-sts
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: installer-cloud-credentials
    namespace: openshift-image-registry
  serviceAccountNames:
  - registry
  cloudTokenPath: /var/run/secrets/openshift/serviceaccount/token
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    stsIAMRoleARN: arn:aws:iam::123456789012:role/openshift-image-registry
    statementEntries:
    - effect: Allow
      action:
      - s3:PutObject
      - s3:GetObject
      - s3:DeleteObject
      resource: "*"
```

**Use case**: Manual mode with OIDC. `ccoctl` pre-created IAM role with trust policy for cluster OIDC provider. CCO creates secret with `role_arn` and `web_identity_token_file` for AWS SDK.

## Component-Specific Behavior

### Mode Detection

CCO auto-detects mode on startup by checking root credential capabilities:
1. Attempts to query cloud API (can mint?)
2. Checks if root credential satisfies all CredentialsRequests (passthrough?)
3. Checks if all secrets exist (manual?)

**Mode is cluster-wide** - all CredentialsRequests use the same mode.

### Finalizer Management

`FinalizerDeprovision` ensures cloud cleanup before etcd deletion. Prevents:
- Orphaned cloud IAM users (AWS)
- Orphaned service principals (Azure)
- Orphaned service accounts (GCP)

### Status Conditions

```go
type CredentialsRequestCondition struct {
    Type    CredentialsRequestConditionType  // CredentialsProvisionFailure, InsufficientCloudCreds, etc.
    Status  ConditionStatus                  // True, False, Unknown
    Reason  string                           // MachineReadable reason
    Message string                           // Human-readable detail
}
```

**Common conditions**:
- `CredentialsProvisionFailure`: Cloud API error during provisioning
- `InsufficientCloudCreds`: Root credential lacks permissions
- `CloudCredSecretNotFound`: Root credential secret missing
- `ProvisionedCredentialsFailed`: Secret exists but credentials invalid

### Annotations on Target Secret

CCO adds annotations to managed secrets:

- `cloudcredential.openshift.io/credentials-request`: Links back to CredentialsRequest (`namespace/name`)
- `cloudcredential.openshift.io/aws-policy-last-applied`: Last applied AWS policy (for drift detection)

**For generic patterns**, see:
- Controller patterns: [Tier 1](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns.md)
- Status conditions: [Tier 1](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/status-conditions.md)
- Finalizers: [Tier 1](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/finalizers.md)

## Related Concepts

- [ClusterOperator Status](../architecture/components.md#status-controller) - Aggregated CCO status
- [Operator Modes](../architecture/components.md#modes) - Mode detection and behavior
- [Cloud Provider Actuators](../architecture/components.md#cloud-providers) - Provider-specific logic

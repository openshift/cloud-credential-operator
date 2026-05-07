# ADR-0002: ccoctl as Off-Cluster Tool

**Status**: Accepted  
**Date**: 2020-06-10  
**Deciders**: OpenShift Cloud Credential Operator Team  
**Component**: Cloud Credential Operator

## Context

Manual mode with OIDC (AWS STS, Azure/GCP Workload Identity) requires cloud IAM configuration:
- OIDC provider registration
- IAM roles with trust policies for cluster OIDC issuer
- Role policies granting permissions from CredentialsRequests

**Problem**: Where should this cloud IAM configuration logic live? In-cluster CCO operator or separate tool?

**Constraints**:
- Manual mode means **no admin credentials in cluster** (by definition)
- Cloud IAM setup must happen **before** cluster installation
- Installation process extracts CredentialsRequests from release image
- Setup must work in CI/CD pipelines (automation)

**Scope**: This ADR is component-specific. For cross-repo credential management patterns, see [Tier 1 ADRs](https://github.com/openshift/enhancements/tree/master/ai-docs/decisions).

## Decision

Create **`ccoctl`** as a separate CLI binary that runs **off-cluster** to configure cloud IAM for Manual + OIDC mode.

**Responsibilities**:
- Extract CredentialsRequests from release image
- Create cloud OIDC provider
- Create IAM roles with trust policies for cluster OIDC issuer
- Attach role policies matching CredentialsRequest permissions
- Generate Kubernetes secret manifests for cluster application

**Usage**:
```bash
# Extract CredentialsRequests from release image
oc adm release extract --credentials-requests --to ./credrequests

# Create cloud resources + generate manifests
ccoctl aws create-all \
  --name my-cluster \
  --region us-east-1 \
  --credentials-requests-dir ./credrequests \
  --output-dir ./manifests

# Apply manifests to cluster
oc apply -f ./manifests
```

**Shipped as**: Binary in release image (`oc adm release extract --command=ccoctl`)

## Rationale

### Why Off-Cluster?

1. **Manual mode definition**: No admin credentials **in cluster**. Must use external admin creds.
2. **Pre-install requirement**: Cloud IAM must exist before cluster boots (chicken-egg problem if in-cluster).
3. **Security**: Admin credentials never touch cluster (zero long-lived credentials goal).
4. **Air-gap support**: Can run on internet-connected bastion; cluster can be air-gapped.

### Why Separate Binary (not `openshift-install`)?

1. **Lifecycle**: Cloud IAM setup happens once; credential rotation uses same tool.
2. **Re-usability**: Updating cluster (new CredentialsRequests) re-runs `ccoctl`, not full `openshift-install`.
3. **Separation of concerns**: `openshift-install` creates cluster; `ccoctl` creates cloud IAM.
4. **Testability**: `ccoctl` independently testable without full cluster install.

### Why Not In-Cluster CCO?

In-cluster CCO **cannot** handle Manual + OIDC setup:
- No admin credentials in cluster (manual mode premise)
- Must run before cluster exists (OIDC provider needed for kubelet to start)
- Cloud IAM is immutable infrastructure (shouldn't change during runtime)

In-cluster CCO **does** still run in Manual + OIDC mode, but only to:
- Create secrets with cloud config (role ARN, token path)
- Deploy pod identity webhook
- Validate CredentialsRequests

## Consequences

### Positive
- Clean separation: `ccoctl` = cloud IAM setup (off-cluster), CCO operator = secret/webhook management (in-cluster)
- Security: Admin credentials never in cluster
- Flexibility: Can re-run `ccoctl` to update IAM without cluster downtime
- Automation-friendly: CI/CD pipelines run `ccoctl` before `openshift-install`
- Supports credential rotation: `ccoctl` re-generates manifests, user re-applies

### Negative
- Extra tool: Users must learn `ccoctl` in addition to `openshift-install`
- Manual step: Installer cannot fully automate Manual + OIDC mode (requires `ccoctl` + manifest apply)
- Version skew risk: `ccoctl` version must match release image (mitigated by shipping in release)
- Discoverability: Users might not know about `ccoctl` (docs burden)

### Neutral
- `ccoctl` re-implements some CCO logic (CredentialsRequest parsing, cloud actuators)
- Cloud-specific commands: `ccoctl aws`, `ccoctl azure`, `ccoctl gcp` (not generic)
- Generates static manifests (user must apply to cluster)

## Alternatives Considered

### Alternative 1: Extend openshift-install
**Description**: Add Manual + OIDC setup to `openshift-install` binary.

**Rejected because**:
- Lifecycle mismatch: Cloud IAM updates independent of cluster installs
- Code duplication: `openshift-install` would duplicate CCO's cloud actuator logic
- Re-use: Post-install IAM changes require `openshift-install` (heavyweight)

### Alternative 2: In-Cluster CCO with External Credential Injection
**Description**: Run CCO in "setup mode" with injected admin credentials, then remove credentials.

**Rejected because**:
- Violates Manual mode premise (admin creds should never enter cluster)
- Chicken-egg: Cluster needs OIDC IAM to start; can't run CCO before cluster starts
- Security risk: Admin credentials touch cluster (audit trail, secret sprawl)

### Alternative 3: Cloud-Specific Scripts (not binary)
**Description**: Provide shell scripts (Terraform, CloudFormation) instead of Go binary.

**Rejected because**:
- Maintenance burden: Multiple IaC languages (Terraform, ARM, Deployment Manager)
- Testing: Harder to test scripts vs Go code
- Consistency: Scripts diverge; binary shares code with CCO operator
- Error handling: Scripts lack structured error messages

### Alternative 4: Fully Manual Setup (no tool)
**Description**: Document cloud IAM setup steps; users create resources manually.

**Rejected because**:
- Error-prone: Cloud IAM setup is complex (OIDC thumbprints, trust policies, role mappings)
- No validation: Users might misconfigure; cluster fails to start
- Poor UX: Manual IAM setup for every CredentialsRequest (10+ steps per cluster)

## References

- [ccoctl Usage](../CCO_DEVELOPMENT.md#ccoctl)
- [Manual + OIDC Mode](../architecture/components.md#manual--oidc-pod-identity)
- [AWS STS Enhancement](https://github.com/openshift/enhancements/blob/master/enhancements/cloud-integration/aws-sts.md)
- [ccoctl Source Code](https://github.com/openshift/cloud-credential-operator/tree/master/cmd/ccoctl)

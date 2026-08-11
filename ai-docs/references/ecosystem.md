# Tier 1 Ecosystem References

This document links to generic OpenShift/Kubernetes patterns in the Tier 1 ecosystem hub. Cloud Credential Operator inherits these platform-wide patterns and practices.

## Operator Patterns

**Location**: [ai-docs/practices/operator-patterns/](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns)

- **Controller Runtime**: Reconciliation loops, event handling, client patterns
- **Status Conditions**: Available, Progressing, Degraded condition semantics
- **Webhooks**: Validation and mutation patterns (pod identity webhook)
- **Finalizers**: Resource cleanup patterns
- **RBAC**: Service account and permissions

**Component Usage**:
- CCO uses controller-runtime for 8+ controllers (credentialsrequest, status, secretannotator, etc.)
- Status controller aggregates conditions to ClusterOperator resource
- Pod identity webhook mutates pods in Manual + OIDC mode
- Finalizer ensures cloud resource cleanup (see [ADR-0003](../decisions/adr-0003-finalizer-for-cloud-cleanup.md))

## Testing Practices

**Location**: [ai-docs/practices/testing/](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/testing)

- **Test Pyramid**: Unit > Integration > E2E ratio (60/30/10)
- **E2E Framework**: OpenShift E2E test patterns
- **Mock vs Real**: When to mock cloud APIs vs use real providers

**Component Usage**:
- See [CCO_TESTING.md](../CCO_TESTING.md) for component-specific test suites
- Unit tests mock cloud APIs; E2E tests use real clusters with cloud accounts

## Security Practices

**Location**: [ai-docs/practices/security/](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/security)

- **STRIDE Threat Model**: Threat modeling framework
- **RBAC Guidelines**: Role and ClusterRole design
- **Secrets Management**: Handling sensitive data

**Component Usage**:
- CCO manages highly sensitive cloud credentials
- Mint mode creates least-privilege credentials (per CredentialsRequest)
- Manual + OIDC mode eliminates long-lived credentials (AWS STS, Azure/GCP Workload Identity)
- Root credential can be removed post-install in mint mode (security hardening)

## Reliability Practices

**Location**: [ai-docs/practices/reliability/](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/reliability)

- **SLO Framework**: Service Level Objectives and error budgets
- **Observability**: Metrics, logging, tracing patterns
- **Degraded State Management**: When to mark operator degraded

**Component Usage**:
- CCO exposes Prometheus metrics (`cco_credentials_mode`, `cco_credentials_requests_total`)
- Status controller marks ClusterOperator degraded on credential provisioning failures
- Cloud API errors are retried with exponential backoff

## Kubernetes Fundamentals

**Location**: [ai-docs/domain/kubernetes/](https://github.com/openshift/enhancements/tree/master/ai-docs/domain/kubernetes)

- **Pod**: Pod lifecycle, container specs
- **Secret**: Secret management and projection
- **ServiceAccount**: Authentication and RBAC
- **CRDs**: CustomResourceDefinition patterns

**Component Usage**:
- CCO creates Secrets from CredentialsRequests
- Pod identity webhook mutates pod specs (Manual + OIDC mode)
- ServiceAccount tokens used for cloud OIDC authentication (AWS STS, Azure/GCP Workload Identity)
- CredentialsRequest is a namespaced CRD

## OpenShift Fundamentals

**Location**: [ai-docs/domain/openshift/](https://github.com/openshift/enhancements/tree/master/ai-docs/domain/openshift)

- **ClusterOperator**: Cluster operator status reporting
- **ClusterVersion**: Platform upgrade orchestration
- **Infrastructure**: Platform detection (AWS, Azure, GCP, etc.)
- **Authentication**: OIDC provider configuration

**Component Usage**:
- CCO reports status via ClusterOperator resource
- Detects cloud platform via Infrastructure.status.platformStatus.type
- Blocks upgrades if credentials insufficient (ClusterOperator.Upgradeable=False)
- Manual + OIDC mode reads authentication.spec.serviceAccountIssuer for OIDC provider URL

## Cloud Platforms

**Location**: [ai-docs/domain/cloud/](https://github.com/openshift/enhancements/tree/master/ai-docs/domain/cloud)

- **AWS IAM**: Users, roles, policies, STS
- **Azure RBAC**: Service principals, role assignments, Workload Identity
- **GCP IAM**: Service accounts, bindings, Workload Identity

**Component Usage**:
- CCO cloud actuators implement provider-specific credential provisioning
- AWS actuator creates IAM users (mint) or uses STS AssumeRoleWithWebIdentity (OIDC)
- Azure actuator creates service principals (mint) or uses Workload Identity (OIDC)
- GCP actuator creates service accounts (mint) or uses Workload Identity (OIDC)

## Cross-Repository ADRs

**Location**: [ai-docs/decisions/](https://github.com/openshift/enhancements/tree/master/ai-docs/decisions)

Platform-wide architectural decisions:
- **etcd Backend**: Why etcd is used for Kubernetes state
- **CVO Orchestration**: Why CVO orchestrates upgrades (CCO must report status correctly)
- **Immutable Nodes**: Why RHCOS + rpm-ostree

**Component-Specific ADRs**: See [ai-docs/decisions/](../decisions/) for CCO-specific decisions:
- [ADR-0001: Automatic Mode Detection](../decisions/adr-0001-automatic-mode-detection.md)
- [ADR-0002: ccoctl as Off-Cluster Tool](../decisions/adr-0002-ccoctl-off-cluster-tool.md)
- [ADR-0003: Finalizer for Cloud Cleanup](../decisions/adr-0003-finalizer-for-cloud-cleanup.md)

---

**Note**: These links point to Tier 1 (ecosystem hub) documentation. Component-specific patterns and decisions are documented in the `ai-docs/` directory of this repository.

**Last Updated**: 2026-04-30

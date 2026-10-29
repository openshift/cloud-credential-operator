# Cloud Credential Operator - Agentic Documentation

**Component**: Cloud Credential Operator (CCO)  
**Repository**: openshift/cloud-credential-operator  
**Documentation Tier**: 2 (Component-specific)

> **Agent Instruction**: When working on CCO, read relevant files from `ai-docs/` for component-specific details. For generic operator patterns, testing practices, or security guidelines, retrieve from [Tier 1 Hub](https://github.com/openshift/enhancements/tree/master/ai-docs).

> **Generic Platform Patterns**: See [Tier 1 Hub](https://github.com/openshift/enhancements/tree/master/ai-docs)

## What is CCO?

Manages cloud provider credentials for OpenShift components. Allows operators to request fine-grained credentials via `CredentialsRequest` CRs instead of using admin credentials.

## Core Components

- **CCO Controller**: Reconciles CredentialsRequests | **ccoctl CLI**: Off-cluster credential management | **Mode Detection**: Mint/Passthrough/Manual selection

## Documentation Structure

```text
ai-docs/
├── domain/              # CRDs: CredentialsRequest
├── architecture/        # Controllers, modes, cloud providers
├── decisions/           # Component ADRs (mode design, ccoctl)
├── exec-plans/          # Active feature planning
├── references/          # Tier 1 ecosystem links
├── CCO_DEVELOPMENT.md   # Build, dev workflow
└── CCO_TESTING.md       # Test suites
```

## Tier 1 Links

**Patterns**: [Operator](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns.md) | [Testing](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/testing.md) | [Security](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/security.md)

## Quick Navigation

| Topic | Location | Description |
|-------|----------|-------------|
| **Core CRD** | [domain/credentialsrequest.md](ai-docs/domain/credentialsrequest.md) | CredentialsRequest API |
| **Modes** | [architecture/components.md](ai-docs/architecture/components.md) | Mint/Passthrough/Manual |
| **Controllers** | [architecture/components.md](ai-docs/architecture/components.md) | credentialsrequest, secretannotator, status |
| **Cloud Providers** | [architecture/components.md](ai-docs/architecture/components.md) | AWS, Azure, GCP, etc. |
| **ccoctl** | [decisions/adr-0002-ccoctl-design.md](ai-docs/decisions/adr-0002-ccoctl-design.md) | Off-cluster tool |
| **Development** | [CCO_DEVELOPMENT.md](ai-docs/CCO_DEVELOPMENT.md) | Build, test locally |
| **Testing** | [CCO_TESTING.md](ai-docs/CCO_TESTING.md) | Unit, integration, E2E |

## Operator Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Mint** | Creates fine-grained cloud credentials | Admin creds have IAM permissions |
| **Passthrough** | Reuses root credential for all secrets | Root cred has all needed permissions |
| **Manual** | No credential management by CCO | User provisions credentials externally |
| **Manual + OIDC** | Short-lived tokens (AWS STS, Azure Workload Identity) | Zero long-lived credentials |

## Cloud Provider Support

**Supported**: AWS, Azure, GCP, IBM Cloud, KubeVirt, Nutanix, OpenStack, oVirt, PowerVS, vSphere

**Provider-specific logic**: `pkg/{aws,azure,gcp,ibmcloud,kubevirt,nutanix,openstack,ovirt,powervs,vsphere}/`

## Key Controllers

| Controller | Purpose |
|------------|---------|
| `credentialsrequest` | Core: provisions/updates credentials |
| `secretannotator` | Annotates root secret with mode |
| `status` | Aggregates ClusterOperator status |
| `cleanup` | Removes stale CredentialsRequests |
| `podidentity` | Deploys pod identity webhook (OIDC) |
| `awspodidentity` | AWS pod identity webhook |
| `loglevel` | Syncs log level from operator config |
| `metrics` | Prometheus metrics |

## ccoctl CLI

Off-cluster tool for manual mode with OIDC. Creates cloud IAM resources and secret manifests.

**Common tasks**: `ccoctl aws create-all`, `ccoctl azure create-all`, `ccoctl gcp create-all`

## Knowledge Graph

```
CredentialsRequest (CR)
  ├─> credentialsrequest controller
  │     ├─> Mode detection (Mint/Passthrough/Manual)
  │     ├─> Cloud provider actuator (aws|azure|gcp|...)
  │     └─> Secret creation/update
  ├─> status controller (aggregates for ClusterOperator)
  └─> cleanup controller (removes stale CRs)

Root Credential Secret (kube-system)
  ├─> secretannotator controller (sets mode annotation)
  └─> Used by provider actuators

ccoctl (off-cluster)
  ├─> Creates cloud IAM (OIDC providers, roles, policies)
  └─> Generates secret manifests for manual mode
```

## Ecosystem References

See [references/ecosystem.md](ai-docs/references/ecosystem.md) for links to:
- Operator patterns (controller-runtime, status conditions, webhooks, RBAC)
- Testing practices (pyramid, E2E framework)
- Security practices (STRIDE, secrets management)
- Kubernetes fundamentals (Pod, Secret, ServiceAccount)
- OpenShift fundamentals (ClusterOperator, release image)

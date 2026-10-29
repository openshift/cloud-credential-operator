# ADR-0001: Automatic Mode Detection

**Status**: Accepted  
**Date**: 2019-01-15  
**Deciders**: OpenShift Cloud Credential Operator Team  
**Component**: Cloud Credential Operator

## Context

CCO needs to provision cloud credentials for OpenShift components, but different cluster configurations require different strategies:
- Some clusters have admin credentials capable of creating fine-grained IAM resources (mint)
- Some have credentials with all needed permissions but cannot create IAM resources (passthrough)
- Some clusters are air-gapped or require manual credential management (manual)
- Some use OIDC-based short-lived tokens for zero long-lived credentials (manual + OIDC)

**Problem**: How should CCO determine which mode to operate in? User configuration vs automatic detection?

**Scope**: This ADR is component-specific. For cross-repo credential management patterns, see [Tier 1 ADRs](https://github.com/openshift/enhancements/tree/master/ai-docs/decisions).

## Decision

CCO will **automatically detect** the appropriate mode at startup by probing cloud API capabilities and cluster state, rather than requiring explicit user configuration.

**Detection Algorithm**:
1. Check if root credential secret exists
   - If missing: **Manual mode** (assumes pre-provisioned secrets)
2. Attempt read-only cloud API call
   - If fails: **Manual mode** or error
3. Attempt IAM creation API call (least-privilege test)
   - If succeeds: **Mint mode**
4. Compare root credential permissions against all CredentialsRequests
   - If sufficient: **Passthrough mode**
   - If insufficient: **Error** (blocks installation/upgrade)
5. Check for OIDC configuration (`authentication.spec.serviceAccountIssuer`)
   - If present with Manual mode: **Manual + OIDC** (pod identity)

## Rationale

### Why Automatic Detection?

1. **Simplicity**: Users don't need to configure mode; cluster "just works"
2. **Flexibility**: Same CCO code supports all deployment scenarios (cloud, air-gap, STS)
3. **Safety**: Detection ensures chosen mode is compatible with available credentials
4. **Install-time validation**: Installer can run same detection logic to fail-fast

### Why This Detection Order?

1. **Manual mode first**: If root secret missing, cluster expects manual provisioning
2. **Mint preferred**: Fine-grained credentials = least privilege (best security)
3. **Passthrough fallback**: Works if root credential sufficient but can't mint
4. **Error on insufficient**: Better to fail than use invalid credentials

### Why Support Multiple Modes?

Different cloud environments have different constraints:
- **Mint**: Best for clusters with admin creds (most on-prem, dev clusters)
- **Passthrough**: Works for instance roles (AWS EC2, GCP GCE) with broad permissions
- **Manual**: Required for air-gap, compliance-restricted environments
- **Manual + OIDC**: Modern zero-trust approach (AWS STS, Azure/GCP Workload Identity)

## Consequences

### Positive
- Users never configure mode explicitly (zero configuration burden)
- Single operator binary supports all modes (no separate distributions)
- Mode detection can change after install (e.g., remove admin creds → passthrough/manual)
- Installer can validate mode before creating cluster

### Negative
- Detection logic is complex and cloud-specific (AWS IAM ≠ Azure RBAC ≠ GCP IAM)
- Mode detection failures can be hard to diagnose (cloud API errors opaque)
- Detection happens at startup; mode changes require operator restart
- Passthrough mode might select overprivileged credentials without warning (mitigated by secretannotator logging)

### Neutral
- Mode is cluster-wide (all CredentialsRequests use same mode)
- Detection order implies preference (mint > passthrough > manual)

## Alternatives Considered

### Alternative 1: Explicit User Configuration
**Description**: Require users to set `CloudCredentialOperator.spec.mode` field.

**Rejected because**:
- Adds configuration burden (users must understand mode implications)
- Installation complexity (installer must detect and configure)
- Error-prone (user misconfiguration leads to broken cluster)
- No advantage over automatic detection

### Alternative 2: Per-CredentialsRequest Mode
**Description**: Allow each CredentialsRequest to specify its own mode preference.

**Rejected because**:
- Increases complexity (different components use different modes?)
- Root credential is shared (can't mint for one CR and passthrough for another)
- Cloud API rate limits favor single mode
- No clear use case for mixed modes

### Alternative 3: Static Mode Detection at Install
**Description**: Detect mode during installation only; lock mode afterward.

**Rejected because**:
- Prevents post-install mode changes (e.g., removing admin credentials)
- Mint mode benefit is removing admin creds after install (security hardening)
- Manual mode is valid post-install state

## References

- [Operator Modes](../architecture/components.md#modes)
- [Mode Detection Code](https://github.com/openshift/cloud-credential-operator/blob/master/pkg/operator/credentialsrequest/actuator.go)
- [CredentialsRequest CRD](../domain/credentialsrequest.md)
- [Enhancement Proposal](https://github.com/openshift/enhancements/blob/master/enhancements/cloud-integration/cloud-credentials-operator.md)

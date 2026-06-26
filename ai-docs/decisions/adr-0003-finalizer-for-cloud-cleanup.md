# ADR-0003: Finalizer for Cloud Resource Cleanup

**Status**: Accepted  
**Date**: 2018-10-20  
**Deciders**: OpenShift Cloud Credential Operator Team  
**Component**: Cloud Credential Operator

## Context

In Mint mode, CCO creates cloud IAM resources (users, roles, service accounts) when provisioning CredentialsRequests. When a component is uninstalled, its CredentialsRequest is deleted.

**Problem**: How do we ensure cloud IAM resources are deleted when CredentialsRequests are removed?

**Challenges**:
1. Kubernetes deletes CR from etcd immediately (no guarantee controller sees deletion event)
2. Cloud API calls can fail (network issues, rate limits, permission changes)
3. Orphaned cloud resources cost money and violate least-privilege
4. Cloud credentials in secrets might still be in use when CR deleted

**Scope**: This ADR is component-specific. For generic finalizer patterns, see [Tier 1 Operator Patterns](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/finalizers.md).

## Decision

Use Kubernetes **finalizer** (`cloudcredential.openshift.io/deprovision`) on CredentialsRequest to ensure cloud resource cleanup before etcd deletion.

**Finalizer Workflow**:
1. CCO adds finalizer when creating CredentialsRequest
2. User/controller deletes CredentialsRequest (sets `deletionTimestamp`)
3. Kubernetes blocks etcd deletion (finalizer present)
4. CCO reconciles, sees `deletionTimestamp`, calls cloud actuator `Delete()`
5. Cloud actuator deletes IAM resource (user, role, service account)
6. CCO removes finalizer
7. Kubernetes deletes CR from etcd

**Finalizer Applied In**: Mint mode only (Passthrough/Manual modes don't create cloud resources)

## Rationale

### Why Finalizer?

1. **Guaranteed cleanup opportunity**: Controller always gets chance to run cleanup logic before etcd deletion
2. **Retry on failure**: If cloud API fails, finalizer stays; controller retries on next reconcile
3. **Idempotent**: Multiple Delete calls safe (cloud actuator checks if resource exists)
4. **Standard pattern**: Finalizers are Kubernetes-native mechanism for cleanup

### Why Not OwnerReferences?

Kubernetes `ownerReferences` auto-delete child resources, but:
- Cloud IAM resources are **not Kubernetes resources** (cannot use ownerReferences)
- Need custom logic to call cloud APIs

### Why Not Pre-Delete Hook?

Admission webhooks can block deletion, but:
- Webhook must synchronously delete cloud resource (slow, timeout risk)
- Webhook failure blocks deletion (worse UX than finalizer retry)
- Finalizer allows async, retryable cleanup

## Consequences

### Positive
- Cloud resources always cleaned up (no orphans)
- Retry on transient cloud API failures
- Clear ownership: CCO owns cloud resource lifecycle
- Cost savings: No leaked IAM users/roles

### Negative
- CredentialsRequest stuck if finalizer removal fails (manual intervention needed)
- Finalizer logic must handle cloud API rate limits/errors
- Deleted CredentialsRequest remains in etcd until cloud cleanup succeeds (visible to user as "Terminating")
- Risk of finalizer deadlock if cloud credentials deleted externally

### Neutral
- Finalizer only in Mint mode (Passthrough/Manual don't add finalizer)
- Secret deletion happens separately (not tied to finalizer)

## Alternatives Considered

### Alternative 1: No Finalizer (best-effort cleanup)
**Description**: Reconcile loop deletes cloud resources when CR deleted, but no guarantee.

**Rejected because**:
- CR might be deleted from etcd before controller sees event
- Orphaned cloud resources accumulate over cluster lifetime
- No retry on cloud API failure

### Alternative 2: External Garbage Collector
**Description**: Separate controller periodically scans cloud for orphaned resources.

**Rejected because**:
- Complex: Must track "expected" vs "actual" cloud state
- Eventual consistency: Delay between CR deletion and cleanup
- Cloud API cost: Constant scanning
- Finalizer is simpler and immediate

### Alternative 3: Block Deletion Until Components Stop Using Credentials
**Description**: Finalizer waits until pods using secret are deleted.

**Rejected because**:
- Too conservative: Delays cleanup unnecessarily
- Hard to detect "safe to delete" (secret might be cached in pod)
- Cloud credentials can be revoked before secret deletion (cloud IAM delete = credentials invalid)

### Alternative 4: User Manual Cleanup
**Description**: Document that users must delete cloud resources manually.

**Rejected because**:
- Poor UX: Users must remember to clean up
- Error-prone: Users might forget, leaving orphans
- Automation: Can't fully automate component uninstall

## Implementation Notes

### Finalizer Handling Code

**Add Finalizer**: When creating CredentialsRequest in Mint mode
```go
if mode == Mint && !hasFinalizer(cr, FinalizerDeprovision) {
    cr.Finalizers = append(cr.Finalizers, FinalizerDeprovision)
    update(cr)
}
```

**Remove Finalizer**: After successful cloud resource deletion
```go
if cr.DeletionTimestamp != nil {
    if err := actuator.Delete(cr); err != nil {
        return err // Retry on next reconcile
    }
    cr.Finalizers = remove(cr.Finalizers, FinalizerDeprovision)
    update(cr)
}
```

### Error Handling

- **Cloud API transient error**: Return error, finalizer stays, controller retries
- **Resource already deleted**: Ignore (idempotent), remove finalizer
- **Permanent error** (e.g., permission denied): Log error, manual intervention needed

### Edge Case: Root Credential Deleted

If root credential deleted before CredentialsRequest cleanup:
- Finalizer cleanup fails (can't call cloud API without creds)
- CredentialsRequest stuck in "Terminating"
- **Mitigation**: Manual finalizer removal (`oc patch`) after verifying cloud resource deleted externally

## References

- [Finalizer Implementation](https://github.com/openshift/cloud-credential-operator/blob/master/pkg/operator/credentialsrequest/actuator.go)
- [Kubernetes Finalizers](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/)
- [CredentialsRequest CRD](../domain/credentialsrequest.md#finalizer-management)
- [Tier 1 Finalizer Patterns](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/finalizers.md)

# `ccoctl` signing-key rotation command contract

> **Status:** The shared phase engine and command factory implement this provider-neutral contract,
> but the provider commands and their concrete cluster/cloud adapters are not registered yet. Until
> those integrations are available, use the [manual rotation procedure](rotate-oidc-key.md).

## Scope

The initial AWS provider command is invoked externally for exactly one provider and one cluster:

```text
ccoctl aws rotate-signing-key [options]
```

Future Azure and GCP provider adapters are expected to use the equivalent contract forms below;
these commands are not registered by this foundation:

```text
ccoctl azure rotate-signing-key [options]
ccoctl gcp rotate-signing-key [options]
```

One invocation follows the existing rotation sequence: preserve the current JWKS, request a
replacement signer, publish overlapping old and new public keys, wait for the cluster and nodes to
stabilize, and only then retire the old public keys.

This is an operator-initiated workflow. It does not add an in-cluster controller, autonomous
scheduler, recurring job, or cadence API. A desired annual cadence remains an operational decision
outside this command.

## Common command options

The existing `ccoctl` option names are retained where they already express the required input. The
following names are the proposed v1 common contract:

```text
--kubeconfig <path>
--output-dir <path>
--publication-mode <direct|manual>
--resume
```

- `--kubeconfig` explicitly selects the target cluster. There is no in-cluster configuration
  fallback.
- `--output-dir` holds public JWKS artifacts and the non-secret checkpoint record.
- `--publication-mode` selects direct provider operations or a paused manual workflow. The command
  must not silently switch modes.
- `--resume` continues the operation recorded in `--output-dir` after validating its state against
  the cluster and provider.

Provider resource selectors, cloud-authentication options, manual artifact-import options, and the
manual publication acknowledgment mechanism are not settled by CCO-862. They must be resolved by
the provider adapter stories instead of being inferred here.

## Required inputs and access

The command contract requires the following capabilities:

- An explicit kubeconfig for the target cluster. The command must not fall back to in-cluster
  configuration.
- Explicit external cloud authentication for the selected provider. Credentials may be used in
  memory but must not be copied into artifacts or checkpoint state, and the command must not obtain
  cloud credentials from cluster Secrets.
- Enough cluster permission to inspect stability, read the public-only
  `openshift-kube-apiserver/bound-sa-token-signing-certs` ConfigMap, inspect only the metadata of
  the `openshift-kube-apiserver-operator/next-bound-service-account-signing-key` Secret, delete that
  Secret with UID and resource version preconditions to trigger regeneration, acquire and complete
  the cluster-durable signer-rotation guard, and reboot and observe the applicable worker and
  control-plane machine config pools.
- Enough cloud permission to locate and read the current JWKS and to publish both the combined and
  final JWKS to the supported target.
- A durable working directory for public artifacts and resumable, non-secret checkpoint state.
- A direct-publication or manual-publication choice. Manual operation must support supplying the
  current JWKS and exporting each publication artifact. It also requires positive confirmation that
  each artifact was applied, but the acknowledgment interface remains unresolved.

Only public signer material is an input or output of this workflow. Public signer bytes and the
derived JWKS key ID are read from the public-only
`openshift-kube-apiserver/bound-sa-token-signing-certs` ConfigMap. The signer Secret is accessed only
through metadata-only retrieval of its UID and resource version for delete preconditions; the
command must never perform a normal Secret GET that returns its data. The command must never
require, export, or persist the private service-account signing key. It must also avoid persisting
kubeconfig contents, cloud credentials, bearer tokens, Secret payloads, or other authentication
material.

The cluster adapter must request only the `meta.k8s.io/v1` `PartialObjectMetadata`
representation when reading signer Secret metadata. It must reject an unsupported response or any
full-object fallback rather than allowing the process to receive Secret data.

The initial implementation accepts canonical `ccoctl`-owned JWKS documents. Unsupported top-level
or per-key extension fields fail before mutation or publication so the command cannot silently drop
issuer metadata. Supporting additional externally managed JWKS fields requires an explicit provider
contract that preserves them during combined-key publication.

The shared package does not register an executable provider command, build a concrete cluster
adapter, resolve provider targets, or call cloud APIs. The AWS, Azure, and GCP adapter stories own
those integrations. The shared engine instead enforces the phase order, artifact/checkpoint rules,
conditional-publication contract, and reconciliation boundaries through injected adapters.

## Preconditions

Before requesting a replacement key, the command must verify and record that:

1. The kubeconfig identifies the intended cluster and the cluster is stable.
2. The selected provider and issuer target can be resolved without assuming a public issuer
   endpoint.
3. Cluster and cloud permissions needed by the selected publication mode are available.
4. A stable metadata-Secret/public-ConfigMap/metadata-Secret observation records the exact signer
   Secret UID and resource version plus the complete public signer ConfigMap UID, resource version,
   entry names, public-value digests, and derived key IDs.
5. A deterministic guard reference has been derived from that evidence. Its scope serializes all
   signer rotations for the cluster, while its operation ID also binds the provider and exact target.
6. The current JWKS has been retrieved, parsed, saved as a non-secret recovery artifact, and every
   current key ID is present in the recorded public signer baseline.
7. The working directory contains no conflicting in-progress rotation, unless the caller is
   explicitly resuming it.

A failed preflight must not mutate the cluster or provider.

## Artifacts and checkpoint state

The workflow produces the same public JWKS artifacts used by the manual procedure:

- `serviceaccount-signer.public`: the replacement public signer retrieved from the cluster.
- `jwks.current.json`: the validated provider state captured before cluster mutation.
- `jwks.new.json`: the replacement public key only.
- `jwks.combined.json`: the retained current keys plus the replacement public key.
- `rotation-state.json`: a machine-readable checkpoint record containing the provider, stable
  cluster identity, non-secret target identity, the complete pre-rotation public signer baseline,
  the original signer Secret's metadata-only UID and resource version, the deterministic
  cluster-wide guard reference, the exact appended public entry and replacement Secret reference,
  validated artifact SHA-256 digests, the immutable reboot intent and its machine config pool
  targets and node boot-ID baselines once recorded, last confirmed checkpoint, exact-artifact
  publication confirmations, and a non-secret error code when applicable.

Files containing private keys or credentials are not rotation artifacts. Logs and checkpoint data
must not include their contents.

Public artifacts are validated before they are written, synced through a temporary file, atomically
renamed, and only then referenced by a checkpoint. An existing artifact name is immutable: an exact
retry is accepted, but different content fails closed. `jwks.new.json` must exactly represent the
replacement public key, and `jwks.combined.json` must be the canonical ordered union of the saved
current keys and that replacement, with all supported key metadata preserved.

Local state updates use a persistent advisory lock in the output directory so concurrent checkpoint
writers cannot lose an update. The shared orchestrator holds the same workspace lock across cluster
or provider actions as well as their following checkpoint write; per-file locking alone is not
sufficient to serialize external mutations. The local lock is not a cluster-wide safety mechanism.
A separate cluster-durable guard serializes all signer rotations for the cluster, is verified before
post-preflight cluster observations and effects, and remains held through the final new-only
provider publication. Identical workspaces may converge on the same operation ID; a different
operation in the same scope fails closed.

Checkpoint schema version 1 fixes generated JWKS encoding to two-space-indented JSON with one final
newline. A future implementation that changes that canonical representation must retain version 1
compatibility or increment the checkpoint schema. The output directory must be on a trusted local
filesystem and must not be placed beneath a path that another user can replace or redirect.
Schema version 1 is the first supported rotation checkpoint format; checkpoints produced by earlier
development snapshots are not resumable.

## Ordered checkpoints

The implementation must durably record these exact schema-version-1 phases in order:

1. **`initialized`:** the operation identity and publication mode are recorded before preflight.
2. **`preflight-complete`:** cluster identity, stability, target resolution, permissions, the
   complete named public signer baseline, the signer Secret's metadata-only UID and resource
   version, deterministic cluster-wide guard reference, and working state are validated and
   recorded before the guard is acquired.
3. **`guard-acquired`:** the exact operation owns the cluster-durable signer-rotation guard. An
   identical operation may adopt the same guard, while a different operation in the cluster scope
   is rejected.
4. **`current-jwks-read`:** `jwks.current.json` is strictly validated, bound to the signer baseline,
   and its digest is recorded.
5. **`next-key-requested`:** deletion of
   `openshift-kube-apiserver-operator/next-bound-service-account-signing-key` is confirmed using the
   recorded UID and resource version as preconditions.
6. **`next-public-key-read`:** the replacement Secret has a different exact UID/resource-version
   reference, every baseline ConfigMap entry remains byte-identical, exactly one new named public
   entry is present, and `serviceaccount-signer.public` is validated and bound to that evidence.
7. **`new-jwks-built`:** `jwks.new.json` is validated and its digest is recorded.
8. **`combined-jwks-built`:** `jwks.combined.json` contains the retained current keys and the new
   key.
9. **`combined-jwks-published`:** the provider confirms the direct write, or the caller explicitly
   acknowledges applying the exact manual artifact.
10. **`signer-rollout-stable`:** the cluster reports stability after adopting the replacement
   signer.
11. **`reboot-intent-recorded`:** a non-secret operation ID, the exact machine config pool targets,
    and each target node's baseline boot ID are durably recorded before requesting a reboot. The
    shared engine derives the operation ID deterministically from the cluster identity and
    replacement key ID so retries using another working directory converge even when their observed
    targets or boot-ID baselines differ. The first reboot request atomically creates a
    cluster-durable canonical record containing its exact targets and baselines. Later workspaces
    adopt that canonical record before advancing, and it remains observable for the lifetime of
    resumable operation state.
12. **`nodes-rebooted`:** reboot completion is confirmed for every node recorded in the immutable
    reboot intent.
13. **`post-reboot-stable`:** the cluster reports stability after the node reboots.
14. **`new-only-jwks-published`:** the provider confirms the direct write, or the caller explicitly
    acknowledges applying `jwks.new.json`.
15. **`guard-release-recorded`:** final cluster and provider state was reconciled while the exact
    guard was still held, and the durable intent to complete that guard is recorded.
16. **`complete`:** the exact guard operation is durably marked complete. A crash after that
    external update is reconciled from the guard's per-operation terminal record rather than by
    accepting a later owner's guard.

The command must never publish the new-only JWKS before combined publication, signer stability,
node reboot completion, and post-reboot stability are all confirmed.

## Direct and manual publication

In direct mode, the provider adapter reads and writes the supported JWKS target with the caller's
external cloud authentication. Every write is conditional on the opaque revision from an exact
predecessor read. The shared engine records success only after an exact readback of the desired
artifact; unrelated state is a conflict and is never overwritten. Immediately before each
publication, the engine verifies that the exact cluster guard is still held and that the complete
recorded signer evidence is unchanged. A local checkpoint is not proof of publication.

In manual mode, the command emits the exact public artifact required for the next provider action
and pauses. Resume requires explicit confirmation bound to the publication phase, artifact name,
and SHA-256 digest. The command must not infer that a copy or upload succeeded, and must not pass a
publication checkpoint merely because the artifact exists locally. The public provider-specific
flags used to supply that acknowledgement remain an adapter integration decision.

The cluster-wide signer-rotation guard remains held while a manual operation is paused. Losing or
replacing that exact guard is a conflict; the command must not silently reacquire a different
operation and continue from the old artifacts.

Manual mode must also allow the caller to fetch the current JWKS out of band and supply it before
the command performs the cluster mutation. This supports private or externally managed issuers
without requiring a publicly reachable JWKS endpoint.

## Interruption, retry, and recovery

- A retry uses the same working directory and operation state. It validates observable cluster and
  provider state before skipping a completed checkpoint.
- Preflight evidence and the deterministic guard reference are checkpointed before guard
  acquisition. Resume observes and, only when still absent, idempotently acquires that same
  operation; it never adopts a different operation in the cluster-global signer scope.
- If interrupted after requesting the replacement key, resume must compare the public key observed
  in the complete public signer ConfigMap with the exact named baseline. Every baseline entry must
  remain unchanged, the ConfigMap UID must match with a newer resource version, exactly one new
  entry with a unique digest and derived key ID must exist, and the replacement Secret must have a
  different, stable UID/resource-version reference. The old Secret is deleted only with the
  recorded metadata-only UID and resource version preconditions. Resume must not request another
  key merely because the previous run ended.
- If a provider write has an unknown outcome, retry must read or otherwise reconcile the target
  before writing again.
- The reboot intent must be checkpointed before the disruptive request. Resume must reconcile node
  boot IDs against the cluster-canonical baselines and reuse the same operation ID; it must not
  submit a second pool reboot merely because the previous run ended or its outcome is unknown.
- Reboot planning, observation, reconciliation, and waits are read-only. The reboot request is the
  only operation allowed to create the canonical reboot record or trigger the disruptive action.
- Repeated execution must not duplicate keys in the combined JWKS, regress to an earlier artifact,
  or repeat a disruptive cluster action without validation.
- The cluster-wide guard is retained through final new-only publication and reconciliation. Its
  release is an observable, idempotent external effect with a durable per-operation completion
  record, so a crash cannot make a resumed run confuse a later owner with this operation.
- Invalid, missing, mismatched, or out-of-order state fails closed and preserves available public
  recovery artifacts.
- Recovery must keep the overlapping JWKS published until the stability and reboot checkpoints are
  confirmed. It must not retire old keys as an automatic rollback action.

## Provider boundaries that remain unresolved

The shared command must not hide provider capabilities that have not been agreed:

- **AWS custom issuers:** the standard S3 publication path is in scope. For custom issuer storage,
  including the OCPSTRAT-3586 case, it remains unresolved whether the command invokes a publisher
  hook or produces an artifact and waits for an explicit acknowledgement. Required resource and
  hook-selection options are therefore provider follow-up decisions.
- **GCP embedded JWK:** the GCS bucket `keys.json` path is the defined baseline. Support for an
  embedded `pool-jwk-file` target is included only after explicit agreement; otherwise it is
  follow-on work. Publication-target resource options remain a provider follow-up decision.
- **Discovery document:** the current provider stories specify JWKS publication. Whether rotation
  also updates `.well-known/openid-configuration` or `jwks_uri` remains unresolved and must not be
  assumed.
- **Availability:** overlapping keys reduce authentication risk, but this contract does not promise
  zero downtime. Implementations and user documentation must surface the disruptive phases and the
  availability implications for single-node and other non-highly-available clusters.

package rotation

import (
	"context"
	"fmt"
)

// EffectOutcome describes what an adapter knows about an external mutation.
// Unknown outcomes must be reconciled through observation before an adapter is
// asked to repeat the mutation.
type EffectOutcome string

const (
	EffectSubmitted  EffectOutcome = "submitted"
	EffectNotApplied EffectOutcome = "not-applied"
	EffectUnknown    EffectOutcome = "unknown"
)

// PublicSignerObservation is one named public value from the cumulative signer
// ConfigMap. Entry names do not identify an active or next signer.
type PublicSignerObservation struct {
	Name         string
	PublicKeyPEM []byte
}

// PublicSignerBundleObservation is a complete read of the public-only signer
// ConfigMap. Implementations must return every data entry without selecting or
// reordering a presumed active signer.
type PublicSignerBundleObservation struct {
	ConfigMapUID             string
	ConfigMapResourceVersion string
	Signers                  []PublicSignerObservation
}

// ClusterPreflight is returned only after the adapter has confirmed cluster
// stability and the permissions needed by the shared workflow.
type ClusterPreflight struct {
	ClusterIdentity string
}

// ClusterExpectation describes the non-secret evidence an adapter must
// reconcile before a resumed workflow trusts any prior checkpoint.
type ClusterExpectation struct {
	Phase                     Phase
	ClusterIdentity           string
	RotationGuard             RotationGuardReference
	PreRotationSignerBaseline PublicSignerBaseline
	PreRotationSignerRef      SignerObjectReference
	ReplacementSigner         *ReplacementSignerEvidence
	RebootIntent              *RebootIntent
}

// RotationGuardStatus is the observable state of one exact signer-rotation
// operation in its cluster-global guard scope.
type RotationGuardStatus string

const (
	RotationGuardNotFound     RotationGuardStatus = "not-found"
	RotationGuardHeld         RotationGuardStatus = "held"
	RotationGuardCompleted    RotationGuardStatus = "completed"
	RotationGuardOwnedByOther RotationGuardStatus = "owned-by-other"
)

// RotationGuardObservation is a read-only lookup of one exact operation. For
// Held and Completed, OperationID is the requested operation. For
// OwnedByOther, it is the conflicting active operation. A Completed result is
// a durable per-operation terminal record and remains observable after a later
// operation acquires the same cluster-global scope.
type RotationGuardObservation struct {
	Status      RotationGuardStatus
	OperationID string
}

// RebootStatus is the observable state of a cluster-durable reboot record.
// RebootInProgress includes the interval after the canonical intent is durable
// but before every target reboot request has been reconciled.
type RebootStatus string

const (
	RebootNotStarted RebootStatus = "not-started"
	RebootInProgress RebootStatus = "in-progress"
	RebootComplete   RebootStatus = "complete"
)

// RebootPlan is the adapter-observed set of machine config pool targets and
// node boot-ID baselines. The shared engine canonicalizes this plan and assigns
// the deterministic RebootIntent ID before it becomes durable.
type RebootPlan struct {
	Targets   []string
	Baselines []NodeRebootBaseline
}

// RebootObservation is a read-only lookup of one deterministic reboot
// operation ID. CanonicalIntent is nil only when Status is RebootNotStarted.
// Otherwise it is the immutable intent stored by the first RequestReboot call.
type RebootObservation struct {
	Status          RebootStatus
	CanonicalIntent *RebootIntent
}

// ClusterRotation supplies provider-independent cluster observations and
// actions. Disruptive methods receive immutable checkpoint evidence so their
// implementations can use API preconditions and idempotent operation IDs.
//
// Preflight, Reconcile, every Observe* and Wait* method, and PrepareReboot are
// read-only. AcquireRotationGuard, ReleaseRotationGuard, RequestReplacement,
// and RequestReboot are the only mutation entry points. Reconcile validates
// identity and all claims that are durable at the
// supplied phase. It must tolerate the in-between observable state of an effect
// whose checkpoint was interrupted: at PhaseCurrentJWKSRead the original signer
// may already be absent or replaced, and at PhaseRebootIntentRecorded the exact
// persisted reboot may be not started, in progress, or complete.
//
// RequestReboot is the sole reboot mutation. When the ID is new, it must first
// durably create the cluster-canonical intent and must not mutate a reboot
// target before that record exists. It must then idempotently reconcile every
// target request in the canonical intent. For an existing ID it must preserve
// the first canonical intent and finish any target requests that are not yet
// durable, without repeating a target request that already records the same
// operation ID. The orchestrator may therefore call RequestReboot again while
// the operation is RebootInProgress.
//
// EffectSubmitted means the canonical intent and every target request are
// known to be durable, including when they were already in the desired state.
// A partial or ambiguous multi-target result must be EffectUnknown;
// EffectNotApplied is valid only when the adapter knows that no mutation from
// the call was applied. The canonical record must remain observable while a
// checkpoint for the operation can be resumed. RebootNotStarted means that no
// canonical record, queued target, active target, or completed operation with
// that ID is observable.
// ObserveSignerReference must request only the meta.k8s.io/v1
// PartialObjectMetadata representation of the next-signer Secret and must fail
// closed rather than accepting a full Secret fallback. A nil reference means
// only that the object was not found. ObservePublicSignerBundle must read only
// the public openshift-kube-apiserver/bound-sa-token-signing-certs ConfigMap.
// Shared orchestration surrounds each bundle read with two metadata-reference
// reads and accepts the observation only when those references match.
//
// ObserveRotationGuard looks up the exact operation within the cluster-global
// signer-rotation scope. AcquireRotationGuard must atomically claim a free
// scope, converge when the same operation already owns it, and report a
// different active operation as OwnedByOther. ReleaseRotationGuard must only
// release the exact active operation and must atomically leave a durable
// Completed record for it. Unknown mutation outcomes are reconciled by another
// observation before any retry.
//
// The public ConfigMap has no field that cryptographically binds an entry to a
// particular next-signer Secret UID. Every method after preflight evidence
// capture therefore receives the exact immutable guard reference. The two
// signer observation methods accept a nil reference only for the initial
// read-only ref-bundle-ref snapshot needed to derive that reference; every
// later call must supply it. Implementations must fail closed if that operation
// no longer owns the guard. Multiple
// workspaces may reconcile the same guarded operation; different preflight
// evidence derives a different operation and must conflict in the shared scope.
//
// RequestReplacement must issue a UID/resource-version-preconditioned delete
// and be idempotent for the same SignerObjectReference. EffectSubmitted alone
// does not advance the checkpoint; absence or a changed Secret UID must be
// observed first. WaitForReplacement is read-only and only waits for cluster
// progress; shared orchestration re-observes and verifies the exact bundle
// delta before trusting a replacement.
type ClusterRotation interface {
	Preflight(context.Context) (ClusterPreflight, error)
	ObserveRotationGuard(context.Context, RotationGuardReference) (RotationGuardObservation, error)
	AcquireRotationGuard(context.Context, RotationGuardReference) (EffectOutcome, error)
	ReleaseRotationGuard(context.Context, RotationGuardReference) (EffectOutcome, error)
	Reconcile(context.Context, RotationGuardReference, ClusterExpectation) error
	ObserveSignerReference(context.Context, *RotationGuardReference) (*SignerObjectReference, error)
	ObservePublicSignerBundle(context.Context, *RotationGuardReference) (PublicSignerBundleObservation, error)
	RequestReplacement(context.Context, RotationGuardReference, SignerObjectReference) (EffectOutcome, error)
	WaitForReplacement(context.Context, RotationGuardReference, SignerObjectReference) error
	WaitForSignerRollout(context.Context, RotationGuardReference, string) error
	PrepareReboot(context.Context, RotationGuardReference, string) (RebootPlan, error)
	ObserveReboot(context.Context, RotationGuardReference, string) (RebootObservation, error)
	RequestReboot(context.Context, RotationGuardReference, RebootIntent) (EffectOutcome, error)
	WaitForReboot(context.Context, RotationGuardReference, RebootIntent) error
	WaitForPostRebootStable(context.Context, RotationGuardReference, RebootIntent) error
}

// TargetResolver returns a stable, non-secret identity for the issuer JWKS
// target. The same identity must be returned throughout a resumed operation.
type TargetResolver interface {
	ResolveTarget(context.Context) (string, error)
}

// VersionedJWKS is an exact provider read plus the opaque revision required by
// a subsequent conditional write.
type VersionedJWKS struct {
	Data     []byte
	Revision string
}

// ConditionalJWKSBackend implements direct publication without blind
// overwrites. PublishIfVersion must submit no write when the revision no longer
// matches.
type ConditionalJWKSBackend interface {
	CheckAccess(context.Context, string) error
	ReadJWKS(context.Context, string) (VersionedJWKS, error)
	PublishIfVersion(context.Context, string, string, []byte) (EffectOutcome, error)
}

// ManualAcknowledgement confirms that the caller applied one exact public
// artifact. It is valid for only the publication phase named here.
type ManualAcknowledgement struct {
	Phase    Phase
	Artifact string
	SHA256   string
}

// ManualInput supplies information that cannot be observed by the engine in
// manual publication mode. Only one acknowledgement can be consumed per run.
type ManualInput struct {
	CurrentJWKS     []byte
	Acknowledgement *ManualAcknowledgement
}

// RunOptions identifies one new or resumed rotation operation.
type RunOptions struct {
	Provider        Provider
	PublicationMode PublicationMode
	OutputDir       string
	Resume          bool
	Manual          ManualInput
}

// RunResult reports the last durable phase reached by Run.
type RunResult struct {
	Phase    Phase
	Complete bool
}

// PauseReason identifies an expected manual hand-off rather than a failure.
type PauseReason string

const (
	PauseForCurrentJWKS PauseReason = "current-jwks-required"
	PauseForPublication PauseReason = "publication-acknowledgement-required"
)

// PauseError tells a caller which public input or publication confirmation is
// required before resuming.
type PauseError struct {
	Phase    Phase
	Reason   PauseReason
	Artifact string
	Path     string
	SHA256   string
}

func (e *PauseError) Error() string {
	if e == nil {
		return "rotation is paused"
	}
	if e.Reason == PauseForPublication {
		return fmt.Sprintf("rotation paused at phase %q: apply artifact %q with SHA-256 %s and resume with an acknowledgement", e.Phase, e.Artifact, e.SHA256)
	}
	return fmt.Sprintf("rotation paused at phase %q: supply the current JWKS and resume", e.Phase)
}

// OutcomeUnknownError reports an external mutation whose final state could not
// be proven. A later resume must reconcile observation before retrying it.
type OutcomeUnknownError struct {
	Phase     Phase
	Operation string
	Cause     error
}

func (e *OutcomeUnknownError) Error() string {
	if e == nil {
		return "rotation external operation outcome is unknown"
	}
	return fmt.Sprintf("rotation operation %q at phase %q has an unknown outcome; inspect observable state and resume", e.Operation, e.Phase)
}

func (e *OutcomeUnknownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ConflictError reports observable state that is neither the expected
// predecessor nor the exact desired result.
type ConflictError struct {
	Phase  Phase
	Reason string
}

func (e *ConflictError) Error() string {
	if e == nil {
		return "rotation state conflict"
	}
	return fmt.Sprintf("rotation state conflict at phase %q: %s", e.Phase, e.Reason)
}

package rotation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

const (
	errorCodeCancelled              = "operation-cancelled"
	errorCodeConflict               = "state-conflict"
	errorCodeExternalOutcomeUnknown = "external-outcome-unknown"
	errorCodeManualInputRequired    = "manual-input-required"
)

// Orchestrator executes the shared signer-key rotation phase machine. Provider
// adapters supply target resolution and conditional publication; cluster
// actions remain behind a separately fakeable boundary.
type Orchestrator struct {
	Cluster   ClusterRotation
	Target    TargetResolver
	Publisher ConditionalJWKSBackend
}

// Run holds the local workspace lease across observation, external effects,
// public artifact persistence, and the checkpoint that follows each effect.
func (o Orchestrator) Run(ctx context.Context, options RunOptions) (RunResult, error) {
	var result RunResult
	if err := o.validateOptions(options); err != nil {
		return result, err
	}

	err := WithRotationWorkspace(options.OutputDir, func(workspace *RotationWorkspace) error {
		checkpoint, existed, err := loadOrInitializeCheckpoint(workspace, options)
		if err != nil {
			return err
		}
		result.Phase = checkpoint.Phase

		if err := validateManualInput(options, checkpoint.Phase); err != nil {
			return err
		}
		if existed {
			if err := o.reconcileRecordedState(ctx, workspace, &checkpoint); err != nil {
				recordCheckpointError(workspace, &checkpoint, classifyCheckpointError(err, checkpoint.Phase))
				result.Phase = checkpoint.Phase
				return err
			}
		}

		acknowledgementConsumed := false
		for checkpoint.Phase != PhaseComplete {
			if err := ctx.Err(); err != nil {
				recordCheckpointError(workspace, &checkpoint, errorCodeCancelled)
				result.Phase = checkpoint.Phase
				return err
			}
			if err := o.step(ctx, workspace, &checkpoint, options, &acknowledgementConsumed); err != nil {
				recordCheckpointError(workspace, &checkpoint, classifyCheckpointError(err, checkpoint.Phase))
				result.Phase = checkpoint.Phase
				return err
			}
			result.Phase = checkpoint.Phase
		}

		result.Complete = true
		return nil
	})
	return result, err
}

func (o Orchestrator) validateOptions(options RunOptions) error {
	if o.Cluster == nil {
		return fmt.Errorf("rotation cluster adapter must not be nil")
	}
	if o.Target == nil {
		return fmt.Errorf("rotation target resolver must not be nil")
	}
	if !isSupportedProvider(options.Provider) {
		return fmt.Errorf("unsupported rotation provider %q", options.Provider)
	}
	if !isSupportedPublicationMode(options.PublicationMode) {
		return fmt.Errorf("unsupported rotation publication mode %q", options.PublicationMode)
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return fmt.Errorf("rotation output directory must not be empty")
	}
	if options.PublicationMode == PublicationModeDirect && o.Publisher == nil {
		return fmt.Errorf("direct rotation publication requires a conditional JWKS backend")
	}
	return nil
}

func loadOrInitializeCheckpoint(workspace *RotationWorkspace, options RunOptions) (Checkpoint, bool, error) {
	checkpoint, err := workspace.LoadCheckpoint()
	switch {
	case err == nil:
		if !options.Resume {
			return Checkpoint{}, true, fmt.Errorf("rotation checkpoint already exists in %q; use resume to continue it", options.OutputDir)
		}
		if checkpoint.Provider != options.Provider {
			return Checkpoint{}, true, fmt.Errorf("rotation checkpoint provider %q does not match requested provider %q", checkpoint.Provider, options.Provider)
		}
		if checkpoint.PublicationMode != options.PublicationMode {
			return Checkpoint{}, true, fmt.Errorf("rotation checkpoint publication mode %q does not match requested mode %q", checkpoint.PublicationMode, options.PublicationMode)
		}
		return checkpoint, true, nil
	case errors.Is(err, errCheckpointNotFound):
		if options.Resume {
			return Checkpoint{}, false, fmt.Errorf("no rotation checkpoint exists in %q to resume", options.OutputDir)
		}
		outputDir, err := workspace.OutputDir()
		if err != nil {
			return Checkpoint{}, false, err
		}
		checkpoint = NewCheckpoint(options.Provider, options.PublicationMode, outputDir)
		if err := workspace.SaveCheckpoint(checkpoint); err != nil {
			return Checkpoint{}, false, err
		}
		return checkpoint, false, nil
	default:
		return Checkpoint{}, false, err
	}
}

func validateManualInput(options RunOptions, phase Phase) error {
	hasCurrent := len(options.Manual.CurrentJWKS) != 0
	hasAcknowledgement := options.Manual.Acknowledgement != nil
	if options.PublicationMode == PublicationModeDirect {
		if hasCurrent || hasAcknowledgement {
			return fmt.Errorf("manual rotation input cannot be used with direct publication")
		}
		return nil
	}
	if hasCurrent && hasAcknowledgement {
		return fmt.Errorf("manual current JWKS input and a publication acknowledgement must be supplied in separate runs")
	}
	if hasCurrent && phase != PhaseInitialized && phase != PhasePreflightComplete && phase != PhaseGuardAcquired {
		return fmt.Errorf("manual current JWKS input is not expected at checkpoint phase %q", phase)
	}
	if !hasAcknowledgement {
		return nil
	}

	expectedPhase := Phase("")
	switch phase {
	case PhaseCombinedJWKSBuilt:
		expectedPhase = PhaseCombinedJWKSPublished
	case PhasePostRebootStable:
		expectedPhase = PhaseNewOnlyJWKSPublished
	default:
		return fmt.Errorf("manual publication acknowledgement is not expected at checkpoint phase %q", phase)
	}
	if options.Manual.Acknowledgement.Phase != expectedPhase {
		return fmt.Errorf("manual publication acknowledgement for phase %q cannot be used at checkpoint phase %q", options.Manual.Acknowledgement.Phase, phase)
	}
	return nil
}

func (o Orchestrator) step(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint, options RunOptions, acknowledgementConsumed *bool) error {
	if phaseAtLeast(checkpoint.Phase, PhaseGuardAcquired) && !phaseAtLeast(checkpoint.Phase, PhaseGuardReleaseRecorded) {
		if err := o.requireRotationGuardHeld(ctx, *checkpoint); err != nil {
			return err
		}
	}
	switch checkpoint.Phase {
	case PhaseInitialized:
		return o.completePreflight(ctx, workspace, checkpoint, options.PublicationMode)
	case PhasePreflightComplete:
		return o.acquireRotationGuard(ctx, workspace, checkpoint)
	case PhaseGuardAcquired:
		return o.captureCurrentJWKS(ctx, workspace, checkpoint, options)
	case PhaseCurrentJWKSRead:
		return o.requestReplacement(ctx, workspace, checkpoint)
	case PhaseNextKeyRequested:
		return o.captureReplacementSigner(ctx, workspace, checkpoint)
	case PhaseNextPublicKeyRead:
		return buildNewJWKS(workspace, checkpoint)
	case PhaseNewJWKSBuilt:
		return buildCombinedJWKS(workspace, checkpoint)
	case PhaseCombinedJWKSBuilt:
		return o.publishArtifact(ctx, workspace, checkpoint, options, acknowledgementConsumed, PhaseCombinedJWKSPublished, ArtifactCombinedJWKS, ArtifactCurrentJWKS)
	case PhaseCombinedJWKSPublished:
		return o.waitForSignerRollout(ctx, workspace, checkpoint)
	case PhaseSignerRolloutStable:
		return o.recordRebootIntent(ctx, workspace, checkpoint)
	case PhaseRebootIntentRecorded:
		return o.completeReboot(ctx, workspace, checkpoint)
	case PhaseNodesRebooted:
		return o.waitForPostRebootStability(ctx, workspace, checkpoint)
	case PhasePostRebootStable:
		return o.publishArtifact(ctx, workspace, checkpoint, options, acknowledgementConsumed, PhaseNewOnlyJWKSPublished, ArtifactNewJWKS, ArtifactCombinedJWKS)
	case PhaseNewOnlyJWKSPublished:
		if err := o.reconcileRecordedState(ctx, workspace, checkpoint); err != nil {
			return err
		}
		return advanceCheckpoint(workspace, checkpoint, PhaseGuardReleaseRecorded, nil)
	case PhaseGuardReleaseRecorded:
		return o.releaseRotationGuard(ctx, workspace, checkpoint)
	default:
		return fmt.Errorf("cannot execute unsupported rotation phase %q", checkpoint.Phase)
	}
}

func (o Orchestrator) completePreflight(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint, mode PublicationMode) error {
	preflight, err := o.Cluster.Preflight(ctx)
	if err != nil {
		return fmt.Errorf("rotation cluster preflight failed: %w", err)
	}
	if err := validateOpaqueCheckpointValue("cluster identity", preflight.ClusterIdentity); err != nil {
		return err
	}
	signerState, err := o.observeStableSignerState(ctx, checkpoint.Phase, nil)
	if err != nil {
		return fmt.Errorf("capture stable pre-rotation public signer baseline: %w", err)
	}
	if signerState.Reference == nil {
		return &ConflictError{Phase: checkpoint.Phase, Reason: "the pre-rotation signer Secret is absent"}
	}

	targetIdentity, err := o.Target.ResolveTarget(ctx)
	if err != nil {
		return fmt.Errorf("resolve rotation publication target: %w", err)
	}
	if err := validateOpaqueCheckpointValue("target identity", targetIdentity); err != nil {
		return err
	}
	if mode == PublicationModeDirect {
		if err := o.Publisher.CheckAccess(ctx, targetIdentity); err != nil {
			return fmt.Errorf("validate direct publication access: %w", err)
		}
	}

	baseline := clonePublicSignerBaseline(signerState.Baseline)
	reference := *signerState.Reference
	guard, err := deriveRotationGuardReference(preflight.ClusterIdentity, checkpoint.Provider, targetIdentity, baseline, reference)
	if err != nil {
		return fmt.Errorf("derive signer-rotation guard reference: %w", err)
	}
	return advanceCheckpoint(workspace, checkpoint, PhasePreflightComplete, func(next *Checkpoint) {
		next.ClusterIdentity = preflight.ClusterIdentity
		next.TargetIdentity = targetIdentity
		next.PreRotationSignerBaseline = &baseline
		next.PreRotationSignerRef = &reference
		next.RotationGuard = &guard
	})
}

func (o Orchestrator) captureCurrentJWKS(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint, options RunOptions) error {
	var current []byte
	if options.PublicationMode == PublicationModeManual {
		if len(options.Manual.CurrentJWKS) == 0 {
			return &PauseError{Phase: checkpoint.Phase, Reason: PauseForCurrentJWKS, Artifact: ArtifactCurrentJWKS}
		}
		current = append([]byte(nil), options.Manual.CurrentJWKS...)
	} else {
		observed, err := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
		if err != nil {
			return fmt.Errorf("read current provider JWKS: %w", err)
		}
		current = append([]byte(nil), observed.Data...)
	}

	metadata, err := workspace.WriteArtifact(ArtifactCurrentJWKS, current)
	if err != nil {
		return err
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseCurrentJWKSRead, func(next *Checkpoint) {
		next.Artifacts = append(next.Artifacts, metadata)
	})
}

func (o Orchestrator) requestReplacement(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	guard := *checkpoint.RotationGuard
	observed, err := o.observeStableSignerState(ctx, checkpoint.Phase, checkpoint.RotationGuard)
	if err != nil {
		return fmt.Errorf("observe signer state before replacement request: %w", err)
	}
	progress, _, err := classifySignerState(checkpoint.Phase, observed, *checkpoint)
	if err != nil {
		return err
	}
	if progress != signerStateOriginal {
		return advanceCheckpoint(workspace, checkpoint, PhaseNextKeyRequested, nil)
	}
	if checkpoint.PublicationMode == PublicationModeDirect {
		current, err := workspace.ReadArtifact(ArtifactCurrentJWKS)
		if err != nil {
			return err
		}
		providerState, err := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
		if err != nil {
			return fmt.Errorf("read provider JWKS before signer replacement: %w", err)
		}
		if !bytes.Equal(providerState.Data, current.Data) {
			return &ConflictError{
				Phase:  checkpoint.Phase,
				Reason: fmt.Sprintf("provider JWKS digest %s does not match the recorded current artifact before signer replacement", publicDigest(providerState.Data)),
			}
		}
	}

	outcome, requestErr := o.Cluster.RequestReplacement(ctx, guard, *checkpoint.PreRotationSignerRef)
	if err := validateEffectOutcome(outcome); err != nil {
		return err
	}
	reconciled, observeErr := o.observeStableSignerState(ctx, checkpoint.Phase, checkpoint.RotationGuard)
	if observeErr == nil {
		progress, _, err = classifySignerState(checkpoint.Phase, reconciled, *checkpoint)
		if err != nil {
			return err
		}
		if progress != signerStateOriginal {
			return advanceCheckpoint(workspace, checkpoint, PhaseNextKeyRequested, nil)
		}
	}

	switch outcome {
	case EffectUnknown, EffectSubmitted:
		cause := requestErr
		if cause == nil {
			cause = observeErr
		}
		return &OutcomeUnknownError{Phase: checkpoint.Phase, Operation: "request signer replacement", Cause: cause}
	case EffectNotApplied:
		if requestErr != nil {
			return fmt.Errorf("signer replacement request was not applied: %w", requestErr)
		}
		if observeErr != nil {
			return fmt.Errorf("reconcile unapplied signer replacement request: %w", observeErr)
		}
		return &ConflictError{Phase: checkpoint.Phase, Reason: "the preconditioned signer deletion was not applied and the original signer is still present"}
	default:
		return fmt.Errorf("unsupported signer replacement outcome %q", outcome)
	}
}

func (o Orchestrator) captureReplacementSigner(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	guard := *checkpoint.RotationGuard
	if err := o.Cluster.WaitForReplacement(ctx, guard, *checkpoint.PreRotationSignerRef); err != nil {
		return fmt.Errorf("wait for replacement signer public key: %w", err)
	}
	observed, err := o.observeStableSignerState(ctx, checkpoint.Phase, checkpoint.RotationGuard)
	if err != nil {
		return fmt.Errorf("observe stable replacement signer state: %w", err)
	}
	progress, replacement, err := classifySignerState(checkpoint.Phase, observed, *checkpoint)
	if err != nil {
		return err
	}
	if progress != signerStateReplacementReady || replacement == nil {
		return &OutcomeUnknownError{Phase: checkpoint.Phase, Operation: "wait for replacement signer", Cause: fmt.Errorf("replacement Secret and exactly one appended public signer are not both observable")}
	}

	metadata, err := workspace.WriteArtifact(ArtifactReplacementPublicKey, replacement.PublicPEM)
	if err != nil {
		return err
	}
	evidence := cloneReplacementSignerEvidence(replacement.Evidence)
	return advanceCheckpoint(workspace, checkpoint, PhaseNextPublicKeyRead, func(next *Checkpoint) {
		next.Artifacts = append(next.Artifacts, metadata)
		next.ReplacementSigner = &evidence
	})
}

func buildNewJWKS(workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	prepared, err := prepareFromRecordedArtifacts(workspace)
	if err != nil {
		return err
	}
	metadata, err := workspace.WriteArtifact(ArtifactNewJWKS, prepared.New.Data)
	if err != nil {
		return err
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseNewJWKSBuilt, func(next *Checkpoint) {
		next.Artifacts = append(next.Artifacts, metadata)
	})
}

func buildCombinedJWKS(workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	prepared, err := prepareFromRecordedArtifacts(workspace)
	if err != nil {
		return err
	}
	metadata, err := workspace.WriteArtifact(ArtifactCombinedJWKS, prepared.Combined.Data)
	if err != nil {
		return err
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseCombinedJWKSBuilt, func(next *Checkpoint) {
		next.Artifacts = append(next.Artifacts, metadata)
	})
}

func prepareFromRecordedArtifacts(workspace *RotationWorkspace) (PreparedJWKSArtifacts, error) {
	current, err := workspace.ReadArtifact(ArtifactCurrentJWKS)
	if err != nil {
		return PreparedJWKSArtifacts{}, err
	}
	replacement, err := workspace.ReadArtifact(ArtifactReplacementPublicKey)
	if err != nil {
		return PreparedJWKSArtifacts{}, err
	}
	return PrepareJWKSArtifacts(current.Data, replacement.Data)
}

func (o Orchestrator) publishArtifact(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint, options RunOptions, acknowledgementConsumed *bool, publishedPhase Phase, artifactName, predecessorName string) error {
	if err := o.revalidateRecordedSignerEvidence(ctx, *checkpoint); err != nil {
		return fmt.Errorf("revalidate replacement signer before publication: %w", err)
	}
	desired, err := workspace.ReadArtifact(artifactName)
	if err != nil {
		return err
	}
	if options.PublicationMode == PublicationModeManual {
		if err := validateAndConsumeAcknowledgement(options.Manual.Acknowledgement, acknowledgementConsumed, publishedPhase, desired); err != nil {
			return err
		}
	} else {
		predecessor, err := workspace.ReadArtifact(predecessorName)
		if err != nil {
			return err
		}
		if err := o.publishDirect(ctx, *checkpoint, desired, predecessor); err != nil {
			return err
		}
	}

	confirmation := PublicationConfirmation{Phase: publishedPhase, Artifact: artifactName, SHA256: desired.Metadata.SHA256}
	return advanceCheckpoint(workspace, checkpoint, publishedPhase, func(next *Checkpoint) {
		next.Publications = append(next.Publications, confirmation)
	})
}

func validateAndConsumeAcknowledgement(acknowledgement *ManualAcknowledgement, consumed *bool, expectedPhase Phase, desired StoredArtifact) error {
	if acknowledgement == nil || *consumed {
		return &PauseError{
			Phase:    phaseBefore(expectedPhase),
			Reason:   PauseForPublication,
			Artifact: desired.Metadata.Name,
			Path:     desired.Path,
			SHA256:   desired.Metadata.SHA256,
		}
	}
	if acknowledgement.Phase != expectedPhase || acknowledgement.Artifact != desired.Metadata.Name || acknowledgement.SHA256 != desired.Metadata.SHA256 {
		return &ConflictError{Phase: phaseBefore(expectedPhase), Reason: "the manual acknowledgement does not match the required phase, artifact, and SHA-256 digest"}
	}
	*consumed = true
	return nil
}

func (o Orchestrator) publishDirect(ctx context.Context, checkpoint Checkpoint, desired, predecessor StoredArtifact) error {
	observed, err := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
	if err != nil {
		return fmt.Errorf("read provider JWKS before conditional publication: %w", err)
	}
	if bytes.Equal(observed.Data, desired.Data) {
		return nil
	}
	if !bytes.Equal(observed.Data, predecessor.Data) {
		return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("provider JWKS digest %s is neither the recorded predecessor nor the desired artifact", publicDigest(observed.Data))}
	}
	if strings.TrimSpace(observed.Revision) == "" {
		return fmt.Errorf("provider JWKS read did not return the revision required for conditional publication")
	}

	outcome, publishErr := o.Publisher.PublishIfVersion(ctx, checkpoint.TargetIdentity, observed.Revision, append([]byte(nil), desired.Data...))
	if err := validateEffectOutcome(outcome); err != nil {
		return err
	}
	readback, readbackErr := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
	if readbackErr == nil && bytes.Equal(readback.Data, desired.Data) {
		return nil
	}

	switch outcome {
	case EffectUnknown, EffectSubmitted:
		cause := publishErr
		if cause == nil {
			cause = readbackErr
		}
		return &OutcomeUnknownError{Phase: checkpoint.Phase, Operation: "conditionally publish provider JWKS", Cause: cause}
	case EffectNotApplied:
		if publishErr != nil {
			return fmt.Errorf("conditional provider JWKS publication was not applied: %w", publishErr)
		}
		if readbackErr != nil {
			return fmt.Errorf("read provider JWKS after rejected conditional publication: %w", readbackErr)
		}
		return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("conditional provider write was rejected and the target now has digest %s", publicDigest(readback.Data))}
	default:
		return fmt.Errorf("unsupported provider publication outcome %q", outcome)
	}
}

func (o Orchestrator) waitForSignerRollout(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	replacementKeyID, err := recordedReplacementKeyID(workspace)
	if err != nil {
		return err
	}
	guard := *checkpoint.RotationGuard
	if err := o.Cluster.WaitForSignerRollout(ctx, guard, replacementKeyID); err != nil {
		return fmt.Errorf("wait for replacement signer rollout: %w", err)
	}
	if err := o.revalidateRecordedSignerEvidence(ctx, *checkpoint); err != nil {
		return fmt.Errorf("revalidate replacement signer after rollout: %w", err)
	}
	if checkpoint.PublicationMode == PublicationModeDirect {
		combined, err := workspace.ReadArtifact(ArtifactCombinedJWKS)
		if err != nil {
			return err
		}
		observed, err := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
		if err != nil {
			return fmt.Errorf("read provider JWKS before node reboot: %w", err)
		}
		if !bytes.Equal(observed.Data, combined.Data) {
			return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("provider JWKS digest %s does not match the recorded combined artifact before node reboot", publicDigest(observed.Data))}
		}
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseSignerRolloutStable, nil)
}

func (o Orchestrator) recordRebootIntent(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	replacementKeyID, err := recordedReplacementKeyID(workspace)
	if err != nil {
		return err
	}
	operationID, err := rebootIntentID(checkpoint.ClusterIdentity, replacementKeyID)
	if err != nil {
		return fmt.Errorf("derive node reboot operation ID: %w", err)
	}
	observation, err := o.observeCanonicalReboot(ctx, *checkpoint.RotationGuard, operationID)
	if err != nil {
		return fmt.Errorf("observe existing node reboot record: %w", err)
	}

	var intent RebootIntent
	if observation.CanonicalIntent != nil {
		intent = cloneRebootIntent(*observation.CanonicalIntent)
	} else {
		plan, err := o.Cluster.PrepareReboot(ctx, *checkpoint.RotationGuard, replacementKeyID)
		if err != nil {
			return fmt.Errorf("prepare node reboot intent: %w", err)
		}
		intent, err = buildRebootIntent(checkpoint.ClusterIdentity, replacementKeyID, plan)
		if err != nil {
			return fmt.Errorf("validate node reboot intent: %w", err)
		}
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseRebootIntentRecorded, func(next *Checkpoint) {
		next.RebootIntent = &intent
	})
}

func (o Orchestrator) completeReboot(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	status, intent, err := o.observeAndAdoptCanonicalReboot(ctx, workspace, checkpoint)
	if err != nil {
		return fmt.Errorf("observe persisted node reboot intent: %w", err)
	}
	if status == RebootComplete {
		return advanceCheckpoint(workspace, checkpoint, PhaseNodesRebooted, nil)
	}

	if status == RebootNotStarted {
		outcome, requestErr := o.Cluster.RequestReboot(ctx, *checkpoint.RotationGuard, cloneRebootIntent(intent))
		if err := validateEffectOutcome(outcome); err != nil {
			return err
		}
		status, intent, err = o.observeAndAdoptCanonicalReboot(ctx, workspace, checkpoint)
		if err != nil {
			if outcome == EffectUnknown || outcome == EffectSubmitted {
				return &OutcomeUnknownError{Phase: checkpoint.Phase, Operation: "request persisted node reboot", Cause: errors.Join(requestErr, err)}
			}
			return fmt.Errorf("reconcile node reboot request: %w", err)
		}
		if status == RebootComplete {
			return advanceCheckpoint(workspace, checkpoint, PhaseNodesRebooted, nil)
		}
		if status == RebootNotStarted {
			switch outcome {
			case EffectUnknown, EffectSubmitted:
				return &OutcomeUnknownError{Phase: checkpoint.Phase, Operation: "request persisted node reboot", Cause: requestErr}
			case EffectNotApplied:
				if requestErr != nil {
					return fmt.Errorf("node reboot request was not applied: %w", requestErr)
				}
				return &ConflictError{Phase: checkpoint.Phase, Reason: "the persisted reboot request was not applied"}
			}
		}
	}

	if err := o.Cluster.WaitForReboot(ctx, *checkpoint.RotationGuard, cloneRebootIntent(intent)); err != nil {
		return fmt.Errorf("wait for persisted node reboot: %w", err)
	}
	status, intent, err = o.observeAndAdoptCanonicalReboot(ctx, workspace, checkpoint)
	if err != nil {
		return fmt.Errorf("confirm persisted node reboot completion: %w", err)
	}
	if status != RebootComplete {
		return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("reboot wait returned before intent %q was complete", intent.ID)}
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseNodesRebooted, nil)
}

func (o Orchestrator) observeCanonicalReboot(ctx context.Context, guard RotationGuardReference, operationID string) (RebootObservation, error) {
	observation, err := o.Cluster.ObserveReboot(ctx, guard, operationID)
	if err != nil {
		return RebootObservation{}, err
	}
	if err := validateRebootObservation(operationID, observation); err != nil {
		return RebootObservation{}, err
	}
	if observation.CanonicalIntent != nil {
		intent := cloneRebootIntent(*observation.CanonicalIntent)
		observation.CanonicalIntent = &intent
	}
	return observation, nil
}

func (o Orchestrator) observeAndAdoptCanonicalReboot(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) (RebootStatus, RebootIntent, error) {
	localIntent := cloneRebootIntent(*checkpoint.RebootIntent)
	observation, err := o.observeCanonicalReboot(ctx, *checkpoint.RotationGuard, localIntent.ID)
	if err != nil {
		return "", RebootIntent{}, err
	}
	if observation.CanonicalIntent == nil || reflect.DeepEqual(localIntent, *observation.CanonicalIntent) {
		return observation.Status, localIntent, nil
	}
	if checkpoint.Phase != PhaseRebootIntentRecorded {
		return "", RebootIntent{}, &ConflictError{
			Phase:  checkpoint.Phase,
			Reason: fmt.Sprintf("cluster reboot record %q differs from the checkpoint after reboot completion was recorded", localIntent.ID),
		}
	}

	canonicalIntent := cloneRebootIntent(*observation.CanonicalIntent)
	next := cloneCheckpoint(*checkpoint)
	next.RebootIntent = &canonicalIntent
	next.LastErrorCode = ""
	if err := workspace.saveCheckpointAdoptingCanonicalRebootIntent(next); err != nil {
		return "", RebootIntent{}, fmt.Errorf("persist cluster-canonical reboot intent: %w", err)
	}
	*checkpoint = next
	return observation.Status, cloneRebootIntent(canonicalIntent), nil
}

func (o Orchestrator) waitForPostRebootStability(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	intent := cloneRebootIntent(*checkpoint.RebootIntent)
	if err := o.Cluster.WaitForPostRebootStable(ctx, *checkpoint.RotationGuard, intent); err != nil {
		return fmt.Errorf("wait for post-reboot cluster stability: %w", err)
	}
	return advanceCheckpoint(workspace, checkpoint, PhasePostRebootStable, nil)
}

func (o Orchestrator) reconcileRecordedState(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	if checkpoint.Phase == PhaseInitialized {
		return nil
	}
	if checkpoint.Phase == PhasePreflightComplete {
		// The exact reference is durable but the external guard may not have
		// been acquired yet. The next phase reconciles that mutation before
		// any guarded signer observation.
		return nil
	}
	if checkpoint.Phase == PhaseGuardReleaseRecorded || checkpoint.Phase == PhaseComplete {
		// Once exact terminal completion is observable, signer and provider
		// state may legitimately belong to a later rotation.
		return o.reconcileReleasedRotationGuard(ctx, *checkpoint)
	}
	if err := o.requireRotationGuardHeld(ctx, *checkpoint); err != nil {
		return err
	}
	guard := *checkpoint.RotationGuard

	targetIdentity, err := o.Target.ResolveTarget(ctx)
	if err != nil {
		return fmt.Errorf("resolve rotation publication target during reconciliation: %w", err)
	}
	if targetIdentity != checkpoint.TargetIdentity {
		return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("resolved target identity %q does not match checkpoint target %q", targetIdentity, checkpoint.TargetIdentity)}
	}
	if checkpoint.PublicationMode == PublicationModeDirect && checkpoint.Phase != PhaseComplete {
		if err := o.Publisher.CheckAccess(ctx, targetIdentity); err != nil {
			return fmt.Errorf("validate direct publication access during reconciliation: %w", err)
		}
	}
	if checkpoint.RebootIntent != nil {
		if _, _, err := o.observeAndAdoptCanonicalReboot(ctx, workspace, checkpoint); err != nil {
			return fmt.Errorf("reconcile cluster-canonical reboot intent: %w", err)
		}
	}
	signerState, err := o.observeStableSignerState(ctx, checkpoint.Phase, checkpoint.RotationGuard)
	if err != nil {
		return fmt.Errorf("reconcile signer state: %w", err)
	}
	if err := validateRecordedSignerState(checkpoint.Phase, signerState, *checkpoint); err != nil {
		return err
	}

	expectation, err := clusterExpectation(workspace, *checkpoint)
	if err != nil {
		return err
	}
	if err := o.Cluster.Reconcile(ctx, guard, expectation); err != nil {
		return fmt.Errorf("reconcile cluster state at phase %q: %w", checkpoint.Phase, err)
	}

	if checkpoint.PublicationMode != PublicationModeDirect {
		return nil
	}
	artifactName := ""
	switch {
	case phaseAtLeast(checkpoint.Phase, PhaseNewOnlyJWKSPublished):
		artifactName = ArtifactNewJWKS
	case checkpoint.Phase == PhasePostRebootStable:
		combined, err := workspace.ReadArtifact(ArtifactCombinedJWKS)
		if err != nil {
			return err
		}
		newOnly, err := workspace.ReadArtifact(ArtifactNewJWKS)
		if err != nil {
			return err
		}
		observed, err := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
		if err != nil {
			return fmt.Errorf("read provider JWKS during final-publication reconciliation: %w", err)
		}
		if !bytes.Equal(observed.Data, combined.Data) && !bytes.Equal(observed.Data, newOnly.Data) {
			return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("provider JWKS digest %s is neither the recorded combined predecessor nor the new-only artifact", publicDigest(observed.Data))}
		}
		return nil
	case phaseAtLeast(checkpoint.Phase, PhaseCombinedJWKSPublished):
		artifactName = ArtifactCombinedJWKS
	default:
		return nil
	}
	expected, err := workspace.ReadArtifact(artifactName)
	if err != nil {
		return err
	}
	observed, err := o.Publisher.ReadJWKS(ctx, checkpoint.TargetIdentity)
	if err != nil {
		return fmt.Errorf("read provider JWKS during reconciliation: %w", err)
	}
	if !bytes.Equal(observed.Data, expected.Data) {
		return &ConflictError{Phase: checkpoint.Phase, Reason: fmt.Sprintf("provider JWKS digest %s does not match recorded artifact %q", publicDigest(observed.Data), artifactName)}
	}
	return nil
}

func clusterExpectation(workspace *RotationWorkspace, checkpoint Checkpoint) (ClusterExpectation, error) {
	expectation := ClusterExpectation{
		Phase:                     checkpoint.Phase,
		ClusterIdentity:           checkpoint.ClusterIdentity,
		RotationGuard:             *checkpoint.RotationGuard,
		PreRotationSignerBaseline: clonePublicSignerBaseline(*checkpoint.PreRotationSignerBaseline),
		PreRotationSignerRef:      *checkpoint.PreRotationSignerRef,
	}
	if phaseAtLeast(checkpoint.Phase, PhaseNextPublicKeyRead) {
		replacementKeyID, err := recordedReplacementKeyID(workspace)
		if err != nil {
			return ClusterExpectation{}, err
		}
		if replacementKeyID != checkpoint.ReplacementSigner.Entry.KeyID {
			return ClusterExpectation{}, fmt.Errorf("recorded replacement public key does not match checkpoint replacement evidence")
		}
		evidence := cloneReplacementSignerEvidence(*checkpoint.ReplacementSigner)
		expectation.ReplacementSigner = &evidence
	}
	if checkpoint.RebootIntent != nil {
		intent := cloneRebootIntent(*checkpoint.RebootIntent)
		expectation.RebootIntent = &intent
	}
	return expectation, nil
}
func recordedReplacementKeyID(workspace *RotationWorkspace) (string, error) {
	replacement, err := workspace.ReadArtifact(ArtifactReplacementPublicKey)
	if err != nil {
		return "", err
	}
	if len(replacement.Metadata.KeyIDs) != 1 {
		return "", fmt.Errorf("replacement signer artifact must record exactly one key ID")
	}
	return replacement.Metadata.KeyIDs[0], nil
}

func validateEffectOutcome(outcome EffectOutcome) error {
	switch outcome {
	case EffectSubmitted, EffectNotApplied, EffectUnknown:
		return nil
	default:
		return fmt.Errorf("adapter returned unsupported external effect outcome %q", outcome)
	}
}

func validateRebootStatus(status RebootStatus) error {
	switch status {
	case RebootNotStarted, RebootInProgress, RebootComplete:
		return nil
	default:
		return fmt.Errorf("adapter returned unsupported reboot status %q", status)
	}
}

func validateRebootObservation(operationID string, observation RebootObservation) error {
	if err := validateOpaqueCheckpointValue("reboot operation ID", operationID); err != nil {
		return err
	}
	if err := validateRebootStatus(observation.Status); err != nil {
		return err
	}
	if observation.Status == RebootNotStarted {
		if observation.CanonicalIntent != nil {
			return fmt.Errorf("adapter returned a canonical reboot intent for status %q", RebootNotStarted)
		}
		return nil
	}
	if observation.CanonicalIntent == nil {
		return fmt.Errorf("adapter returned reboot status %q without the canonical reboot intent", observation.Status)
	}
	if err := validateRebootIntent(*observation.CanonicalIntent); err != nil {
		return fmt.Errorf("adapter returned an invalid canonical reboot intent: %w", err)
	}
	if observation.CanonicalIntent.ID != operationID {
		return fmt.Errorf("adapter returned canonical reboot intent %q for operation %q", observation.CanonicalIntent.ID, operationID)
	}
	return nil
}

func phaseBefore(phase Phase) Phase {
	position := phasePosition(phase)
	if position <= 0 {
		return ""
	}
	return orderedPhases[position-1]
}

func advanceCheckpoint(workspace *RotationWorkspace, checkpoint *Checkpoint, nextPhase Phase, mutate func(*Checkpoint)) error {
	next := cloneCheckpoint(*checkpoint)
	next.Phase = nextPhase
	next.LastErrorCode = ""
	if mutate != nil {
		mutate(&next)
	}
	if err := workspace.SaveCheckpoint(next); err != nil {
		return err
	}
	*checkpoint = next
	return nil
}

func recordCheckpointError(workspace *RotationWorkspace, checkpoint *Checkpoint, code string) {
	if code == "" || checkpoint.Phase == "" {
		return
	}
	next := cloneCheckpoint(*checkpoint)
	next.LastErrorCode = code
	if err := workspace.SaveCheckpoint(next); err == nil {
		*checkpoint = next
	}
}

func classifyCheckpointError(err error, phase Phase) string {
	var pause *PauseError
	if errors.As(err, &pause) {
		return errorCodeManualInputRequired
	}
	var unknown *OutcomeUnknownError
	if errors.As(err, &unknown) {
		return errorCodeExternalOutcomeUnknown
	}
	var conflict *ConflictError
	if errors.As(err, &conflict) {
		return errorCodeConflict
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errorCodeCancelled
	}
	if phase == "" {
		return "operation-failed"
	}
	return string(phase) + "-failed"
}

func cloneCheckpoint(checkpoint Checkpoint) Checkpoint {
	clone := checkpoint
	clone.Artifacts = make([]ArtifactMetadata, len(checkpoint.Artifacts))
	for index, artifact := range checkpoint.Artifacts {
		clone.Artifacts[index] = artifact
		clone.Artifacts[index].KeyIDs = append([]string(nil), artifact.KeyIDs...)
	}
	clone.Publications = append([]PublicationConfirmation(nil), checkpoint.Publications...)
	if checkpoint.PreRotationSignerBaseline != nil {
		baseline := clonePublicSignerBaseline(*checkpoint.PreRotationSignerBaseline)
		clone.PreRotationSignerBaseline = &baseline
	}
	if checkpoint.PreRotationSignerRef != nil {
		reference := *checkpoint.PreRotationSignerRef
		clone.PreRotationSignerRef = &reference
	}
	if checkpoint.RotationGuard != nil {
		reference := *checkpoint.RotationGuard
		clone.RotationGuard = &reference
	}
	if checkpoint.ReplacementSigner != nil {
		evidence := cloneReplacementSignerEvidence(*checkpoint.ReplacementSigner)
		clone.ReplacementSigner = &evidence
	}
	if checkpoint.RebootIntent != nil {
		intent := cloneRebootIntent(*checkpoint.RebootIntent)
		clone.RebootIntent = &intent
	}
	return clone
}

func cloneRebootIntent(intent RebootIntent) RebootIntent {
	intent.Targets = append([]string(nil), intent.Targets...)
	intent.Baselines = append([]NodeRebootBaseline(nil), intent.Baselines...)
	return intent
}

func clonePublicSignerBaseline(baseline PublicSignerBaseline) PublicSignerBaseline {
	baseline.Entries = append([]PublicSignerBaselineEntry(nil), baseline.Entries...)
	return baseline
}

func cloneReplacementSignerEvidence(evidence ReplacementSignerEvidence) ReplacementSignerEvidence {
	return evidence
}

func publicDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest)
}

package rotation

import (
	"context"
	"errors"
	"fmt"
)

func (o Orchestrator) observeRotationGuard(ctx context.Context, reference RotationGuardReference) (RotationGuardObservation, error) {
	observation, err := o.Cluster.ObserveRotationGuard(ctx, reference)
	if err != nil {
		return RotationGuardObservation{}, err
	}
	if err := validateRotationGuardObservation(reference, observation); err != nil {
		return RotationGuardObservation{}, err
	}
	return observation, nil
}

func validateRotationGuardObservation(reference RotationGuardReference, observation RotationGuardObservation) error {
	if err := validateRotationGuardReference(reference); err != nil {
		return err
	}
	switch observation.Status {
	case RotationGuardNotFound:
		if observation.OperationID != "" {
			return fmt.Errorf("adapter returned operation ID %q for rotation guard status %q", observation.OperationID, observation.Status)
		}
	case RotationGuardHeld, RotationGuardCompleted:
		if observation.OperationID != reference.OperationID {
			return fmt.Errorf("adapter returned rotation guard operation %q for requested operation %q", observation.OperationID, reference.OperationID)
		}
	case RotationGuardOwnedByOther:
		if err := validateSHA256(observation.OperationID); err != nil {
			return fmt.Errorf("adapter returned invalid conflicting rotation guard operation ID: %w", err)
		}
		if observation.OperationID == reference.OperationID {
			return fmt.Errorf("adapter reported requested rotation guard operation %q as owned by another operation", observation.OperationID)
		}
	default:
		return fmt.Errorf("adapter returned unsupported rotation guard status %q", observation.Status)
	}
	return nil
}

func (o Orchestrator) acquireRotationGuard(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	reference, err := checkpointRotationGuard(*checkpoint)
	if err != nil {
		return err
	}
	observation, err := o.observeRotationGuard(ctx, reference)
	if err != nil {
		return fmt.Errorf("observe signer-rotation guard before acquisition: %w", err)
	}
	switch observation.Status {
	case RotationGuardHeld:
		return o.persistAcquiredRotationGuard(ctx, workspace, checkpoint, reference)
	case RotationGuardCompleted:
		return rotationGuardConflict(checkpoint.Phase, reference, "the exact signer-rotation operation was already completed before this checkpoint acquired it")
	case RotationGuardOwnedByOther:
		return rotationGuardOwnedByOther(checkpoint.Phase, reference, observation.OperationID)
	case RotationGuardNotFound:
	}

	outcome, acquireErr := o.Cluster.AcquireRotationGuard(ctx, reference)
	if err := validateEffectOutcome(outcome); err != nil {
		return err
	}
	observed, observeErr := o.observeRotationGuard(ctx, reference)
	if observeErr == nil {
		switch observed.Status {
		case RotationGuardHeld:
			return o.persistAcquiredRotationGuard(ctx, workspace, checkpoint, reference)
		case RotationGuardOwnedByOther:
			return rotationGuardOwnedByOther(checkpoint.Phase, reference, observed.OperationID)
		case RotationGuardCompleted:
			return rotationGuardConflict(checkpoint.Phase, reference, "the exact signer-rotation operation completed while acquisition was being reconciled")
		case RotationGuardNotFound:
		}
	}

	switch outcome {
	case EffectUnknown, EffectSubmitted:
		return &OutcomeUnknownError{
			Phase:     checkpoint.Phase,
			Operation: "acquire cluster-wide signer-rotation guard",
			Cause:     errors.Join(acquireErr, observeErr),
		}
	case EffectNotApplied:
		if acquireErr != nil {
			return fmt.Errorf("signer-rotation guard acquisition was not applied: %w", acquireErr)
		}
		if observeErr != nil {
			return fmt.Errorf("reconcile unapplied signer-rotation guard acquisition: %w", observeErr)
		}
		return rotationGuardConflict(checkpoint.Phase, reference, "the signer-rotation guard acquisition was not applied")
	default:
		return fmt.Errorf("unsupported signer-rotation guard acquisition outcome %q", outcome)
	}
}

func (o Orchestrator) persistAcquiredRotationGuard(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint, reference RotationGuardReference) error {
	state, err := o.observeStableSignerState(ctx, checkpoint.Phase, &reference)
	if err != nil {
		return fmt.Errorf("observe signer state after acquiring rotation guard: %w", err)
	}
	if err := validateRecordedSignerState(checkpoint.Phase, state, *checkpoint); err != nil {
		return err
	}
	return advanceCheckpoint(workspace, checkpoint, PhaseGuardAcquired, nil)
}

func (o Orchestrator) requireRotationGuardHeld(ctx context.Context, checkpoint Checkpoint) error {
	reference, err := checkpointRotationGuard(checkpoint)
	if err != nil {
		return err
	}
	observation, err := o.observeRotationGuard(ctx, reference)
	if err != nil {
		return fmt.Errorf("observe signer-rotation guard ownership: %w", err)
	}
	switch observation.Status {
	case RotationGuardHeld:
		return nil
	case RotationGuardOwnedByOther:
		return rotationGuardOwnedByOther(checkpoint.Phase, reference, observation.OperationID)
	case RotationGuardCompleted:
		return rotationGuardConflict(checkpoint.Phase, reference, "the signer-rotation guard was released before this checkpoint reached its release phase")
	case RotationGuardNotFound:
		return rotationGuardConflict(checkpoint.Phase, reference, "the signer-rotation guard is no longer observable")
	default:
		return fmt.Errorf("unsupported signer-rotation guard status %q", observation.Status)
	}
}

func (o Orchestrator) releaseRotationGuard(ctx context.Context, workspace *RotationWorkspace, checkpoint *Checkpoint) error {
	reference, err := checkpointRotationGuard(*checkpoint)
	if err != nil {
		return err
	}
	observation, err := o.observeRotationGuard(ctx, reference)
	if err != nil {
		return fmt.Errorf("observe signer-rotation guard before release: %w", err)
	}
	switch observation.Status {
	case RotationGuardCompleted:
		return advanceCheckpoint(workspace, checkpoint, PhaseComplete, nil)
	case RotationGuardOwnedByOther:
		return rotationGuardOwnedByOther(checkpoint.Phase, reference, observation.OperationID)
	case RotationGuardNotFound:
		return rotationGuardConflict(checkpoint.Phase, reference, "the signer-rotation guard disappeared before a durable completion record was observed")
	case RotationGuardHeld:
	}

	outcome, releaseErr := o.Cluster.ReleaseRotationGuard(ctx, reference)
	if err := validateEffectOutcome(outcome); err != nil {
		return err
	}
	observed, observeErr := o.observeRotationGuard(ctx, reference)
	if observeErr == nil {
		switch observed.Status {
		case RotationGuardCompleted:
			return advanceCheckpoint(workspace, checkpoint, PhaseComplete, nil)
		case RotationGuardOwnedByOther:
			return rotationGuardOwnedByOther(checkpoint.Phase, reference, observed.OperationID)
		case RotationGuardNotFound, RotationGuardHeld:
		}
	}

	switch outcome {
	case EffectUnknown, EffectSubmitted:
		return &OutcomeUnknownError{
			Phase:     checkpoint.Phase,
			Operation: "release cluster-wide signer-rotation guard",
			Cause:     errors.Join(releaseErr, observeErr),
		}
	case EffectNotApplied:
		if releaseErr != nil {
			return fmt.Errorf("signer-rotation guard release was not applied: %w", releaseErr)
		}
		if observeErr != nil {
			return fmt.Errorf("reconcile unapplied signer-rotation guard release: %w", observeErr)
		}
		return rotationGuardConflict(checkpoint.Phase, reference, "the signer-rotation guard release was not applied")
	default:
		return fmt.Errorf("unsupported signer-rotation guard release outcome %q", outcome)
	}
}

func (o Orchestrator) reconcileReleasedRotationGuard(ctx context.Context, checkpoint Checkpoint) error {
	reference, err := checkpointRotationGuard(checkpoint)
	if err != nil {
		return err
	}
	observation, err := o.observeRotationGuard(ctx, reference)
	if err != nil {
		return fmt.Errorf("reconcile signer-rotation guard completion: %w", err)
	}
	if observation.Status == RotationGuardOwnedByOther {
		return rotationGuardOwnedByOther(checkpoint.Phase, reference, observation.OperationID)
	}
	if checkpoint.Phase == PhaseComplete && observation.Status != RotationGuardCompleted {
		return rotationGuardConflict(checkpoint.Phase, reference, "the completed checkpoint has no durable signer-rotation guard completion record")
	}
	if checkpoint.Phase == PhaseGuardReleaseRecorded && observation.Status != RotationGuardHeld && observation.Status != RotationGuardCompleted {
		return rotationGuardConflict(checkpoint.Phase, reference, "the signer-rotation guard is neither held nor durably completed at the release checkpoint")
	}
	return nil
}

func checkpointRotationGuard(checkpoint Checkpoint) (RotationGuardReference, error) {
	if checkpoint.RotationGuard == nil {
		return RotationGuardReference{}, fmt.Errorf("checkpoint is missing the signer-rotation guard reference")
	}
	reference := *checkpoint.RotationGuard
	if err := validateRotationGuardReference(reference); err != nil {
		return RotationGuardReference{}, err
	}
	return reference, nil
}

func rotationGuardOwnedByOther(phase Phase, reference RotationGuardReference, owner string) error {
	return &ConflictError{
		Phase:  phase,
		Reason: fmt.Sprintf("signer-rotation guard scope %q is owned by different operation %q instead of %q", reference.ScopeID, owner, reference.OperationID),
	}
}

func rotationGuardConflict(phase Phase, reference RotationGuardReference, reason string) error {
	return &ConflictError{
		Phase:  phase,
		Reason: fmt.Sprintf("signer-rotation guard operation %q: %s", reference.OperationID, reason),
	}
}

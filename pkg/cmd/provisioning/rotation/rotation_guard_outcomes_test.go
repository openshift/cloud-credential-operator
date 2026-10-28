package rotation

import (
	"context"
	"errors"
	"testing"
)

const otherGuardOperationID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func TestAcquireRotationGuardRejectsPreexistingConflictsWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		status RotationGuardStatus
	}{
		{name: "completed operation", status: RotationGuardCompleted},
		{name: "different owner", status: RotationGuardOwnedByOther},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeManual)
			status := test.status
			cluster := &guardOutcomeTestCluster{
				fakeClusterRotation:     harness.cluster,
				initialGuardObservation: &status,
			}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()

			result, err := harness.orchestrator.Run(context.Background(), RunOptions{
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeManual,
				OutputDir:       outputDir,
			})
			var conflict *ConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("Run() error = %v, want ConflictError", err)
			}
			if result.Phase != PhasePreflightComplete || result.Complete {
				t.Fatalf("Run() result = %#v, want stable preflight checkpoint", result)
			}
			if harness.cluster.guardAcquireCalls != 0 || harness.cluster.guardAcquireMutations != 0 {
				t.Fatalf("guard acquisition = calls %d, mutations %d; want 0, 0", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
			}
			requireGuardOutcomeCheckpointPhase(t, outputDir, PhasePreflightComplete)
		})
	}
}

func TestAcquireRotationGuardRetriesOnlyProvenUnappliedEffects(t *testing.T) {
	mutationErr := errors.New("guard acquisition rejected")
	readbackErr := errors.New("guard acquisition readback failed")

	for _, test := range []struct {
		name         string
		plan         guardMutationTestPlan
		wantCause    error
		wantConflict bool
	}{
		{
			name:      "mutation error",
			plan:      guardMutationTestPlan{outcome: EffectNotApplied, mutationErr: mutationErr},
			wantCause: mutationErr,
		},
		{
			name:      "readback error",
			plan:      guardMutationTestPlan{outcome: EffectNotApplied, readbackErr: readbackErr},
			wantCause: readbackErr,
		},
		{
			name:         "still not found",
			plan:         guardMutationTestPlan{outcome: EffectNotApplied},
			wantConflict: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeManual)
			plan := test.plan
			cluster := &guardOutcomeTestCluster{fakeClusterRotation: harness.cluster, acquirePlan: &plan}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()
			options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: outputDir}

			result, err := harness.orchestrator.Run(context.Background(), options)
			if test.wantConflict {
				var conflict *ConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("Run() error = %v, want ConflictError", err)
				}
			} else if !errors.Is(err, test.wantCause) {
				t.Fatalf("Run() error = %v, want cause %v", err, test.wantCause)
			}
			if result.Phase != PhasePreflightComplete || result.Complete {
				t.Fatalf("Run() result = %#v, want stable preflight checkpoint", result)
			}
			if harness.cluster.guardAcquireCalls != 1 || harness.cluster.guardAcquireMutations != 0 {
				t.Fatalf("guard acquisition = calls %d, mutations %d; want 1, 0", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
			}
			requireGuardOutcomeCheckpointPhase(t, outputDir, PhasePreflightComplete)

			options.Resume = true
			result, err = harness.orchestrator.Run(context.Background(), options)
			requireOrchestratorPause(t, err, PhaseGuardAcquired, PauseForCurrentJWKS, ArtifactCurrentJWKS)
			if result.Phase != PhaseGuardAcquired || result.Complete {
				t.Fatalf("resumed Run() result = %#v, want guard-acquired pause", result)
			}
			if harness.cluster.guardAcquireCalls != 2 || harness.cluster.guardAcquireMutations != 1 {
				t.Fatalf("guard acquisition after safe retry = calls %d, mutations %d; want 2, 1", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
			}
		})
	}
}

func TestAcquireRotationGuardReconcilesUncertainAppliedEffectsWithoutReplay(t *testing.T) {
	for _, outcome := range []EffectOutcome{EffectUnknown, EffectSubmitted} {
		t.Run(string(outcome), func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeManual)
			plan := guardMutationTestPlan{
				outcome:     outcome,
				apply:       true,
				mutationErr: errors.New("guard acquisition response lost"),
				readbackErr: errors.New("guard acquisition readback interrupted"),
			}
			cluster := &guardOutcomeTestCluster{fakeClusterRotation: harness.cluster, acquirePlan: &plan}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()
			options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: outputDir}

			result, err := harness.orchestrator.Run(context.Background(), options)
			var unknown *OutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("Run() error = %v, want OutcomeUnknownError", err)
			}
			if result.Phase != PhasePreflightComplete || result.Complete {
				t.Fatalf("Run() result = %#v, want stable preflight checkpoint", result)
			}
			if harness.cluster.guardAcquireCalls != 1 || harness.cluster.guardAcquireMutations != 1 {
				t.Fatalf("guard acquisition = calls %d, mutations %d; want 1, 1", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
			}

			options.Resume = true
			result, err = harness.orchestrator.Run(context.Background(), options)
			requireOrchestratorPause(t, err, PhaseGuardAcquired, PauseForCurrentJWKS, ArtifactCurrentJWKS)
			if result.Phase != PhaseGuardAcquired || result.Complete {
				t.Fatalf("resumed Run() result = %#v, want guard-acquired pause", result)
			}
			if harness.cluster.guardAcquireCalls != 1 || harness.cluster.guardAcquireMutations != 1 {
				t.Fatalf("guard acquisition was replayed: calls %d, mutations %d; want 1, 1", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
			}
		})
	}
}

func TestReleaseRotationGuardRetriesOnlyProvenUnappliedEffects(t *testing.T) {
	mutationErr := errors.New("guard release rejected")
	readbackErr := errors.New("guard release readback failed")

	for _, test := range []struct {
		name         string
		plan         guardMutationTestPlan
		wantCause    error
		wantConflict bool
	}{
		{
			name:      "mutation error",
			plan:      guardMutationTestPlan{outcome: EffectNotApplied, mutationErr: mutationErr},
			wantCause: mutationErr,
		},
		{
			name:      "readback error",
			plan:      guardMutationTestPlan{outcome: EffectNotApplied, readbackErr: readbackErr},
			wantCause: readbackErr,
		},
		{
			name:         "still held",
			plan:         guardMutationTestPlan{outcome: EffectNotApplied},
			wantConflict: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeDirect)
			plan := test.plan
			cluster := &guardOutcomeTestCluster{fakeClusterRotation: harness.cluster, releasePlan: &plan}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()
			options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

			result, err := harness.orchestrator.Run(context.Background(), options)
			if test.wantConflict {
				var conflict *ConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("Run() error = %v, want ConflictError", err)
				}
			} else if !errors.Is(err, test.wantCause) {
				t.Fatalf("Run() error = %v, want cause %v", err, test.wantCause)
			}
			if result.Phase != PhaseGuardReleaseRecorded || result.Complete {
				t.Fatalf("Run() result = %#v, want stable guard-release checkpoint", result)
			}
			if harness.cluster.guardReleaseCalls != 1 || harness.cluster.guardReleaseMutations != 0 {
				t.Fatalf("guard release = calls %d, mutations %d; want 1, 0", harness.cluster.guardReleaseCalls, harness.cluster.guardReleaseMutations)
			}
			requireGuardOutcomeCheckpointPhase(t, outputDir, PhaseGuardReleaseRecorded)

			options.Resume = true
			result, err = harness.orchestrator.Run(context.Background(), options)
			if err != nil || !result.Complete || result.Phase != PhaseComplete {
				t.Fatalf("resumed Run() result = %#v, error = %v; want complete", result, err)
			}
			if harness.cluster.guardReleaseCalls != 2 || harness.cluster.guardReleaseMutations != 1 {
				t.Fatalf("guard release after safe retry = calls %d, mutations %d; want 2, 1", harness.cluster.guardReleaseCalls, harness.cluster.guardReleaseMutations)
			}
		})
	}
}

func TestReleaseRotationGuardReconcilesUncertainAppliedEffectsWithoutReplay(t *testing.T) {
	for _, outcome := range []EffectOutcome{EffectUnknown, EffectSubmitted} {
		t.Run(string(outcome), func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeDirect)
			plan := guardMutationTestPlan{
				outcome:     outcome,
				apply:       true,
				mutationErr: errors.New("guard release response lost"),
				readbackErr: errors.New("guard release readback interrupted"),
			}
			cluster := &guardOutcomeTestCluster{fakeClusterRotation: harness.cluster, releasePlan: &plan}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()
			options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

			result, err := harness.orchestrator.Run(context.Background(), options)
			var unknown *OutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("Run() error = %v, want OutcomeUnknownError", err)
			}
			if result.Phase != PhaseGuardReleaseRecorded || result.Complete {
				t.Fatalf("Run() result = %#v, want stable guard-release checkpoint", result)
			}
			if harness.cluster.guardReleaseCalls != 1 || harness.cluster.guardReleaseMutations != 1 {
				t.Fatalf("guard release = calls %d, mutations %d; want 1, 1", harness.cluster.guardReleaseCalls, harness.cluster.guardReleaseMutations)
			}

			options.Resume = true
			result, err = harness.orchestrator.Run(context.Background(), options)
			if err != nil || !result.Complete || result.Phase != PhaseComplete {
				t.Fatalf("resumed Run() result = %#v, error = %v; want complete", result, err)
			}
			if harness.cluster.guardReleaseCalls != 1 || harness.cluster.guardReleaseMutations != 1 {
				t.Fatalf("guard release was replayed: calls %d, mutations %d; want 1, 1", harness.cluster.guardReleaseCalls, harness.cluster.guardReleaseMutations)
			}
		})
	}
}

func TestReleaseCheckpointRejectsLostOrConflictingGuardWithoutAnotherMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		status RotationGuardStatus
	}{
		{name: "completed operation", status: RotationGuardCompleted},
		{name: "different owner", status: RotationGuardOwnedByOther},
		{name: "guard not found", status: RotationGuardNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeDirect)
			plan := guardMutationTestPlan{outcome: EffectNotApplied, mutationErr: errors.New("stop at release checkpoint")}
			cluster := &guardOutcomeTestCluster{fakeClusterRotation: harness.cluster, releasePlan: &plan}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()
			options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

			result, err := harness.orchestrator.Run(context.Background(), options)
			if err == nil || result.Phase != PhaseGuardReleaseRecorded {
				t.Fatalf("initial Run() result = %#v, error = %v; want guard-release checkpoint", result, err)
			}
			checkpoint := requireGuardOutcomeCheckpointPhase(t, outputDir, PhaseGuardReleaseRecorded)
			switch test.status {
			case RotationGuardCompleted:
				harness.cluster.guardReference = nil
				harness.cluster.completedGuards = map[string]struct{}{checkpoint.RotationGuard.OperationID: {}}
			case RotationGuardOwnedByOther:
				other := *checkpoint.RotationGuard
				other.OperationID = otherGuardOperationID
				harness.cluster.guardReference = &other
			case RotationGuardNotFound:
				harness.cluster.guardReference = nil
			}

			options.Resume = true
			result, err = harness.orchestrator.Run(context.Background(), options)
			if test.status == RotationGuardCompleted {
				if err != nil || !result.Complete || result.Phase != PhaseComplete {
					t.Fatalf("resumed Run() result = %#v, error = %v; want completed observation to finish", result, err)
				}
			} else {
				var conflict *ConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("resumed Run() error = %v, want ConflictError", err)
				}
				if result.Phase != PhaseGuardReleaseRecorded || result.Complete {
					t.Fatalf("resumed Run() result = %#v, want stable guard-release checkpoint", result)
				}
				requireGuardOutcomeCheckpointPhase(t, outputDir, PhaseGuardReleaseRecorded)
			}
			if harness.cluster.guardReleaseCalls != 1 || harness.cluster.guardReleaseMutations != 0 {
				t.Fatalf("guard release after reconciliation = calls %d, mutations %d; want 1, 0", harness.cluster.guardReleaseCalls, harness.cluster.guardReleaseMutations)
			}
		})
	}
}

type guardMutationTestPlan struct {
	outcome     EffectOutcome
	apply       bool
	mutationErr error
	readbackErr error
}

type guardOutcomeTestCluster struct {
	*fakeClusterRotation
	initialGuardObservation *RotationGuardStatus
	acquirePlan             *guardMutationTestPlan
	releasePlan             *guardMutationTestPlan
	nextGuardObservationErr error
}

func (c *guardOutcomeTestCluster) ObserveRotationGuard(ctx context.Context, reference RotationGuardReference) (RotationGuardObservation, error) {
	if c.nextGuardObservationErr != nil {
		*c.events = append(*c.events, "cluster.observe-rotation-guard")
		err := c.nextGuardObservationErr
		c.nextGuardObservationErr = nil
		return RotationGuardObservation{}, err
	}
	if c.initialGuardObservation != nil {
		*c.events = append(*c.events, "cluster.observe-rotation-guard")
		status := *c.initialGuardObservation
		c.initialGuardObservation = nil
		observation := RotationGuardObservation{Status: status}
		switch status {
		case RotationGuardHeld, RotationGuardCompleted:
			observation.OperationID = reference.OperationID
		case RotationGuardOwnedByOther:
			observation.OperationID = otherGuardOperationID
		}
		return observation, nil
	}
	return c.fakeClusterRotation.ObserveRotationGuard(ctx, reference)
}

func (c *guardOutcomeTestCluster) AcquireRotationGuard(ctx context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	if c.acquirePlan == nil {
		return c.fakeClusterRotation.AcquireRotationGuard(ctx, reference)
	}
	plan := *c.acquirePlan
	c.acquirePlan = nil
	if plan.apply {
		_, _ = c.fakeClusterRotation.AcquireRotationGuard(ctx, reference)
	} else {
		*c.events = append(*c.events, "cluster.acquire-rotation-guard")
		c.guardAcquireCalls++
	}
	c.nextGuardObservationErr = plan.readbackErr
	return plan.outcome, plan.mutationErr
}

func (c *guardOutcomeTestCluster) ReleaseRotationGuard(ctx context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	if c.releasePlan == nil {
		return c.fakeClusterRotation.ReleaseRotationGuard(ctx, reference)
	}
	plan := *c.releasePlan
	c.releasePlan = nil
	if plan.apply {
		_, _ = c.fakeClusterRotation.ReleaseRotationGuard(ctx, reference)
	} else {
		*c.events = append(*c.events, "cluster.release-rotation-guard")
		c.guardReleaseCalls++
	}
	c.nextGuardObservationErr = plan.readbackErr
	return plan.outcome, plan.mutationErr
}

func requireGuardOutcomeCheckpointPhase(t *testing.T, outputDir string, want Phase) Checkpoint {
	t.Helper()
	checkpoint, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("LoadCheckpoint() returned unexpected error: %v", err)
	}
	if checkpoint.Phase != want {
		t.Fatalf("checkpoint phase = %q, want %q", checkpoint.Phase, want)
	}
	return checkpoint
}

package rotation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestRotationGuardReferenceUsesClusterGlobalScopeAndExactOperationEvidence(t *testing.T) {
	baseline := clonePublicSignerBaseline(*testSignerBaseline())
	signerRef := *testSignerObjectReference()

	first, err := deriveRotationGuardReference("cluster-123", ProviderAWS, "aws://issuer-a", baseline, signerRef)
	if err != nil {
		t.Fatalf("derive first guard reference: %v", err)
	}
	repeated, err := deriveRotationGuardReference("cluster-123", ProviderAWS, "aws://issuer-a", clonePublicSignerBaseline(baseline), signerRef)
	if err != nil {
		t.Fatalf("derive repeated guard reference: %v", err)
	}
	if first != repeated {
		t.Fatalf("deterministic guard references differ: first=%#v repeated=%#v", first, repeated)
	}

	wrongTarget, err := deriveRotationGuardReference("cluster-123", ProviderGCP, "gcp://issuer-b", baseline, signerRef)
	if err != nil {
		t.Fatalf("derive different target guard reference: %v", err)
	}
	if wrongTarget.ScopeID != first.ScopeID {
		t.Fatalf("one cluster's signer rotations received different scopes: %q and %q", first.ScopeID, wrongTarget.ScopeID)
	}
	if wrongTarget.OperationID == first.OperationID {
		t.Fatal("different provider and target identities received the same operation ID")
	}

	changedBaseline := clonePublicSignerBaseline(baseline)
	changedBaseline.ConfigMapResourceVersion = "67891"
	fromChangedBaseline, err := deriveRotationGuardReference("cluster-123", ProviderAWS, "aws://issuer-a", changedBaseline, signerRef)
	if err != nil {
		t.Fatalf("derive changed-baseline guard reference: %v", err)
	}
	if fromChangedBaseline.ScopeID != first.ScopeID || fromChangedBaseline.OperationID == first.OperationID {
		t.Fatalf("baseline change produced unexpected guard reference: first=%#v changed=%#v", first, fromChangedBaseline)
	}

	changedSignerRef := signerRef
	changedSignerRef.ResourceVersion = "12346"
	fromChangedSigner, err := deriveRotationGuardReference("cluster-123", ProviderAWS, "aws://issuer-a", baseline, changedSignerRef)
	if err != nil {
		t.Fatalf("derive changed-signer guard reference: %v", err)
	}
	if fromChangedSigner.ScopeID != first.ScopeID || fromChangedSigner.OperationID == first.OperationID {
		t.Fatalf("signer reference change produced unexpected guard reference: first=%#v changed=%#v", first, fromChangedSigner)
	}

	otherCluster, err := deriveRotationGuardReference("cluster-456", ProviderAWS, "aws://issuer-a", baseline, signerRef)
	if err != nil {
		t.Fatalf("derive other-cluster guard reference: %v", err)
	}
	if otherCluster.ScopeID == first.ScopeID || otherCluster.OperationID == first.OperationID {
		t.Fatalf("different clusters shared guard identity: first=%#v other=%#v", first, otherCluster)
	}
}

func TestOrchestratorReconcilesUnknownGuardAcquisitionWithoutRepeatingMutation(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeManual)
	cluster := &faultingGuardCluster{
		fakeClusterRotation: harness.cluster,
		unknownAcquire:      true,
	}
	harness.orchestrator.Cluster = cluster
	outputDir := t.TempDir()
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: outputDir}

	result, err := harness.orchestrator.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("initial Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhasePreflightComplete || result.Complete {
		t.Fatalf("initial Run() result = %#v, want preflight checkpoint", result)
	}
	if harness.cluster.guardAcquireCalls != 1 || harness.cluster.guardAcquireMutations != 1 {
		t.Fatalf("guard acquisition after unknown outcome = calls %d, mutations %d; want 1, 1", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
	}
	checkpoint, loadErr := LoadCheckpoint(outputDir)
	if loadErr != nil {
		t.Fatalf("load interrupted checkpoint: %v", loadErr)
	}
	if checkpoint.RotationGuard == nil {
		t.Fatal("guard reference was not durable before acquisition mutation")
	}

	options.Resume = true
	result, err = harness.orchestrator.Run(context.Background(), options)
	var pause *PauseError
	if !errors.As(err, &pause) || pause.Reason != PauseForCurrentJWKS {
		t.Fatalf("resumed Run() error = %v, want current-JWKS pause", err)
	}
	if result.Phase != PhaseGuardAcquired || result.Complete {
		t.Fatalf("resumed Run() result = %#v, want guard-acquired checkpoint", result)
	}
	if harness.cluster.guardAcquireCalls != 1 || harness.cluster.guardAcquireMutations != 1 {
		t.Fatalf("resume repeated guard mutation: calls %d, mutations %d", harness.cluster.guardAcquireCalls, harness.cluster.guardAcquireMutations)
	}
}

func TestOrchestratorFailsBeforeSignerObservationWhenGuardIsLostOrOwnedByOther(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeClusterRotation, RotationGuardReference)
	}{
		{
			name: "guard disappeared",
			mutate: func(cluster *fakeClusterRotation, _ RotationGuardReference) {
				cluster.guardReference = nil
			},
		},
		{
			name: "guard owned by another operation",
			mutate: func(cluster *fakeClusterRotation, reference RotationGuardReference) {
				reference.OperationID = strings.Repeat("b", 64)
				cluster.guardReference = &reference
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeManual)
			outputDir := t.TempDir()
			options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: outputDir}
			result, err := harness.orchestrator.Run(context.Background(), options)
			var pause *PauseError
			if !errors.As(err, &pause) || result.Phase != PhaseGuardAcquired {
				t.Fatalf("initial Run() result = %#v, error = %v; want guarded current-JWKS pause", result, err)
			}
			checkpoint, loadErr := LoadCheckpoint(outputDir)
			if loadErr != nil {
				t.Fatalf("load guarded checkpoint: %v", loadErr)
			}
			test.mutate(harness.cluster, *checkpoint.RotationGuard)
			harness.events = nil

			options.Resume = true
			options.Manual.CurrentJWKS = append([]byte(nil), harness.currentJWKS...)
			result, err = harness.orchestrator.Run(context.Background(), options)
			var conflict *ConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("resumed Run() error = %v, want ConflictError", err)
			}
			if result.Phase != PhaseGuardAcquired || result.Complete {
				t.Fatalf("resumed Run() result = %#v, want no advancement", result)
			}
			if !reflect.DeepEqual(harness.events, []string{"cluster.observe-rotation-guard"}) {
				t.Fatalf("events after guard loss = %v, want only exact guard observation", harness.events)
			}
		})
	}
}

func TestOrchestratorReconcilesReleasedGuardAfterLaterOperationAcquiresScope(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	cluster := &faultingGuardCluster{
		fakeClusterRotation: harness.cluster,
		unknownRelease:      true,
	}
	harness.orchestrator.Cluster = cluster
	outputDir := t.TempDir()
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := harness.orchestrator.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("initial Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhaseGuardReleaseRecorded || result.Complete {
		t.Fatalf("initial Run() result = %#v, want durable guard-release checkpoint", result)
	}
	checkpoint, loadErr := LoadCheckpoint(outputDir)
	if loadErr != nil {
		t.Fatalf("load release checkpoint: %v", loadErr)
	}
	if _, completed := harness.cluster.completedGuards[checkpoint.RotationGuard.OperationID]; !completed {
		t.Fatal("release mutation did not leave the exact durable completion record")
	}
	other := *checkpoint.RotationGuard
	other.OperationID = strings.Repeat("c", 64)
	harness.cluster.guardReference = &other
	harness.events = nil

	options.Resume = true
	result, err = harness.orchestrator.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("resumed Run() returned unexpected error: %v", err)
	}
	if result.Phase != PhaseComplete || !result.Complete {
		t.Fatalf("resumed Run() result = %#v, want complete", result)
	}
	if !reflect.DeepEqual(harness.events, []string{"cluster.observe-rotation-guard", "cluster.observe-rotation-guard"}) {
		t.Fatalf("terminal resume events = %v, want exact completion observations only", harness.events)
	}
}

func TestSecondClusterRotationWithDifferentTargetIsBlockedBySharedScope(t *testing.T) {
	old := safetySigner(testPublicKeyPEM(t), "old-uid", "10")
	replacement := safetySigner(testPublicKeyPEM(t), "new-uid", "20")
	registry := newSharedSignerRegistry(old, replacement)
	firstCluster := &sharedSignerCluster{safetyCluster: newSafetyCluster(old, replacement), registry: registry}
	secondCluster := &sharedSignerCluster{safetyCluster: newSafetyCluster(old, replacement), registry: registry}

	firstDir := t.TempDir()
	firstResult, firstErr := (Orchestrator{Cluster: firstCluster, Target: safetyTarget("issuer-a")}).Run(context.Background(), RunOptions{
		Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: firstDir,
	})
	var pause *PauseError
	if !errors.As(firstErr, &pause) || firstResult.Phase != PhaseGuardAcquired {
		t.Fatalf("first Run() result = %#v, error = %v; want guarded pause", firstResult, firstErr)
	}

	secondDir := t.TempDir()
	secondResult, secondErr := (Orchestrator{Cluster: secondCluster, Target: safetyTarget("issuer-b")}).Run(context.Background(), RunOptions{
		Provider: ProviderGCP, PublicationMode: PublicationModeManual, OutputDir: secondDir,
	})
	var conflict *ConflictError
	if !errors.As(secondErr, &conflict) {
		t.Fatalf("second Run() error = %v, want ConflictError", secondErr)
	}
	if secondResult.Phase != PhasePreflightComplete || secondResult.Complete {
		t.Fatalf("second Run() result = %#v, want blocked preflight checkpoint", secondResult)
	}

	firstCheckpoint, err := LoadCheckpoint(firstDir)
	if err != nil {
		t.Fatalf("load first checkpoint: %v", err)
	}
	secondCheckpoint, err := LoadCheckpoint(secondDir)
	if err != nil {
		t.Fatalf("load second checkpoint: %v", err)
	}
	if firstCheckpoint.RotationGuard.ScopeID != secondCheckpoint.RotationGuard.ScopeID {
		t.Fatalf("same cluster used different guard scopes: first=%#v second=%#v", firstCheckpoint.RotationGuard, secondCheckpoint.RotationGuard)
	}
	if firstCheckpoint.RotationGuard.OperationID == secondCheckpoint.RotationGuard.OperationID {
		t.Fatal("different provider/target evidence produced the same operation ID")
	}
	acquireCalls, acquireMutations, _, _ := registry.guardCounts()
	if acquireCalls != 1 || acquireMutations != 1 {
		t.Fatalf("shared guard acquisition = calls %d, mutations %d; want first operation only", acquireCalls, acquireMutations)
	}
	if requests := registry.requestCount(); requests != 0 {
		t.Fatalf("signer replacement requests = %d, want zero before the blocked operation", requests)
	}
}

type faultingGuardCluster struct {
	*fakeClusterRotation
	unknownAcquire  bool
	unknownRelease  bool
	failNextObserve error
}

func (cluster *faultingGuardCluster) ObserveRotationGuard(ctx context.Context, reference RotationGuardReference) (RotationGuardObservation, error) {
	if cluster.failNextObserve != nil {
		err := cluster.failNextObserve
		cluster.failNextObserve = nil
		return RotationGuardObservation{}, err
	}
	return cluster.fakeClusterRotation.ObserveRotationGuard(ctx, reference)
}

func (cluster *faultingGuardCluster) AcquireRotationGuard(ctx context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	outcome, err := cluster.fakeClusterRotation.AcquireRotationGuard(ctx, reference)
	if cluster.unknownAcquire {
		cluster.unknownAcquire = false
		cluster.failNextObserve = errors.New("guard acquisition readback interrupted")
		return EffectUnknown, errors.New("guard acquisition response lost")
	}
	return outcome, err
}

func (cluster *faultingGuardCluster) ReleaseRotationGuard(ctx context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	outcome, err := cluster.fakeClusterRotation.ReleaseRotationGuard(ctx, reference)
	if cluster.unknownRelease {
		cluster.unknownRelease = false
		cluster.failNextObserve = errors.New("guard release readback interrupted")
		return EffectUnknown, errors.New("guard release response lost")
	}
	return outcome, err
}

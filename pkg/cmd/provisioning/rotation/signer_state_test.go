package rotation

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestNormalizePublicSignerBundleCanonicalizesAndRejectsAmbiguity(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	rsaLabel := bytes.ReplaceAll(oldPublic, []byte("PUBLIC KEY"), []byte("RSA PUBLIC KEY"))

	tests := []struct {
		name      string
		signers   []PublicSignerObservation
		wantNames []string
		wantError string
	}{
		{
			name: "canonicalizes entry order",
			signers: []PublicSignerObservation{
				{Name: "service-account-002.pub", PublicKeyPEM: newPublic},
				{Name: "service-account-001.pub", PublicKeyPEM: oldPublic},
			},
			wantNames: []string{"service-account-001.pub", "service-account-002.pub"},
		},
		{name: "empty bundle", wantError: "at least one entry"},
		{
			name:      "unexpected entry name",
			signers:   []PublicSignerObservation{{Name: "active.pub", PublicKeyPEM: oldPublic}},
			wantError: "not supported",
		},
		{
			name: "duplicate entry name",
			signers: []PublicSignerObservation{
				{Name: "service-account-001.pub", PublicKeyPEM: oldPublic},
				{Name: "service-account-001.pub", PublicKeyPEM: newPublic},
			},
			wantError: "duplicate entry name",
		},
		{
			name: "duplicate exact public value",
			signers: []PublicSignerObservation{
				{Name: "service-account-001.pub", PublicKeyPEM: oldPublic},
				{Name: "service-account-002.pub", PublicKeyPEM: oldPublic},
			},
			wantError: "duplicate public value digest",
		},
		{
			name: "duplicate semantic key with different PEM bytes",
			signers: []PublicSignerObservation{
				{Name: "service-account-001.pub", PublicKeyPEM: oldPublic},
				{Name: "service-account-002.pub", PublicKeyPEM: rsaLabel},
			},
			wantError: "duplicate key ID",
		},
		{
			name:      "malformed public key",
			signers:   []PublicSignerObservation{{Name: "service-account-001.pub", PublicKeyPEM: []byte("not pem")}},
			wantError: "parse public signer entry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := normalizePublicSignerBundle(PublicSignerBundleObservation{
				ConfigMapUID:             "signer-configmap-uid",
				ConfigMapResourceVersion: "100",
				Signers:                  test.signers,
			})
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("normalizePublicSignerBundle() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePublicSignerBundle() returned unexpected error: %v", err)
			}
			gotNames := make([]string, len(state.Baseline.Entries))
			for index, entry := range state.Baseline.Entries {
				gotNames[index] = entry.Name
			}
			if !reflect.DeepEqual(gotNames, test.wantNames) {
				t.Fatalf("canonical entry names = %v, want %v", gotNames, test.wantNames)
			}
		})
	}
}

func TestObserveStableSignerStateRequiresMatchingMetadataReads(t *testing.T) {
	old := safetySigner(testPublicKeyPEM(t), "old-uid", "10")
	replacement := safetySigner(testPublicKeyPEM(t), "new-uid", "11")
	base := newSafetyCluster(old, replacement)

	t.Run("matching reference", func(t *testing.T) {
		cluster := &scriptedSignerReferenceCluster{
			safetyCluster: base,
			references: []*SignerObjectReference{
				cloneSignerReferenceForTest(&old.Reference),
				cloneSignerReferenceForTest(&old.Reference),
			},
		}
		state, err := (Orchestrator{Cluster: cluster}).observeStableSignerState(context.Background(), PhaseInitialized, nil)
		if err != nil {
			t.Fatalf("observeStableSignerState() returned unexpected error: %v", err)
		}
		if state.Reference == nil || *state.Reference != old.Reference {
			t.Fatalf("stable reference = %#v, want %#v", state.Reference, old.Reference)
		}
	})

	t.Run("reference changes during every bundle read", func(t *testing.T) {
		references := make([]*SignerObjectReference, 0, stableSignerObservationAttempts*2)
		for attempt := 0; attempt < stableSignerObservationAttempts; attempt++ {
			references = append(references, cloneSignerReferenceForTest(&old.Reference), cloneSignerReferenceForTest(&replacement.Reference))
		}
		cluster := &scriptedSignerReferenceCluster{safetyCluster: base, references: references}
		_, err := (Orchestrator{Cluster: cluster}).observeStableSignerState(context.Background(), PhaseCurrentJWKSRead, nil)
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("observeStableSignerState() error = %v, want ConflictError", err)
		}
	})
}

func TestClassifySignerStateRequiresExactAppendAndChangedUID(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	thirdPublic := testPublicKeyPEM(t)
	oldReference := SignerObjectReference{UID: "old-uid", ResourceVersion: "10"}
	newReference := SignerObjectReference{UID: "new-uid", ResourceVersion: "20"}
	oldSigner := PublicSignerObservation{Name: "service-account-001.pub", PublicKeyPEM: oldPublic}
	newSigner := PublicSignerObservation{Name: "service-account-002.pub", PublicKeyPEM: newPublic}
	thirdSigner := PublicSignerObservation{Name: "service-account-003.pub", PublicKeyPEM: thirdPublic}
	initial := signerStateForTest(t, &oldReference, "configmap-uid", "100", oldSigner)
	baseline := clonePublicSignerBaseline(initial.Baseline)
	checkpoint := Checkpoint{PreRotationSignerBaseline: &baseline, PreRotationSignerRef: &oldReference}

	tests := []struct {
		name         string
		state        func(*testing.T) stableSignerState
		wantProgress signerStateProgress
		wantError    string
	}{
		{name: "original state", state: func(*testing.T) stableSignerState { return initial }, wantProgress: signerStateOriginal},
		{name: "Secret absent", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, nil, "configmap-uid", "100", oldSigner)
		}, wantProgress: signerStateReplacementRequested},
		{name: "changed UID before append", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &newReference, "configmap-uid", "100", oldSigner)
		}, wantProgress: signerStateReplacementRequested},
		{name: "one append and changed UID", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &newReference, "configmap-uid", "101", oldSigner, newSigner)
		}, wantProgress: signerStateReplacementReady},
		{name: "same UID with changed resource version", state: func(t *testing.T) stableSignerState {
			changed := SignerObjectReference{UID: oldReference.UID, ResourceVersion: "11"}
			return signerStateForTest(t, &changed, "configmap-uid", "100", oldSigner)
		}, wantError: "resource version changed"},
		{name: "append while old Secret remains", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &oldReference, "configmap-uid", "101", oldSigner, newSigner)
		}, wantError: "remained current"},
		{name: "old entry overwritten", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &newReference, "configmap-uid", "101", PublicSignerObservation{Name: oldSigner.Name, PublicKeyPEM: newPublic})
		}, wantError: "changed"},
		{name: "old entry removed", state: func(t *testing.T) stableSignerState {
			state := signerStateForTest(t, &newReference, "configmap-uid", "101", newSigner)
			return state
		}, wantError: "disappeared"},
		{name: "two entries appended", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &newReference, "configmap-uid", "101", oldSigner, newSigner, thirdSigner)
		}, wantError: "more than one"},
		{name: "ConfigMap recreated", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &newReference, "other-configmap-uid", "101", oldSigner, newSigner)
		}, wantError: "UID changed"},
		{name: "resource version changes without append", state: func(t *testing.T) stableSignerState {
			return signerStateForTest(t, &newReference, "configmap-uid", "101", oldSigner)
		}, wantError: "resource version changed without"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			progress, replacement, err := classifySignerState(PhaseCurrentJWKSRead, test.state(t), checkpoint)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("classifySignerState() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("classifySignerState() returned unexpected error: %v", err)
			}
			if progress != test.wantProgress {
				t.Fatalf("classifySignerState() progress = %v, want %v", progress, test.wantProgress)
			}
			if progress == signerStateReplacementReady {
				if replacement == nil || replacement.Evidence.Entry.Name != newSigner.Name || replacement.Evidence.SecretRef.UID != newReference.UID || !bytes.Equal(replacement.PublicPEM, newPublic) {
					t.Fatalf("replacement candidate = %#v", replacement)
				}
			}
		})
	}
}

func TestCheckpointRejectsReplacementWithPreRotationSecretUID(t *testing.T) {
	checkpoint := completeTestCheckpoint()
	checkpoint.ReplacementSigner.SecretRef.UID = checkpoint.PreRotationSignerRef.UID
	if err := checkpoint.Validate(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("Validate() error = %v, want changed-UID error", err)
	}
}

func TestValidateRecordedSignerStateRequiresExactReplacementReference(t *testing.T) {
	old := safetySigner(testPublicKeyPEM(t), "old-uid", "10")
	replacement := safetySigner(testPublicKeyPEM(t), "new-uid", "20")
	initial := signerStateForTest(t, &old.Reference, "configmap-uid", "100", old.Signer)
	baseline := clonePublicSignerBaseline(initial.Baseline)
	checkpoint := Checkpoint{Phase: PhaseNextPublicKeyRead, PreRotationSignerBaseline: &baseline, PreRotationSignerRef: &old.Reference}
	ready := signerStateForTest(t, &replacement.Reference, "configmap-uid", "101", old.Signer, replacement.Signer)
	_, candidate, err := classifySignerState(checkpoint.Phase, ready, checkpoint)
	if err != nil || candidate == nil {
		t.Fatalf("classify ready signer state: candidate=%#v error=%v", candidate, err)
	}
	evidence := candidate.Evidence
	checkpoint.ReplacementSigner = &evidence

	driftedReference := replacement.Reference
	driftedReference.ResourceVersion = "21"
	drifted := signerStateForTest(t, &driftedReference, "configmap-uid", "101", old.Signer, replacement.Signer)
	err = validateRecordedSignerState(checkpoint.Phase, drifted, checkpoint)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("validateRecordedSignerState() error = %v, want replacement-reference conflict", err)
	}
}

func TestOrchestratorRevalidatesReplacementAtEveryDisruptiveGate(t *testing.T) {
	tests := []struct {
		name                 string
		driftAtObservation   int
		wantPhase            Phase
		wantPublicationCount int
	}{
		{name: "before combined publication", driftAtObservation: 6, wantPhase: PhaseCombinedJWKSBuilt, wantPublicationCount: 0},
		{name: "after signer rollout", driftAtObservation: 7, wantPhase: PhaseCombinedJWKSPublished, wantPublicationCount: 1},
		{name: "before final publication", driftAtObservation: 8, wantPhase: PhasePostRebootStable, wantPublicationCount: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeDirect)
			drift := PublicSignerObservation{Name: "service-account-003.pub", PublicKeyPEM: testPublicKeyPEM(t)}
			cluster := &driftingSignerCluster{
				fakeClusterRotation: harness.cluster,
				driftAtObservation:  test.driftAtObservation,
				driftReference: SignerObjectReference{
					UID:             "second-replacement-uid",
					ResourceVersion: "300",
				},
				driftSigner: drift,
			}
			harness.orchestrator.Cluster = cluster

			result, err := harness.orchestrator.Run(context.Background(), RunOptions{
				Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: t.TempDir(),
			})
			var conflict *ConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("Run() error = %v, want ConflictError", err)
			}
			if result.Phase != test.wantPhase {
				t.Fatalf("Run() phase = %q, want %q", result.Phase, test.wantPhase)
			}
			if len(harness.publisher.publications) != test.wantPublicationCount {
				t.Fatalf("provider publication count = %d, want %d", len(harness.publisher.publications), test.wantPublicationCount)
			}
		})
	}
}

func TestOrchestratorTwoPreflightedWorkspacesAdoptOneSignerReplacement(t *testing.T) {
	old := safetySigner(testPublicKeyPEM(t), "old-uid", "10")
	replacement := safetySigner(testPublicKeyPEM(t), "new-uid", "20")
	registry := newSharedSignerRegistry(old, replacement)
	currentJWKS := encodedJWKSForTest(t, old.Signer.PublicKeyPEM)
	firstCluster := &sharedSignerCluster{safetyCluster: newSafetyCluster(old, replacement), registry: registry}
	secondCluster := &sharedSignerCluster{safetyCluster: newSafetyCluster(old, replacement), registry: registry}
	firstDir := t.TempDir()
	secondDir := t.TempDir()

	for _, run := range []struct {
		cluster *sharedSignerCluster
		dir     string
	}{
		{cluster: firstCluster, dir: firstDir},
		{cluster: secondCluster, dir: secondDir},
	} {
		result, err := (Orchestrator{Cluster: run.cluster, Target: safetyTarget("issuer")}).Run(context.Background(), RunOptions{
			Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: run.dir,
		})
		var pause *PauseError
		if !errors.As(err, &pause) || result.Phase != PhaseGuardAcquired || pause.Reason != PauseForCurrentJWKS {
			t.Fatalf("preflight Run() result = %#v, error = %v", result, err)
		}
	}
	acquireCalls, acquireMutations, _, _ := registry.guardCounts()
	if acquireCalls != 1 || acquireMutations != 1 {
		t.Fatalf("shared guard acquisitions = calls %d, mutations %d; want one idempotent mutation", acquireCalls, acquireMutations)
	}
	firstPreflight, err := LoadCheckpoint(firstDir)
	if err != nil {
		t.Fatalf("load first guarded checkpoint: %v", err)
	}
	secondPreflight, err := LoadCheckpoint(secondDir)
	if err != nil {
		t.Fatalf("load second guarded checkpoint: %v", err)
	}
	if firstPreflight.RotationGuard == nil || !reflect.DeepEqual(firstPreflight.RotationGuard, secondPreflight.RotationGuard) {
		t.Fatalf("identical workspaces did not converge on one guard: first=%#v second=%#v", firstPreflight.RotationGuard, secondPreflight.RotationGuard)
	}

	for _, run := range []struct {
		cluster *sharedSignerCluster
		dir     string
	}{
		{cluster: firstCluster, dir: firstDir},
		{cluster: secondCluster, dir: secondDir},
	} {
		result, err := (Orchestrator{Cluster: run.cluster, Target: safetyTarget("issuer")}).Run(context.Background(), RunOptions{
			Provider: ProviderAWS, PublicationMode: PublicationModeManual, OutputDir: run.dir, Resume: true,
			Manual: ManualInput{CurrentJWKS: currentJWKS},
		})
		var pause *PauseError
		if !errors.As(err, &pause) || result.Phase != PhaseCombinedJWKSBuilt || pause.Reason != PauseForPublication {
			t.Fatalf("resumed Run() result = %#v, error = %v", result, err)
		}
	}

	if requests := registry.requestCount(); requests != 1 {
		t.Fatalf("signer replacement requests = %d, want exactly one", requests)
	}
	first, err := LoadCheckpoint(firstDir)
	if err != nil {
		t.Fatalf("load first checkpoint: %v", err)
	}
	second, err := LoadCheckpoint(secondDir)
	if err != nil {
		t.Fatalf("load second checkpoint: %v", err)
	}
	if first.ReplacementSigner == nil || !reflect.DeepEqual(first.ReplacementSigner, second.ReplacementSigner) {
		t.Fatalf("replacement evidence did not converge: first=%#v second=%#v", first.ReplacementSigner, second.ReplacementSigner)
	}
}

func signerStateForTest(t *testing.T, reference *SignerObjectReference, configMapUID, resourceVersion string, signers ...PublicSignerObservation) stableSignerState {
	t.Helper()
	state, err := normalizePublicSignerBundle(PublicSignerBundleObservation{
		ConfigMapUID:             configMapUID,
		ConfigMapResourceVersion: resourceVersion,
		Signers:                  clonePublicSignerObservationsForTest(signers),
	})
	if err != nil {
		t.Fatalf("normalize signer state fixture: %v", err)
	}
	state.Reference = cloneSignerReferenceForTest(reference)
	return state
}

type scriptedSignerReferenceCluster struct {
	*safetyCluster
	references []*SignerObjectReference
	next       int
}

func (cluster *scriptedSignerReferenceCluster) ObserveSignerReference(context.Context, *RotationGuardReference) (*SignerObjectReference, error) {
	if cluster.next >= len(cluster.references) {
		return nil, errors.New("reference script exhausted")
	}
	reference := cloneSignerReferenceForTest(cluster.references[cluster.next])
	cluster.next++
	return reference, nil
}

type sharedSignerRegistry struct {
	mutex            sync.Mutex
	reference        *SignerObjectReference
	bundle           PublicSignerBundleObservation
	replacement      safetySignerFixture
	requests         int
	guard            *RotationGuardReference
	completed        map[string]struct{}
	acquireCalls     int
	acquireMutations int
	releaseCalls     int
	releaseMutations int
}

func newSharedSignerRegistry(old, replacement safetySignerFixture) *sharedSignerRegistry {
	return &sharedSignerRegistry{
		reference: cloneSignerReferenceForTest(&old.Reference),
		bundle: PublicSignerBundleObservation{
			ConfigMapUID:             "shared-signer-configmap-uid",
			ConfigMapResourceVersion: "1000",
			Signers:                  []PublicSignerObservation{clonePublicSignerObservationForTest(old.Signer)},
		},
		replacement: replacement,
	}
}

func (registry *sharedSignerRegistry) snapshot() (*SignerObjectReference, PublicSignerBundleObservation) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	return cloneSignerReferenceForTest(registry.reference), clonePublicSignerBundleForTest(registry.bundle)
}

func (registry *sharedSignerRegistry) request(reference SignerObjectReference) (EffectOutcome, error) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	if registry.reference == nil || *registry.reference != reference {
		return EffectNotApplied, nil
	}
	registry.requests++
	registry.reference = cloneSignerReferenceForTest(&registry.replacement.Reference)
	registry.bundle.ConfigMapResourceVersion = "1001"
	registry.bundle.Signers = append(registry.bundle.Signers, clonePublicSignerObservationForTest(registry.replacement.Signer))
	return EffectSubmitted, nil
}

func (registry *sharedSignerRegistry) requestCount() int {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	return registry.requests
}

func (registry *sharedSignerRegistry) observeGuard(reference RotationGuardReference) RotationGuardObservation {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	if _, completed := registry.completed[reference.OperationID]; completed {
		return RotationGuardObservation{Status: RotationGuardCompleted, OperationID: reference.OperationID}
	}
	if registry.guard == nil {
		return RotationGuardObservation{Status: RotationGuardNotFound}
	}
	if *registry.guard == reference {
		return RotationGuardObservation{Status: RotationGuardHeld, OperationID: reference.OperationID}
	}
	return RotationGuardObservation{Status: RotationGuardOwnedByOther, OperationID: registry.guard.OperationID}
}

func (registry *sharedSignerRegistry) acquireGuard(reference RotationGuardReference) (EffectOutcome, error) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	registry.acquireCalls++
	if registry.guard == nil {
		stored := reference
		registry.guard = &stored
		registry.acquireMutations++
		return EffectSubmitted, nil
	}
	if *registry.guard == reference {
		return EffectSubmitted, nil
	}
	return EffectNotApplied, nil
}

func (registry *sharedSignerRegistry) releaseGuard(reference RotationGuardReference) (EffectOutcome, error) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	registry.releaseCalls++
	if _, completed := registry.completed[reference.OperationID]; completed {
		return EffectSubmitted, nil
	}
	if registry.guard == nil || *registry.guard != reference {
		return EffectNotApplied, nil
	}
	registry.guard = nil
	if registry.completed == nil {
		registry.completed = make(map[string]struct{})
	}
	registry.completed[reference.OperationID] = struct{}{}
	registry.releaseMutations++
	return EffectSubmitted, nil
}

func (registry *sharedSignerRegistry) guardCounts() (int, int, int, int) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	return registry.acquireCalls, registry.acquireMutations, registry.releaseCalls, registry.releaseMutations
}

type sharedSignerCluster struct {
	*safetyCluster
	registry *sharedSignerRegistry
}

func (cluster *sharedSignerCluster) ObserveRotationGuard(_ context.Context, reference RotationGuardReference) (RotationGuardObservation, error) {
	return cluster.registry.observeGuard(reference), nil
}

func (cluster *sharedSignerCluster) AcquireRotationGuard(_ context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	return cluster.registry.acquireGuard(reference)
}

func (cluster *sharedSignerCluster) ReleaseRotationGuard(_ context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	return cluster.registry.releaseGuard(reference)
}

type driftingSignerCluster struct {
	*fakeClusterRotation
	driftAtObservation int
	driftReference     SignerObjectReference
	driftSigner        PublicSignerObservation
}

func (cluster *driftingSignerCluster) ObservePublicSignerBundle(ctx context.Context, guard *RotationGuardReference) (PublicSignerBundleObservation, error) {
	if cluster.bundleObservations+1 == cluster.driftAtObservation {
		cluster.nextReference = cloneSignerReferenceForTest(&cluster.driftReference)
		cluster.nextBundle.ConfigMapResourceVersion = "1002"
		cluster.nextBundle.Signers = append(cluster.nextBundle.Signers, clonePublicSignerObservationForTest(cluster.driftSigner))
	}
	return cluster.fakeClusterRotation.ObservePublicSignerBundle(ctx, guard)
}

func (cluster *sharedSignerCluster) ObserveSignerReference(context.Context, *RotationGuardReference) (*SignerObjectReference, error) {
	reference, _ := cluster.registry.snapshot()
	return reference, nil
}

func (cluster *sharedSignerCluster) ObservePublicSignerBundle(context.Context, *RotationGuardReference) (PublicSignerBundleObservation, error) {
	_, bundle := cluster.registry.snapshot()
	return bundle, nil
}

func (cluster *sharedSignerCluster) RequestReplacement(_ context.Context, _ RotationGuardReference, reference SignerObjectReference) (EffectOutcome, error) {
	return cluster.registry.request(reference)
}

func (cluster *sharedSignerCluster) WaitForReplacement(context.Context, RotationGuardReference, SignerObjectReference) error {
	return nil
}

package rotation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestOrchestratorDoesNotAdvanceUntilSubmittedReplacementIsObserved(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	oldSigner := safetySigner(oldPublic, "old-uid", "10")
	newSigner := safetySigner(newPublic, "new-uid", "11")
	currentJWKS := encodedJWKSForTest(t, oldPublic)

	cluster := newSafetyCluster(oldSigner, newSigner)
	cluster.replacementOutcome = EffectSubmitted
	cluster.applyReplacement = false
	publisher := newSafetyPublisher(currentJWKS)
	engine := Orchestrator{
		Cluster:   cluster,
		Target:    safetyTarget("aws://issuer/keys.json"),
		Publisher: publisher,
	}
	outputDir := filepath.Join(t.TempDir(), "rotation")
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := engine.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhaseCurrentJWKSRead || cluster.replacementRequests != 1 {
		t.Fatalf("first Run() result = %#v, replacement requests = %d", result, cluster.replacementRequests)
	}
	checkpoint, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load checkpoint after unknown replacement request: %v", err)
	}
	if checkpoint.LastErrorCode != errorCodeExternalOutcomeUnknown {
		t.Fatalf("last error code = %q, want %q", checkpoint.LastErrorCode, errorCodeExternalOutcomeUnknown)
	}
	if cluster.replacementReference != *checkpoint.PreRotationSignerRef {
		t.Fatalf("replacement request reference = %#v, want immutable checkpoint reference %#v", cluster.replacementReference, *checkpoint.PreRotationSignerRef)
	}

	cluster.nextReference = nil
	options.Resume = true
	result, err = engine.Run(context.Background(), options)
	if !errors.As(err, &unknown) {
		t.Fatalf("resume during Secret recreation error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhaseNextKeyRequested || cluster.replacementRequests != 1 {
		t.Fatalf("resume during Secret recreation result = %#v, replacement requests = %d", result, cluster.replacementRequests)
	}

	cluster.applySafetyReplacement()
	result, err = engine.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("second resume Run() returned unexpected error: %v", err)
	}
	if !result.Complete || result.Phase != PhaseComplete {
		t.Fatalf("resume Run() result = %#v, want complete", result)
	}
	if cluster.replacementRequests != 1 {
		t.Fatalf("replacement request count = %d, want exactly one", cluster.replacementRequests)
	}
}

func TestOrchestratorResumeDoesNotReenterUnknownRebootAfterCompletionIsObserved(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	oldSigner := safetySigner(oldPublic, "old-uid", "10")
	newSigner := safetySigner(newPublic, "new-uid", "11")
	cluster := newSafetyCluster(oldSigner, newSigner)
	cluster.replacementOutcome = EffectSubmitted
	cluster.rebootOutcome = EffectUnknown
	cluster.rebootStatuses = []RebootStatus{RebootNotStarted, RebootNotStarted, RebootNotStarted}
	publisher := newSafetyPublisher(encodedJWKSForTest(t, oldPublic))
	engine := Orchestrator{
		Cluster:   cluster,
		Target:    safetyTarget("aws://issuer/keys.json"),
		Publisher: publisher,
	}
	outputDir := filepath.Join(t.TempDir(), "rotation")
	cluster.beforeRebootRequest = func(intent RebootIntent) error {
		checkpoint, err := LoadCheckpoint(outputDir)
		if err != nil {
			return err
		}
		if checkpoint.Phase != PhaseRebootIntentRecorded || checkpoint.RebootIntent == nil || checkpoint.RebootIntent.ID != intent.ID {
			return fmt.Errorf("reboot request ran before matching intent was durable: %#v", checkpoint)
		}
		return nil
	}
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := engine.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhaseRebootIntentRecorded || cluster.rebootRequests != 1 {
		t.Fatalf("first Run() result = %#v, reboot requests = %d", result, cluster.rebootRequests)
	}
	checkpoint, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load checkpoint after unknown reboot request: %v", err)
	}
	if checkpoint.RebootIntent == nil || checkpoint.RebootIntent.ID == "" {
		t.Fatalf("persisted reboot intent = %#v, want a deterministic ID", checkpoint.RebootIntent)
	}

	cluster.rebootStatuses = []RebootStatus{RebootComplete}
	options.Resume = true
	result, err = engine.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("resume Run() returned unexpected error: %v", err)
	}
	if !result.Complete || cluster.rebootRequests != 1 {
		t.Fatalf("resume result = %#v, reboot request count = %d", result, cluster.rebootRequests)
	}
}

func TestOrchestratorDoesNotExposeMutableRebootIntentAliases(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	base := newSafetyCluster(
		safetySigner(oldPublic, "old-uid", "10"),
		safetySigner(newPublic, "new-uid", "11"),
	)
	base.rebootStatuses = []RebootStatus{RebootNotStarted, RebootNotStarted, RebootInProgress, RebootComplete}
	cluster := &mutatingRebootCluster{t: t, safetyCluster: base}
	publisher := newSafetyPublisher(encodedJWKSForTest(t, oldPublic))
	engine := Orchestrator{
		Cluster:   cluster,
		Target:    safetyTarget("aws://issuer/keys.json"),
		Publisher: publisher,
	}

	result, err := engine.Run(context.Background(), RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeDirect,
		OutputDir:       filepath.Join(t.TempDir(), "rotation"),
	})
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if !result.Complete {
		t.Fatalf("Run() result = %#v, want complete", result)
	}
}

func TestBuildRebootIntentIsDeterministicAcrossWorkspaces(t *testing.T) {
	replacementKeyID, err := safetySignerKeyID(safetySigner(testPublicKeyPEM(t), "uid", "1"))
	if err != nil {
		t.Fatalf("derive replacement key ID: %v", err)
	}
	first, err := buildRebootIntent("cluster-123", replacementKeyID, RebootPlan{
		Targets: []string{"worker", "master"},
		Baselines: []NodeRebootBaseline{
			{Target: "worker", Node: "worker-0", BootID: "old-worker-boot"},
			{Target: "master", Node: "master-0", BootID: "old-master-boot"},
		},
	})
	if err != nil {
		t.Fatalf("build first reboot intent: %v", err)
	}
	second, err := buildRebootIntent("cluster-123", replacementKeyID, RebootPlan{
		Targets: []string{"master", "worker"},
		Baselines: []NodeRebootBaseline{
			{Target: "master", Node: "master-0", BootID: "newer-master-baseline"},
			{Target: "worker", Node: "worker-0", BootID: "newer-worker-baseline"},
		},
	})
	if err != nil {
		t.Fatalf("build second reboot intent: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("reboot intent IDs differ across plan order/baseline time: %q and %q", first.ID, second.ID)
	}
	if !reflect.DeepEqual(first.Targets, []string{"master", "worker"}) {
		t.Fatalf("canonical targets = %v", first.Targets)
	}

	differentSnapshot, err := buildRebootIntent("cluster-123", replacementKeyID, RebootPlan{
		Targets:   []string{"worker"},
		Baselines: []NodeRebootBaseline{{Target: "worker", Node: "worker-0", BootID: "old-worker-boot"}},
	})
	if err != nil {
		t.Fatalf("build different-snapshot reboot intent: %v", err)
	}
	if first.ID != differentSnapshot.ID {
		t.Fatalf("one signer rotation produced different reboot IDs across target snapshots: %q and %q", first.ID, differentSnapshot.ID)
	}
}

func TestValidateRebootObservationRequiresCanonicalRecord(t *testing.T) {
	canonical := testNodeRebootIntent()
	invalidCanonical := cloneRebootIntent(*canonical)
	invalidCanonical.Baselines = nil
	tests := []struct {
		name      string
		operation string
		observed  RebootObservation
		wantError string
	}{
		{name: "not started without record", operation: canonical.ID, observed: RebootObservation{Status: RebootNotStarted}},
		{name: "in progress with canonical record", operation: canonical.ID, observed: RebootObservation{Status: RebootInProgress, CanonicalIntent: canonical}},
		{name: "not started with record", operation: canonical.ID, observed: RebootObservation{Status: RebootNotStarted, CanonicalIntent: canonical}, wantError: "canonical reboot intent"},
		{name: "in progress without record", operation: canonical.ID, observed: RebootObservation{Status: RebootInProgress}, wantError: "without the canonical"},
		{name: "mismatched operation", operation: "other-operation", observed: RebootObservation{Status: RebootComplete, CanonicalIntent: canonical}, wantError: "for operation"},
		{name: "invalid canonical record", operation: canonical.ID, observed: RebootObservation{Status: RebootComplete, CanonicalIntent: &invalidCanonical}, wantError: "invalid canonical"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRebootObservation(test.operation, test.observed)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateRebootObservation() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateRebootObservation() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestOrchestratorTwoWorkspacesAdoptOneClusterCanonicalReboot(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	oldSigner := safetySigner(oldPublic, "old-uid", "10")
	newSigner := safetySigner(newPublic, "new-uid", "11")
	currentJWKS := encodedJWKSForTest(t, oldPublic)
	registry := &sharedRebootRegistry{}
	stopBeforeRebootIntent := errors.New("stop before recording the reboot intent")

	firstCluster := &sharedRegistryCluster{
		safetyCluster: newSafetyCluster(oldSigner, newSigner),
		registry:      registry,
		prepareErr:    stopBeforeRebootIntent,
		plan: RebootPlan{
			Targets: []string{"worker", "master"},
			Baselines: []NodeRebootBaseline{
				{Target: "worker", Node: "worker-0", BootID: "worker-before-first-request"},
				{Target: "master", Node: "master-0", BootID: "master-before-first-request"},
			},
		},
	}
	secondCluster := &sharedRegistryCluster{
		safetyCluster: newSafetyCluster(oldSigner, newSigner),
		registry:      registry,
		prepareErr:    stopBeforeRebootIntent,
		plan: RebootPlan{
			Targets: []string{"worker"},
			Baselines: []NodeRebootBaseline{
				{Target: "worker", Node: "worker-0", BootID: "worker-after-snapshot-drift"},
			},
		},
	}
	firstPublisher := newSafetyPublisher(currentJWKS)
	secondPublisher := newSafetyPublisher(currentJWKS)
	firstEngine := Orchestrator{Cluster: firstCluster, Target: safetyTarget("aws://issuer/keys.json"), Publisher: firstPublisher}
	secondEngine := Orchestrator{Cluster: secondCluster, Target: safetyTarget("aws://issuer/keys.json"), Publisher: secondPublisher}
	firstOptions := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: filepath.Join(t.TempDir(), "first")}
	secondOptions := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: filepath.Join(t.TempDir(), "second")}

	for _, run := range []struct {
		name    string
		engine  Orchestrator
		options RunOptions
	}{
		{name: "first workspace", engine: firstEngine, options: firstOptions},
		{name: "second workspace", engine: secondEngine, options: secondOptions},
	} {
		result, err := run.engine.Run(context.Background(), run.options)
		if !errors.Is(err, stopBeforeRebootIntent) {
			t.Fatalf("%s initial Run() error = %v, want %v", run.name, err, stopBeforeRebootIntent)
		}
		if result.Phase != PhaseSignerRolloutStable {
			t.Fatalf("%s initial Run() phase = %q, want %q", run.name, result.Phase, PhaseSignerRolloutStable)
		}
	}

	firstCluster.prepareErr = nil
	secondCluster.prepareErr = nil
	firstProposal := recordRebootProposalForTest(t, firstEngine, firstOptions.OutputDir)
	secondProposal := recordRebootProposalForTest(t, secondEngine, secondOptions.OutputDir)
	if firstProposal.RebootIntent.ID != secondProposal.RebootIntent.ID {
		t.Fatalf("workspace operation IDs differ: %q and %q", firstProposal.RebootIntent.ID, secondProposal.RebootIntent.ID)
	}
	if reflect.DeepEqual(firstProposal.RebootIntent, secondProposal.RebootIntent) {
		t.Fatal("workspace reboot proposals unexpectedly match; test requires snapshot drift")
	}

	firstOptions.Resume = true
	firstResult, err := firstEngine.Run(context.Background(), firstOptions)
	if err != nil || !firstResult.Complete {
		t.Fatalf("first workspace resume result = %#v, error = %v", firstResult, err)
	}
	secondOptions.Resume = true
	secondResult, err := secondEngine.Run(context.Background(), secondOptions)
	if err != nil || !secondResult.Complete {
		t.Fatalf("second workspace resume result = %#v, error = %v", secondResult, err)
	}

	canonical, requestCalls, requestMutations := registry.snapshot()
	if requestCalls != 1 || requestMutations != 1 {
		t.Fatalf("cluster reboot request calls = %d, mutations = %d; want exactly one of each", requestCalls, requestMutations)
	}
	if canonical == nil || !reflect.DeepEqual(*canonical, *firstProposal.RebootIntent) {
		t.Fatalf("cluster-canonical reboot intent = %#v, want first proposal %#v", canonical, firstProposal.RebootIntent)
	}
	for _, outputDir := range []string{firstOptions.OutputDir, secondOptions.OutputDir} {
		checkpoint, err := LoadCheckpoint(outputDir)
		if err != nil {
			t.Fatalf("load completed checkpoint %q: %v", outputDir, err)
		}
		if checkpoint.Phase != PhaseComplete || !reflect.DeepEqual(checkpoint.RebootIntent, canonical) {
			t.Fatalf("completed checkpoint %q has phase %q and reboot intent %#v, want canonical %#v", outputDir, checkpoint.Phase, checkpoint.RebootIntent, canonical)
		}
	}
	if secondCluster.canonicalReconciliations == 0 {
		t.Fatal("second workspace did not reconcile the adopted canonical reboot intent")
	}
}

func recordRebootProposalForTest(t *testing.T, engine Orchestrator, outputDir string) Checkpoint {
	t.Helper()
	var checkpoint Checkpoint
	err := WithRotationWorkspace(outputDir, func(workspace *RotationWorkspace) error {
		var err error
		checkpoint, err = workspace.LoadCheckpoint()
		if err != nil {
			return err
		}
		return engine.recordRebootIntent(context.Background(), workspace, &checkpoint)
	})
	if err != nil {
		t.Fatalf("record reboot proposal in %q: %v", outputDir, err)
	}
	if checkpoint.Phase != PhaseRebootIntentRecorded || checkpoint.RebootIntent == nil {
		t.Fatalf("reboot proposal checkpoint = %#v", checkpoint)
	}
	return checkpoint
}

func TestOrchestratorResumesFinalPublicationAfterAppliedWriteAndFailedReadback(t *testing.T) {
	oldPublic := testPublicKeyPEM(t)
	newPublic := testPublicKeyPEM(t)
	oldSigner := safetySigner(oldPublic, "old-uid", "10")
	newSigner := safetySigner(newPublic, "new-uid", "11")
	cluster := newSafetyCluster(oldSigner, newSigner)
	publisher := newSafetyPublisher(encodedJWKSForTest(t, oldPublic))
	// Reads 1-4 capture and recheck the current state and confirm combined
	// publication, and read 5 rechecks overlap before reboot. Read 6 is the
	// final predecessor read; read 7 fails after the final write.
	publisher.failReadNumber = 7
	engine := Orchestrator{
		Cluster:   cluster,
		Target:    safetyTarget("aws://issuer/keys.json"),
		Publisher: publisher,
	}
	outputDir := filepath.Join(t.TempDir(), "rotation")
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := engine.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhasePostRebootStable || publisher.publishCalls != 2 {
		t.Fatalf("first Run() result = %#v, publication calls = %d", result, publisher.publishCalls)
	}

	options.Resume = true
	result, err = engine.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("resume Run() returned unexpected error: %v", err)
	}
	if !result.Complete || publisher.publishCalls != 2 {
		t.Fatalf("resume result = %#v, publication calls = %d; final write was repeated", result, publisher.publishCalls)
	}
}

func TestPublishDirectRequiresExpectedPredecessorAndExactReadback(t *testing.T) {
	current := StoredArtifact{Data: []byte("current")}
	combined := StoredArtifact{Data: []byte("combined")}
	newOnly := StoredArtifact{Data: []byte("new-only")}
	checkpoint := Checkpoint{Phase: PhaseCombinedJWKSBuilt, TargetIdentity: "target"}

	t.Run("unrelated provider state is never overwritten", func(t *testing.T) {
		publisher := &safetyPublisher{state: VersionedJWKS{Data: []byte("unrelated"), Revision: "7"}, publishOutcome: EffectSubmitted, applyPublication: true}
		engine := Orchestrator{Publisher: publisher}
		err := engine.publishDirect(context.Background(), checkpoint, combined, current)
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("publishDirect() error = %v, want ConflictError", err)
		}
		if publisher.publishCalls != 0 {
			t.Fatalf("conditional publication calls = %d, want zero", publisher.publishCalls)
		}
	})

	t.Run("new-only state cannot satisfy combined publication", func(t *testing.T) {
		publisher := &safetyPublisher{state: VersionedJWKS{Data: newOnly.Data, Revision: "7"}, publishOutcome: EffectSubmitted, applyPublication: true}
		engine := Orchestrator{Publisher: publisher}
		err := engine.publishDirect(context.Background(), checkpoint, combined, current)
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("publishDirect() error = %v, want ConflictError", err)
		}
		if publisher.publishCalls != 0 {
			t.Fatalf("conditional publication calls = %d, want zero", publisher.publishCalls)
		}
	})

	t.Run("unknown write is accepted only after exact readback", func(t *testing.T) {
		publisher := &safetyPublisher{
			reads: []VersionedJWKS{
				{Data: current.Data, Revision: "7"},
				{Data: combined.Data, Revision: "8"},
			},
			publishOutcome: EffectUnknown,
			publishErr:     errors.New("transport ended before response"),
		}
		engine := Orchestrator{Publisher: publisher}
		if err := engine.publishDirect(context.Background(), checkpoint, combined, current); err != nil {
			t.Fatalf("publishDirect() returned unexpected error after exact readback: %v", err)
		}
	})

	t.Run("unknown write with unchanged readback remains resumable", func(t *testing.T) {
		publisher := &safetyPublisher{
			reads: []VersionedJWKS{
				{Data: current.Data, Revision: "7"},
				{Data: current.Data, Revision: "7"},
			},
			publishOutcome: EffectUnknown,
			publishErr:     errors.New("transport ended before response"),
		}
		engine := Orchestrator{Publisher: publisher}
		err := engine.publishDirect(context.Background(), checkpoint, combined, current)
		var unknown *OutcomeUnknownError
		if !errors.As(err, &unknown) {
			t.Fatalf("publishDirect() error = %v, want OutcomeUnknownError", err)
		}
	})
}

type safetyTarget string

func (target safetyTarget) ResolveTarget(context.Context) (string, error) {
	return string(target), nil
}

type sharedRebootRegistry struct {
	mu               sync.Mutex
	canonical        *RebootIntent
	requestCalls     int
	requestMutations int
}

func (registry *sharedRebootRegistry) observe(operationID string) (RebootObservation, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.canonical == nil {
		return RebootObservation{Status: RebootNotStarted}, nil
	}
	if registry.canonical.ID != operationID {
		return RebootObservation{}, fmt.Errorf("canonical operation ID %q does not match requested ID %q", registry.canonical.ID, operationID)
	}
	canonical := cloneRebootIntent(*registry.canonical)
	return RebootObservation{Status: RebootComplete, CanonicalIntent: &canonical}, nil
}

func (registry *sharedRebootRegistry) request(intent RebootIntent) (EffectOutcome, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.requestCalls++
	if registry.canonical == nil {
		canonical := cloneRebootIntent(intent)
		registry.canonical = &canonical
		registry.requestMutations++
		return EffectSubmitted, nil
	}
	if registry.canonical.ID != intent.ID {
		return EffectNotApplied, fmt.Errorf("canonical operation ID %q does not match requested ID %q", registry.canonical.ID, intent.ID)
	}
	return EffectSubmitted, nil
}

func (registry *sharedRebootRegistry) snapshot() (*RebootIntent, int, int) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.canonical == nil {
		return nil, registry.requestCalls, registry.requestMutations
	}
	canonical := cloneRebootIntent(*registry.canonical)
	return &canonical, registry.requestCalls, registry.requestMutations
}

type sharedRegistryCluster struct {
	*safetyCluster
	registry                 *sharedRebootRegistry
	plan                     RebootPlan
	prepareErr               error
	canonicalReconciliations int
}

func (cluster *sharedRegistryCluster) Reconcile(ctx context.Context, guard RotationGuardReference, expectation ClusterExpectation) error {
	canonical, _, _ := cluster.registry.snapshot()
	if canonical != nil && expectation.RebootIntent != nil {
		if !reflect.DeepEqual(*expectation.RebootIntent, *canonical) {
			return fmt.Errorf("generic reconciliation received stale reboot intent %#v, want canonical %#v", expectation.RebootIntent, canonical)
		}
		cluster.canonicalReconciliations++
	}
	return cluster.safetyCluster.Reconcile(ctx, guard, expectation)
}

func (cluster *sharedRegistryCluster) PrepareReboot(context.Context, RotationGuardReference, string) (RebootPlan, error) {
	if cluster.prepareErr != nil {
		return RebootPlan{}, cluster.prepareErr
	}
	return RebootPlan{
		Targets:   append([]string(nil), cluster.plan.Targets...),
		Baselines: append([]NodeRebootBaseline(nil), cluster.plan.Baselines...),
	}, nil
}

func (cluster *sharedRegistryCluster) ObserveReboot(_ context.Context, _ RotationGuardReference, operationID string) (RebootObservation, error) {
	return cluster.registry.observe(operationID)
}

func (cluster *sharedRegistryCluster) RequestReboot(_ context.Context, _ RotationGuardReference, intent RebootIntent) (EffectOutcome, error) {
	return cluster.registry.request(intent)
}

func (cluster *sharedRegistryCluster) WaitForReboot(context.Context, RotationGuardReference, RebootIntent) error {
	return nil
}

func (cluster *sharedRegistryCluster) WaitForPostRebootStable(context.Context, RotationGuardReference, RebootIntent) error {
	return nil
}

type safetyCluster struct {
	preflight     ClusterPreflight
	nextReference *SignerObjectReference
	nextBundle    PublicSignerBundleObservation
	replacement   safetySignerFixture

	replacementOutcome   EffectOutcome
	replacementErr       error
	replacementRequests  int
	replacementReference SignerObjectReference
	applyReplacement     bool

	rebootIntent        RebootIntent
	canonicalReboot     *RebootIntent
	rebootStatuses      []RebootStatus
	rebootOutcome       EffectOutcome
	rebootErr           error
	rebootRequests      int
	beforeRebootRequest func(RebootIntent) error

	reconcileCalls int

	guardReference        *RotationGuardReference
	completedGuards       map[string]struct{}
	guardAcquireCalls     int
	guardAcquireMutations int
	guardReleaseCalls     int
	guardReleaseMutations int
}

func newSafetyCluster(oldSigner, replacement safetySignerFixture) *safetyCluster {
	return &safetyCluster{
		preflight:     ClusterPreflight{ClusterIdentity: "cluster-123"},
		nextReference: cloneSignerReferenceForTest(&oldSigner.Reference),
		nextBundle: PublicSignerBundleObservation{
			ConfigMapUID:             "safety-signer-configmap-uid",
			ConfigMapResourceVersion: "1000",
			Signers:                  []PublicSignerObservation{clonePublicSignerObservationForTest(oldSigner.Signer)},
		},
		replacement:        replacement,
		replacementOutcome: EffectSubmitted,
		applyReplacement:   true,
		rebootIntent: RebootIntent{
			ID:      "rotation-cluster-123-new-key",
			Targets: []string{"worker", "master"},
			Baselines: []NodeRebootBaseline{
				{Target: "worker", Node: "worker-0", BootID: "worker-boot-old"},
				{Target: "master", Node: "master-0", BootID: "master-boot-old"},
			},
		},
		rebootStatuses: []RebootStatus{RebootComplete},
		rebootOutcome:  EffectSubmitted,
	}
}

func (cluster *safetyCluster) Preflight(context.Context) (ClusterPreflight, error) {
	return ClusterPreflight{
		ClusterIdentity: cluster.preflight.ClusterIdentity,
	}, nil
}

func (cluster *safetyCluster) ObserveRotationGuard(_ context.Context, reference RotationGuardReference) (RotationGuardObservation, error) {
	if _, completed := cluster.completedGuards[reference.OperationID]; completed {
		return RotationGuardObservation{Status: RotationGuardCompleted, OperationID: reference.OperationID}, nil
	}
	if cluster.guardReference == nil {
		return RotationGuardObservation{Status: RotationGuardNotFound}, nil
	}
	if *cluster.guardReference == reference {
		return RotationGuardObservation{Status: RotationGuardHeld, OperationID: reference.OperationID}, nil
	}
	return RotationGuardObservation{Status: RotationGuardOwnedByOther, OperationID: cluster.guardReference.OperationID}, nil
}

func (cluster *safetyCluster) AcquireRotationGuard(_ context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	cluster.guardAcquireCalls++
	if cluster.guardReference == nil {
		stored := reference
		cluster.guardReference = &stored
		cluster.guardAcquireMutations++
		return EffectSubmitted, nil
	}
	if *cluster.guardReference == reference {
		return EffectSubmitted, nil
	}
	return EffectNotApplied, nil
}

func (cluster *safetyCluster) ReleaseRotationGuard(_ context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	cluster.guardReleaseCalls++
	if _, completed := cluster.completedGuards[reference.OperationID]; completed {
		return EffectSubmitted, nil
	}
	if cluster.guardReference == nil || *cluster.guardReference != reference {
		return EffectNotApplied, nil
	}
	cluster.guardReference = nil
	if cluster.completedGuards == nil {
		cluster.completedGuards = make(map[string]struct{})
	}
	cluster.completedGuards[reference.OperationID] = struct{}{}
	cluster.guardReleaseMutations++
	return EffectSubmitted, nil
}

func (cluster *safetyCluster) Reconcile(context.Context, RotationGuardReference, ClusterExpectation) error {
	cluster.reconcileCalls++
	return nil
}

func (cluster *safetyCluster) ObserveSignerReference(context.Context, *RotationGuardReference) (*SignerObjectReference, error) {
	return cloneSignerReferenceForTest(cluster.nextReference), nil
}

func (cluster *safetyCluster) ObservePublicSignerBundle(context.Context, *RotationGuardReference) (PublicSignerBundleObservation, error) {
	return clonePublicSignerBundleForTest(cluster.nextBundle), nil
}

func (cluster *safetyCluster) RequestReplacement(_ context.Context, _ RotationGuardReference, reference SignerObjectReference) (EffectOutcome, error) {
	cluster.replacementRequests++
	cluster.replacementReference = reference
	if cluster.replacementOutcome == EffectSubmitted && cluster.replacementErr == nil && cluster.applyReplacement {
		cluster.applySafetyReplacement()
	}
	return cluster.replacementOutcome, cluster.replacementErr
}

func (cluster *safetyCluster) WaitForReplacement(context.Context, RotationGuardReference, SignerObjectReference) error {
	return nil
}

func (cluster *safetyCluster) applySafetyReplacement() {
	cluster.nextReference = cloneSignerReferenceForTest(&cluster.replacement.Reference)
	cluster.nextBundle.ConfigMapResourceVersion = "1001"
	for _, signer := range cluster.nextBundle.Signers {
		if signer.Name == cluster.replacement.Signer.Name {
			return
		}
	}
	cluster.nextBundle.Signers = append(cluster.nextBundle.Signers, clonePublicSignerObservationForTest(cluster.replacement.Signer))
}

func (cluster *safetyCluster) WaitForSignerRollout(context.Context, RotationGuardReference, string) error {
	return nil
}

func (cluster *safetyCluster) PrepareReboot(context.Context, RotationGuardReference, string) (RebootPlan, error) {
	intent := cloneRebootIntent(cluster.rebootIntent)
	return RebootPlan{Targets: intent.Targets, Baselines: intent.Baselines}, nil
}

func (cluster *safetyCluster) ObserveReboot(_ context.Context, _ RotationGuardReference, operationID string) (RebootObservation, error) {
	status := RebootComplete
	if len(cluster.rebootStatuses) == 0 {
		status = RebootComplete
	} else {
		status = cluster.rebootStatuses[0]
		cluster.rebootStatuses = cluster.rebootStatuses[1:]
	}
	if status == RebootNotStarted {
		return RebootObservation{Status: status}, nil
	}
	intent := cloneRebootIntent(cluster.rebootIntent)
	if cluster.canonicalReboot != nil {
		intent = cloneRebootIntent(*cluster.canonicalReboot)
	} else {
		intent.ID = operationID
	}
	return RebootObservation{Status: status, CanonicalIntent: &intent}, nil
}

func (cluster *safetyCluster) RequestReboot(_ context.Context, _ RotationGuardReference, intent RebootIntent) (EffectOutcome, error) {
	cluster.rebootRequests++
	if cluster.beforeRebootRequest != nil {
		if err := cluster.beforeRebootRequest(intent); err != nil {
			return EffectNotApplied, err
		}
	}
	if cluster.rebootOutcome == EffectSubmitted && cluster.rebootErr == nil && cluster.canonicalReboot == nil {
		canonical := cloneRebootIntent(intent)
		cluster.canonicalReboot = &canonical
	}
	return cluster.rebootOutcome, cluster.rebootErr
}

func (cluster *safetyCluster) WaitForReboot(context.Context, RotationGuardReference, RebootIntent) error {
	return nil
}

func (cluster *safetyCluster) WaitForPostRebootStable(context.Context, RotationGuardReference, RebootIntent) error {
	return nil
}

type mutatingRebootCluster struct {
	*safetyCluster
	t    *testing.T
	want *RebootIntent
}

func (cluster *mutatingRebootCluster) ObserveReboot(ctx context.Context, guard RotationGuardReference, operationID string) (RebootObservation, error) {
	return cluster.safetyCluster.ObserveReboot(ctx, guard, operationID)
}

func (cluster *mutatingRebootCluster) RequestReboot(ctx context.Context, guard RotationGuardReference, intent RebootIntent) (EffectOutcome, error) {
	original := cloneRebootIntent(intent)
	cluster.assertAndMutateIntent(intent)
	return cluster.safetyCluster.RequestReboot(ctx, guard, original)
}

func (cluster *mutatingRebootCluster) WaitForReboot(ctx context.Context, guard RotationGuardReference, intent RebootIntent) error {
	cluster.assertAndMutateIntent(intent)
	return cluster.safetyCluster.WaitForReboot(ctx, guard, intent)
}

func (cluster *mutatingRebootCluster) WaitForPostRebootStable(ctx context.Context, guard RotationGuardReference, intent RebootIntent) error {
	cluster.assertAndMutateIntent(intent)
	return cluster.safetyCluster.WaitForPostRebootStable(ctx, guard, intent)
}

func (cluster *mutatingRebootCluster) assertAndMutateIntent(intent RebootIntent) {
	cluster.t.Helper()
	if cluster.want == nil {
		want := cloneRebootIntent(intent)
		cluster.want = &want
	} else if !reflect.DeepEqual(intent, *cluster.want) {
		cluster.t.Errorf("adapter received mutated reboot intent = %#v, want %#v", intent, *cluster.want)
	}
	if len(intent.Targets) != 0 {
		intent.Targets[0] = "tampered-target"
	}
	if len(intent.Baselines) != 0 {
		intent.Baselines[0].BootID = "tampered-boot-id"
	}
}

type safetySignerFixture struct {
	Signer    PublicSignerObservation
	Reference SignerObjectReference
}

func safetySigner(publicKey []byte, uid, resourceVersion string) safetySignerFixture {
	name := "service-account-001.pub"
	if uid != "old-uid" {
		name = "service-account-002.pub"
	}
	return safetySignerFixture{
		Signer: PublicSignerObservation{
			Name:         name,
			PublicKeyPEM: append([]byte(nil), publicKey...),
		},
		Reference: SignerObjectReference{UID: uid, ResourceVersion: resourceVersion},
	}
}

func safetySignerKeyID(signer safetySignerFixture) (string, error) {
	state, err := normalizePublicSignerBundle(PublicSignerBundleObservation{
		ConfigMapUID:             "test-configmap-uid",
		ConfigMapResourceVersion: "1",
		Signers:                  []PublicSignerObservation{signer.Signer},
	})
	if err != nil {
		return "", err
	}
	return state.Baseline.Entries[0].KeyID, nil
}

type safetyPublisher struct {
	state          VersionedJWKS
	reads          []VersionedJWKS
	readCalls      int
	failReadNumber int

	publishOutcome   EffectOutcome
	publishErr       error
	applyPublication bool
	publishCalls     int
}

func newSafetyPublisher(current []byte) *safetyPublisher {
	return &safetyPublisher{
		state:            VersionedJWKS{Data: append([]byte(nil), current...), Revision: "1"},
		publishOutcome:   EffectSubmitted,
		applyPublication: true,
	}
}

func (publisher *safetyPublisher) CheckAccess(context.Context, string) error {
	return nil
}

func (publisher *safetyPublisher) ReadJWKS(context.Context, string) (VersionedJWKS, error) {
	publisher.readCalls++
	if publisher.failReadNumber == publisher.readCalls {
		return VersionedJWKS{}, errors.New("provider readback unavailable")
	}
	if len(publisher.reads) != 0 {
		read := publisher.reads[0]
		publisher.reads = publisher.reads[1:]
		return VersionedJWKS{Data: append([]byte(nil), read.Data...), Revision: read.Revision}, nil
	}
	return VersionedJWKS{Data: append([]byte(nil), publisher.state.Data...), Revision: publisher.state.Revision}, nil
}

func (publisher *safetyPublisher) PublishIfVersion(_ context.Context, _ string, revision string, data []byte) (EffectOutcome, error) {
	publisher.publishCalls++
	if publisher.applyPublication {
		if revision != publisher.state.Revision {
			return EffectNotApplied, fmt.Errorf("revision changed")
		}
		publisher.state.Data = append([]byte(nil), data...)
		publisher.state.Revision = fmt.Sprintf("%d", publisher.publishCalls+1)
	}
	return publisher.publishOutcome, publisher.publishErr
}

func TestPauseErrorDoesNotExposeJWKSContents(t *testing.T) {
	err := (&PauseError{
		Phase:    PhaseCombinedJWKSBuilt,
		Reason:   PauseForPublication,
		Artifact: ArtifactCombinedJWKS,
		Path:     "/tmp/public/jwks.combined.json",
		SHA256:   testDigest,
	}).Error()
	if strings.Contains(err, `"keys"`) || strings.Contains(err, "/tmp/public") {
		t.Fatalf("PauseError exposed artifact contents or local path: %q", err)
	}
}

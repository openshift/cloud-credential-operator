package rotation

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOrchestratorCancellationBetweenPhasesIsDurableAndStopsBeforeNextEffect(t *testing.T) {
	tests := []struct {
		name              string
		cancelAfter       string
		wantPhase         Phase
		triggerEvent      string
		wantPublications  []string
		wantRebootRequest int
	}{
		{
			name:              "after reboot intent is prepared",
			cancelAfter:       "prepare-reboot",
			wantPhase:         PhaseRebootIntentRecorded,
			triggerEvent:      "cluster.prepare-reboot",
			wantPublications:  []string{"combined"},
			wantRebootRequest: 0,
		},
		{
			name:              "after post-reboot stability",
			cancelAfter:       "post-reboot-stable",
			wantPhase:         PhasePostRebootStable,
			triggerEvent:      "cluster.wait-for-post-reboot-stable",
			wantPublications:  []string{"combined"},
			wantRebootRequest: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeDirect)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cluster := &rebootCoverageCluster{
				fakeClusterRotation: harness.cluster,
				cancel:              cancel,
				cancelAfter:         test.cancelAfter,
			}
			harness.orchestrator.Cluster = cluster
			outputDir := t.TempDir()

			result, err := harness.orchestrator.Run(ctx, RunOptions{
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				OutputDir:       outputDir,
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context.Canceled", err)
			}
			if result.Phase != test.wantPhase || result.Complete {
				t.Fatalf("Run() result = %#v, want phase %q and incomplete", result, test.wantPhase)
			}

			checkpoint, loadErr := LoadCheckpoint(outputDir)
			if loadErr != nil {
				t.Fatalf("load cancelled checkpoint: %v", loadErr)
			}
			if checkpoint.Phase != test.wantPhase || checkpoint.LastErrorCode != errorCodeCancelled {
				t.Fatalf("cancelled checkpoint phase/error = %q/%q, want %q/%q", checkpoint.Phase, checkpoint.LastErrorCode, test.wantPhase, errorCodeCancelled)
			}
			if !equalStrings(harness.publisher.publications, test.wantPublications) {
				t.Fatalf("publications = %v, want %v", harness.publisher.publications, test.wantPublications)
			}
			if harness.cluster.rebootRequests != test.wantRebootRequest {
				t.Fatalf("reboot requests = %d, want %d", harness.cluster.rebootRequests, test.wantRebootRequest)
			}
			trigger := eventIndex(harness.events, test.triggerEvent)
			if trigger < 0 {
				t.Fatalf("trigger event %q was not observed: %v", test.triggerEvent, harness.events)
			}
			if trigger != len(harness.events)-1 {
				t.Fatalf("external events occurred after cancellation trigger %q: %v", test.triggerEvent, harness.events[trigger+1:])
			}
		})
	}
}

func TestOrchestratorRebootEffectNotAppliedDoesNotAdvanceOrWait(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	cluster := &rebootCoverageCluster{
		fakeClusterRotation: harness.cluster,
		overrideRequest:     true,
		requestOutcome:      EffectNotApplied,
	}
	harness.orchestrator.Cluster = cluster
	outputDir := t.TempDir()

	result, err := harness.orchestrator.Run(context.Background(), RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeDirect,
		OutputDir:       outputDir,
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Run() error = %v, want ConflictError", err)
	}
	if result.Phase != PhaseRebootIntentRecorded || result.Complete {
		t.Fatalf("Run() result = %#v, want reboot-intent-recorded and incomplete", result)
	}
	checkpoint, loadErr := LoadCheckpoint(outputDir)
	if loadErr != nil {
		t.Fatalf("load failed checkpoint: %v", loadErr)
	}
	if checkpoint.Phase != PhaseRebootIntentRecorded || checkpoint.LastErrorCode != errorCodeConflict {
		t.Fatalf("checkpoint phase/error = %q/%q, want %q/%q", checkpoint.Phase, checkpoint.LastErrorCode, PhaseRebootIntentRecorded, errorCodeConflict)
	}
	if harness.cluster.rebootRequests != 1 || harness.cluster.canonicalReboot != nil {
		t.Fatalf("reboot request count/canonical record = %d/%#v, want one rejected request and no mutation", harness.cluster.rebootRequests, harness.cluster.canonicalReboot)
	}
	if countExactEvent(harness.events, "cluster.wait-for-reboot") != 0 {
		t.Fatalf("reboot wait ran after a confirmed unapplied request: %v", harness.events)
	}
}

func TestOrchestratorRebootReadbackFailureReconcilesWithoutDuplicateMutation(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	cluster := &rebootCoverageCluster{
		fakeClusterRotation:      harness.cluster,
		failReadbackAfterRequest: true,
	}
	harness.orchestrator.Cluster = cluster
	outputDir := t.TempDir()
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := harness.orchestrator.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("initial Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhaseRebootIntentRecorded || harness.cluster.rebootRequests != 1 {
		t.Fatalf("initial result/request count = %#v/%d, want reboot intent and one request", result, harness.cluster.rebootRequests)
	}
	checkpoint, loadErr := LoadCheckpoint(outputDir)
	if loadErr != nil {
		t.Fatalf("load uncertain checkpoint: %v", loadErr)
	}
	if checkpoint.LastErrorCode != errorCodeExternalOutcomeUnknown {
		t.Fatalf("last error code = %q, want %q", checkpoint.LastErrorCode, errorCodeExternalOutcomeUnknown)
	}

	options.Resume = true
	result, err = harness.orchestrator.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("resumed Run() returned unexpected error: %v", err)
	}
	if !result.Complete || result.Phase != PhaseComplete {
		t.Fatalf("resumed Run() result = %#v, want complete", result)
	}
	if harness.cluster.rebootRequests != 2 || harness.cluster.rebootMutations != 1 {
		t.Fatalf("reboot request calls/mutations after resume = %d/%d, want 2/1", harness.cluster.rebootRequests, harness.cluster.rebootMutations)
	}
}

func TestOrchestratorPartialRebootRequestIsReconciledBeforeWait(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	harness.cluster.rebootIntent = RebootIntent{
		ID:      "rotation-test-intent",
		Targets: []string{"master", "worker"},
		Baselines: []NodeRebootBaseline{
			{Target: "master", Node: "master-0", BootID: "master-boot-old"},
			{Target: "worker", Node: "worker-0", BootID: "worker-boot-old"},
		},
	}
	cluster := &partialRebootCluster{
		fakeClusterRotation: harness.cluster,
		targetRequests:      make(map[string]int),
	}
	harness.orchestrator.Cluster = cluster
	outputDir := t.TempDir()
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := harness.orchestrator.Run(context.Background(), options)
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("initial Run() error = %v, want OutcomeUnknownError", err)
	}
	if result.Phase != PhaseRebootIntentRecorded || cluster.requestCalls != 1 || cluster.canonicalWrites != 1 || cluster.waitCalls != 0 {
		t.Fatalf("initial phase/request calls/canonical writes/waits = %q/%d/%d/%d, want %q/1/1/0", result.Phase, cluster.requestCalls, cluster.canonicalWrites, cluster.waitCalls, PhaseRebootIntentRecorded)
	}
	if cluster.targetRequests["master"] != 1 || cluster.targetRequests["worker"] != 0 {
		t.Fatalf("initial target requests = %v, want only master requested", cluster.targetRequests)
	}

	options.Resume = true
	result, err = harness.orchestrator.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("resumed Run() returned unexpected error: %v", err)
	}
	if !result.Complete || result.Phase != PhaseComplete {
		t.Fatalf("resumed Run() result = %#v, want complete", result)
	}
	if cluster.requestCalls != 2 || cluster.canonicalWrites != 1 || cluster.waitCalls != 1 {
		t.Fatalf("final request calls/canonical writes/waits = %d/%d/%d, want 2/1/1", cluster.requestCalls, cluster.canonicalWrites, cluster.waitCalls)
	}
	for _, target := range []string{"master", "worker"} {
		if cluster.targetRequests[target] != 1 {
			t.Fatalf("target %q request mutations = %d, want 1; all targets = %v", target, cluster.targetRequests[target], cluster.targetRequests)
		}
	}
}

func TestOrchestratorRejectsWaitThatReturnsBeforeCanonicalRebootCompletion(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	cluster := &rebootCoverageCluster{
		fakeClusterRotation:   harness.cluster,
		waitWithoutCompletion: true,
	}
	harness.orchestrator.Cluster = cluster
	outputDir := t.TempDir()
	options := RunOptions{Provider: ProviderAWS, PublicationMode: PublicationModeDirect, OutputDir: outputDir}

	result, err := harness.orchestrator.Run(context.Background(), options)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || !strings.Contains(err.Error(), "returned before intent") {
		t.Fatalf("initial Run() error = %v, want early-wait ConflictError", err)
	}
	if result.Phase != PhaseRebootIntentRecorded || harness.cluster.rebootRequests != 1 || cluster.waitCalls != 1 {
		t.Fatalf("initial phase/requests/waits = %q/%d/%d, want %q/1/1", result.Phase, harness.cluster.rebootRequests, cluster.waitCalls, PhaseRebootIntentRecorded)
	}
	checkpoint, loadErr := LoadCheckpoint(outputDir)
	if loadErr != nil {
		t.Fatalf("load early-wait checkpoint: %v", loadErr)
	}
	if checkpoint.LastErrorCode != errorCodeConflict {
		t.Fatalf("last error code = %q, want %q", checkpoint.LastErrorCode, errorCodeConflict)
	}

	options.Resume = true
	result, err = harness.orchestrator.Run(context.Background(), options)
	if !errors.As(err, &conflict) {
		t.Fatalf("resumed Run() error = %v, want ConflictError", err)
	}
	if result.Phase != PhaseRebootIntentRecorded || harness.cluster.rebootRequests != 2 || harness.cluster.rebootMutations != 1 || cluster.waitCalls != 2 {
		t.Fatalf("resumed phase/request calls/mutations/waits = %q/%d/%d/%d, want %q/2/1/2", result.Phase, harness.cluster.rebootRequests, harness.cluster.rebootMutations, cluster.waitCalls, PhaseRebootIntentRecorded)
	}
}

type rebootCoverageCluster struct {
	*fakeClusterRotation
	cancel                   context.CancelFunc
	cancelAfter              string
	overrideRequest          bool
	requestOutcome           EffectOutcome
	requestErr               error
	failReadbackAfterRequest bool
	failNextRebootReadback   bool
	waitWithoutCompletion    bool
	waitCalls                int
}

type partialRebootCluster struct {
	*fakeClusterRotation
	requestCalls    int
	canonicalWrites int
	targetRequests  map[string]int
	waitCalls       int
}

func (cluster *partialRebootCluster) RequestReboot(_ context.Context, guard RotationGuardReference, intent RebootIntent) (EffectOutcome, error) {
	*cluster.events = append(*cluster.events, "cluster.request-reboot")
	if err := cluster.requireHeldRotationGuard(guard); err != nil {
		return EffectNotApplied, err
	}
	cluster.requestCalls++
	if cluster.canonicalReboot == nil {
		canonical := cloneRebootIntent(intent)
		cluster.canonicalReboot = &canonical
		cluster.canonicalWrites++
	}
	cluster.rebootStatus = RebootInProgress
	for _, target := range cluster.canonicalReboot.Targets {
		if cluster.targetRequests[target] != 0 {
			continue
		}
		cluster.targetRequests[target]++
		if cluster.requestCalls == 1 {
			return EffectUnknown, errors.New("remaining reboot target request outcome is unknown")
		}
	}
	return EffectSubmitted, nil
}

func (cluster *partialRebootCluster) WaitForReboot(ctx context.Context, guard RotationGuardReference, intent RebootIntent) error {
	cluster.waitCalls++
	return cluster.fakeClusterRotation.WaitForReboot(ctx, guard, intent)
}

func (cluster *rebootCoverageCluster) PrepareReboot(ctx context.Context, guard RotationGuardReference, replacementKeyID string) (RebootPlan, error) {
	plan, err := cluster.fakeClusterRotation.PrepareReboot(ctx, guard, replacementKeyID)
	if err == nil && cluster.cancelAfter == "prepare-reboot" {
		cluster.cancel()
	}
	return plan, err
}

func (cluster *rebootCoverageCluster) RequestReboot(ctx context.Context, guard RotationGuardReference, intent RebootIntent) (EffectOutcome, error) {
	if cluster.overrideRequest {
		*cluster.events = append(*cluster.events, "cluster.request-reboot")
		cluster.rebootRequests++
		return cluster.requestOutcome, cluster.requestErr
	}
	outcome, err := cluster.fakeClusterRotation.RequestReboot(ctx, guard, intent)
	if cluster.failReadbackAfterRequest {
		cluster.failReadbackAfterRequest = false
		cluster.failNextRebootReadback = true
	}
	return outcome, err
}

func (cluster *rebootCoverageCluster) ObserveReboot(ctx context.Context, guard RotationGuardReference, operationID string) (RebootObservation, error) {
	if cluster.failNextRebootReadback {
		cluster.failNextRebootReadback = false
		*cluster.events = append(*cluster.events, "cluster.observe-reboot:error")
		return RebootObservation{}, errors.New("reboot request readback failed")
	}
	return cluster.fakeClusterRotation.ObserveReboot(ctx, guard, operationID)
}

func (cluster *rebootCoverageCluster) WaitForReboot(ctx context.Context, guard RotationGuardReference, intent RebootIntent) error {
	cluster.waitCalls++
	if cluster.waitWithoutCompletion {
		*cluster.events = append(*cluster.events, "cluster.wait-for-reboot")
		return nil
	}
	return cluster.fakeClusterRotation.WaitForReboot(ctx, guard, intent)
}

func (cluster *rebootCoverageCluster) WaitForPostRebootStable(ctx context.Context, guard RotationGuardReference, intent RebootIntent) error {
	err := cluster.fakeClusterRotation.WaitForPostRebootStable(ctx, guard, intent)
	if err == nil && cluster.cancelAfter == "post-reboot-stable" {
		cluster.cancel()
	}
	return err
}

func eventIndex(events []string, target string) int {
	for index, event := range events {
		if event == target {
			return index
		}
	}
	return -1
}

func countExactEvent(events []string, target string) int {
	count := 0
	for _, event := range events {
		if event == target {
			count++
		}
	}
	return count
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

package rotation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestOrchestratorDirectHappyPathOrdersExternalEffects(t *testing.T) {
	t.Parallel()

	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	outputDir := t.TempDir()

	result, err := harness.orchestrator.Run(context.Background(), RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeDirect,
		OutputDir:       outputDir,
	})
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if result.Phase != PhaseComplete || !result.Complete {
		t.Fatalf("Run() result = %+v, want complete phase", result)
	}

	wantEvents := []string{
		"cluster.preflight",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"target.resolve",
		"publisher.check-access",
		"cluster.observe-rotation-guard",
		"cluster.acquire-rotation-guard",
		"cluster.observe-rotation-guard",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"cluster.observe-rotation-guard",
		"publisher.read:current",
		"cluster.observe-rotation-guard",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"publisher.read:current",
		"cluster.request-replacement",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"cluster.observe-rotation-guard",
		"cluster.wait-for-replacement",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"cluster.observe-rotation-guard",
		"cluster.observe-rotation-guard",
		"cluster.observe-rotation-guard",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"publisher.read:current",
		"publisher.publish:combined",
		"publisher.read:combined",
		"cluster.observe-rotation-guard",
		"cluster.wait-for-signer-rollout",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"publisher.read:combined",
		"cluster.observe-rotation-guard",
		"cluster.observe-reboot:not-started",
		"cluster.prepare-reboot",
		"cluster.observe-rotation-guard",
		"cluster.observe-reboot:not-started",
		"cluster.request-reboot",
		"cluster.observe-reboot:in-progress",
		"cluster.wait-for-reboot",
		"cluster.observe-reboot:complete",
		"cluster.observe-rotation-guard",
		"cluster.wait-for-post-reboot-stable",
		"cluster.observe-rotation-guard",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"publisher.read:combined",
		"publisher.publish:new-only",
		"publisher.read:new-only",
		"cluster.observe-rotation-guard",
		"cluster.observe-rotation-guard",
		"target.resolve",
		"publisher.check-access",
		"cluster.observe-reboot:complete",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"cluster.reconcile:new-only-jwks-published",
		"publisher.read:new-only",
		"cluster.observe-rotation-guard",
		"cluster.release-rotation-guard",
		"cluster.observe-rotation-guard",
	}
	if !reflect.DeepEqual(harness.events, wantEvents) {
		t.Fatalf("external effect order =\n%q\nwant\n%q", harness.events, wantEvents)
	}

	if harness.cluster.replacementRequests != 1 {
		t.Fatalf("replacement requests = %d, want 1", harness.cluster.replacementRequests)
	}
	if harness.cluster.rebootRequests != 1 {
		t.Fatalf("reboot requests = %d, want 1", harness.cluster.rebootRequests)
	}
	if !reflect.DeepEqual(harness.publisher.publications, []string{"combined", "new-only"}) {
		t.Fatalf("provider publications = %v, want combined then new-only", harness.publisher.publications)
	}
	if harness.cluster.requestedReference != harness.initialReference {
		t.Fatalf("replacement precondition = %+v, want %+v", harness.cluster.requestedReference, harness.initialReference)
	}
	if harness.cluster.waitedReference != harness.initialReference {
		t.Fatalf("replacement wait reference = %+v, want %+v", harness.cluster.waitedReference, harness.initialReference)
	}
	if harness.cluster.rolloutKeyID != harness.replacementKeyID {
		t.Fatalf("rollout key ID = %q, want %q", harness.cluster.rolloutKeyID, harness.replacementKeyID)
	}
	if harness.cluster.rebootKeyID != harness.replacementKeyID {
		t.Fatalf("reboot key ID = %q, want %q", harness.cluster.rebootKeyID, harness.replacementKeyID)
	}

	checkpoint, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("LoadCheckpoint() returned unexpected error: %v", err)
	}
	wantArtifactNames := []string{
		ArtifactCurrentJWKS,
		ArtifactReplacementPublicKey,
		ArtifactNewJWKS,
		ArtifactCombinedJWKS,
	}
	gotArtifactNames := make([]string, 0, len(checkpoint.Artifacts))
	for _, artifact := range checkpoint.Artifacts {
		gotArtifactNames = append(gotArtifactNames, artifact.Name)
	}
	if !reflect.DeepEqual(gotArtifactNames, wantArtifactNames) {
		t.Fatalf("checkpoint artifact order = %v, want %v", gotArtifactNames, wantArtifactNames)
	}
	wantPublications := []PublicationConfirmation{
		{Phase: PhaseCombinedJWKSPublished, Artifact: ArtifactCombinedJWKS, SHA256: harness.combinedSHA256},
		{Phase: PhaseNewOnlyJWKSPublished, Artifact: ArtifactNewJWKS, SHA256: harness.newOnlySHA256},
	}
	if !reflect.DeepEqual(checkpoint.Publications, wantPublications) {
		t.Fatalf("checkpoint publications = %+v, want %+v", checkpoint.Publications, wantPublications)
	}
}

func TestOrchestratorManualPublicationRequiresDigestBoundAcknowledgementsAcrossResumes(t *testing.T) {
	t.Parallel()

	harness := newOrchestratorTestHarness(t, PublicationModeManual)
	outputDir := t.TempDir()
	baseOptions := RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeManual,
		OutputDir:       outputDir,
	}

	result, err := harness.orchestrator.Run(context.Background(), baseOptions)
	currentPause := requireOrchestratorPause(t, err, PhaseGuardAcquired, PauseForCurrentJWKS, ArtifactCurrentJWKS)
	if result.Phase != PhaseGuardAcquired || result.Complete {
		t.Fatalf("initial Run() result = %+v, want paused after guard acquisition", result)
	}
	if currentPause.SHA256 != "" {
		t.Fatalf("current-JWKS pause digest = %q, want empty digest", currentPause.SHA256)
	}

	withCurrent := baseOptions
	withCurrent.Resume = true
	withCurrent.Manual.CurrentJWKS = append([]byte(nil), harness.currentJWKS...)
	result, err = harness.orchestrator.Run(context.Background(), withCurrent)
	combinedPause := requireOrchestratorPause(t, err, PhaseCombinedJWKSBuilt, PauseForPublication, ArtifactCombinedJWKS)
	if result.Phase != PhaseCombinedJWKSBuilt || result.Complete {
		t.Fatalf("Run() with current JWKS result = %+v, want combined-JWKS pause", result)
	}
	if combinedPause.SHA256 != harness.combinedSHA256 {
		t.Fatalf("combined-JWKS pause digest = %q, want %q", combinedPause.SHA256, harness.combinedSHA256)
	}

	wrongAcknowledgement := baseOptions
	wrongAcknowledgement.Resume = true
	wrongAcknowledgement.Manual.Acknowledgement = &ManualAcknowledgement{
		Phase:    PhaseCombinedJWKSPublished,
		Artifact: combinedPause.Artifact,
		SHA256:   combinedPause.SHA256 + "-different",
	}
	result, err = harness.orchestrator.Run(context.Background(), wrongAcknowledgement)
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Run() with wrong digest error = %v, want ConflictError", err)
	}
	if result.Phase != PhaseCombinedJWKSBuilt {
		t.Fatalf("Run() with wrong digest phase = %q, want %q", result.Phase, PhaseCombinedJWKSBuilt)
	}
	checkpoint, loadErr := LoadCheckpoint(outputDir)
	if loadErr != nil {
		t.Fatalf("LoadCheckpoint() after rejected acknowledgement returned error: %v", loadErr)
	}
	if checkpoint.Phase != PhaseCombinedJWKSBuilt || len(checkpoint.Publications) != 0 {
		t.Fatalf("checkpoint advanced after rejected acknowledgement: %+v", checkpoint)
	}

	acknowledgeCombined := baseOptions
	acknowledgeCombined.Resume = true
	acknowledgeCombined.Manual.Acknowledgement = &ManualAcknowledgement{
		Phase:    PhaseCombinedJWKSPublished,
		Artifact: combinedPause.Artifact,
		SHA256:   combinedPause.SHA256,
	}
	result, err = harness.orchestrator.Run(context.Background(), acknowledgeCombined)
	newOnlyPause := requireOrchestratorPause(t, err, PhasePostRebootStable, PauseForPublication, ArtifactNewJWKS)
	if result.Phase != PhasePostRebootStable || result.Complete {
		t.Fatalf("Run() after combined acknowledgement result = %+v, want new-only pause", result)
	}
	if newOnlyPause.SHA256 != harness.newOnlySHA256 {
		t.Fatalf("new-only pause digest = %q, want %q", newOnlyPause.SHA256, harness.newOnlySHA256)
	}

	acknowledgeNewOnly := baseOptions
	acknowledgeNewOnly.Resume = true
	acknowledgeNewOnly.Manual.Acknowledgement = &ManualAcknowledgement{
		Phase:    PhaseNewOnlyJWKSPublished,
		Artifact: newOnlyPause.Artifact,
		SHA256:   newOnlyPause.SHA256,
	}
	result, err = harness.orchestrator.Run(context.Background(), acknowledgeNewOnly)
	if err != nil {
		t.Fatalf("Run() after new-only acknowledgement returned unexpected error: %v", err)
	}
	if result.Phase != PhaseComplete || !result.Complete {
		t.Fatalf("final Run() result = %+v, want complete phase", result)
	}

	wantReconciledPhases := []Phase{
		PhaseGuardAcquired,
		PhaseCombinedJWKSBuilt,
		PhaseCombinedJWKSBuilt,
		PhasePostRebootStable,
		PhaseNewOnlyJWKSPublished,
	}
	if !reflect.DeepEqual(harness.cluster.reconciledPhases(), wantReconciledPhases) {
		t.Fatalf("reconciled phases = %v, want %v", harness.cluster.reconciledPhases(), wantReconciledPhases)
	}
	checkpoint, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("LoadCheckpoint() returned unexpected error: %v", err)
	}
	if checkpoint.LastErrorCode != "" {
		t.Fatalf("completed checkpoint last error code = %q, want empty", checkpoint.LastErrorCode)
	}
	wantPublications := []PublicationConfirmation{
		{Phase: PhaseCombinedJWKSPublished, Artifact: ArtifactCombinedJWKS, SHA256: harness.combinedSHA256},
		{Phase: PhaseNewOnlyJWKSPublished, Artifact: ArtifactNewJWKS, SHA256: harness.newOnlySHA256},
	}
	if !reflect.DeepEqual(checkpoint.Publications, wantPublications) {
		t.Fatalf("checkpoint publications = %+v, want %+v", checkpoint.Publications, wantPublications)
	}
}

func TestOrchestratorResumeReconcilesBeforeContinuing(t *testing.T) {
	t.Parallel()

	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	outputDir := t.TempDir()
	interrupted := errors.New("rollout observation interrupted")
	harness.cluster.waitForSignerError = interrupted

	options := RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeDirect,
		OutputDir:       outputDir,
	}
	result, err := harness.orchestrator.Run(context.Background(), options)
	if !errors.Is(err, interrupted) {
		t.Fatalf("initial Run() error = %v, want %v", err, interrupted)
	}
	if result.Phase != PhaseCombinedJWKSPublished || result.Complete {
		t.Fatalf("initial Run() result = %+v, want interruption after combined publication", result)
	}
	if !reflect.DeepEqual(harness.publisher.publications, []string{"combined"}) {
		t.Fatalf("initial provider publications = %v, want only combined", harness.publisher.publications)
	}

	harness.events = nil
	options.Resume = true
	result, err = harness.orchestrator.Run(context.Background(), options)
	if err != nil {
		t.Fatalf("resumed Run() returned unexpected error: %v", err)
	}
	if result.Phase != PhaseComplete || !result.Complete {
		t.Fatalf("resumed Run() result = %+v, want complete phase", result)
	}

	wantPrefix := []string{
		"cluster.observe-rotation-guard",
		"target.resolve",
		"publisher.check-access",
		"cluster.observe-signer-reference",
		"cluster.observe-public-signer-bundle",
		"cluster.observe-signer-reference",
		"cluster.reconcile:combined-jwks-published",
		"publisher.read:combined",
		"cluster.observe-rotation-guard",
		"cluster.wait-for-signer-rollout",
	}
	if len(harness.events) < len(wantPrefix) || !reflect.DeepEqual(harness.events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("resumed external effect prefix = %v, want %v", harness.events, wantPrefix)
	}
	if !reflect.DeepEqual(harness.publisher.publications, []string{"combined", "new-only"}) {
		t.Fatalf("provider publications across resume = %v, want no repeated combined publication", harness.publisher.publications)
	}
	if len(harness.cluster.expectations) != 2 {
		t.Fatalf("reconciliation calls = %d, want 2", len(harness.cluster.expectations))
	}
	firstExpectation := harness.cluster.expectations[0]
	if firstExpectation.Phase != PhaseCombinedJWKSPublished {
		t.Fatalf("first reconciliation phase = %q, want %q", firstExpectation.Phase, PhaseCombinedJWKSPublished)
	}
	if firstExpectation.ClusterIdentity != harness.clusterIdentity {
		t.Fatalf("reconciled cluster identity = %q, want %q", firstExpectation.ClusterIdentity, harness.clusterIdentity)
	}
	if len(firstExpectation.PreRotationSignerBaseline.Entries) != 1 || firstExpectation.PreRotationSignerBaseline.Entries[0].KeyID != harness.initialKeyID {
		t.Fatalf("reconciled pre-rotation signer baseline = %#v, want key %q", firstExpectation.PreRotationSignerBaseline, harness.initialKeyID)
	}
	if firstExpectation.ReplacementSigner == nil || firstExpectation.ReplacementSigner.Entry.KeyID != harness.replacementKeyID {
		t.Fatalf("reconciled replacement signer = %#v, want key %q", firstExpectation.ReplacementSigner, harness.replacementKeyID)
	}
	if firstExpectation.RebootIntent != nil {
		t.Fatalf("reconciliation before reboot intent unexpectedly received %+v", firstExpectation.RebootIntent)
	}
}

func requireOrchestratorPause(t *testing.T, err error, phase Phase, reason PauseReason, artifact string) *PauseError {
	t.Helper()
	var pause *PauseError
	if !errors.As(err, &pause) {
		t.Fatalf("Run() error = %v, want PauseError", err)
	}
	if pause.Phase != phase || pause.Reason != reason || pause.Artifact != artifact {
		t.Fatalf("PauseError = %+v, want phase %q, reason %q, artifact %q", pause, phase, reason, artifact)
	}
	return pause
}

type orchestratorTestHarness struct {
	events           []string
	orchestrator     Orchestrator
	cluster          *fakeClusterRotation
	publisher        *fakeConditionalJWKSBackend
	initialReference SignerObjectReference
	currentJWKS      []byte
	initialKeyID     string
	replacementKeyID string
	clusterIdentity  string
	combinedSHA256   string
	newOnlySHA256    string
}

func newOrchestratorTestHarness(t *testing.T, mode PublicationMode) *orchestratorTestHarness {
	t.Helper()

	initialPublicKey := testPublicKeyPEM(t)
	replacementPublicKey := testPublicKeyPEM(t)
	currentJWKS := encodedJWKSForTest(t, initialPublicKey)
	prepared, err := PrepareJWKSArtifacts(currentJWKS, replacementPublicKey)
	if err != nil {
		t.Fatalf("PrepareJWKSArtifacts() returned unexpected error: %v", err)
	}

	initialReference := SignerObjectReference{
		UID:             "initial-signer-uid",
		ResourceVersion: "100",
	}
	replacementReference := SignerObjectReference{
		UID:             "replacement-signer-uid",
		ResourceVersion: "200",
	}
	initialBundle := PublicSignerBundleObservation{
		ConfigMapUID:             "signer-configmap-uid",
		ConfigMapResourceVersion: "1000",
		Signers: []PublicSignerObservation{{
			Name:         "service-account-001.pub",
			PublicKeyPEM: initialPublicKey,
		}},
	}
	replacement := PublicSignerObservation{
		Name:         "service-account-002.pub",
		PublicKeyPEM: replacementPublicKey,
	}
	initialState, err := normalizePublicSignerBundle(initialBundle)
	if err != nil {
		t.Fatalf("validate initial signer fixture: %v", err)
	}
	replacementState, err := normalizePublicSignerBundle(PublicSignerBundleObservation{
		ConfigMapUID:             initialBundle.ConfigMapUID,
		ConfigMapResourceVersion: "1001",
		Signers:                  append(clonePublicSignerObservationsForTest(initialBundle.Signers), replacement),
	})
	if err != nil {
		t.Fatalf("validate replacement signer fixture: %v", err)
	}
	initialKeyID := initialState.Baseline.Entries[0].KeyID
	replacementKeyID := replacementState.Baseline.Entries[1].KeyID

	harness := &orchestratorTestHarness{
		initialReference: initialReference,
		currentJWKS:      append([]byte(nil), currentJWKS...),
		initialKeyID:     initialKeyID,
		replacementKeyID: replacementKeyID,
		clusterIdentity:  "cluster-test-identity",
		combinedSHA256:   prepared.Combined.SHA256,
		newOnlySHA256:    prepared.New.SHA256,
	}
	harness.cluster = &fakeClusterRotation{
		events:               &harness.events,
		clusterIdentity:      harness.clusterIdentity,
		nextReference:        cloneSignerReferenceForTest(&initialReference),
		nextBundle:           clonePublicSignerBundleForTest(initialBundle),
		replacementReference: replacementReference,
		replacement:          clonePublicSignerObservationForTest(replacement),
		rebootIntent: RebootIntent{
			ID:      "rotation-test-intent",
			Targets: []string{"worker"},
			Baselines: []NodeRebootBaseline{
				{Target: "worker", Node: "worker-0", BootID: "initial-boot-id"},
			},
		},
		rebootStatus: RebootNotStarted,
	}
	target := &fakeTargetResolver{
		events: &harness.events,
		target: "aws://test-issuer/jwks",
	}
	harness.publisher = &fakeConditionalJWKSBackend{
		events:   &harness.events,
		target:   target.target,
		data:     append([]byte(nil), currentJWKS...),
		current:  append([]byte(nil), currentJWKS...),
		combined: append([]byte(nil), prepared.Combined.Data...),
		newOnly:  append([]byte(nil), prepared.New.Data...),
		revision: 1,
	}
	harness.orchestrator = Orchestrator{
		Cluster: harness.cluster,
		Target:  target,
	}
	if mode == PublicationModeDirect {
		harness.orchestrator.Publisher = harness.publisher
	}
	return harness
}

type fakeTargetResolver struct {
	events *[]string
	target string
}

func (f *fakeTargetResolver) ResolveTarget(context.Context) (string, error) {
	*f.events = append(*f.events, "target.resolve")
	return f.target, nil
}

type fakeConditionalJWKSBackend struct {
	events       *[]string
	target       string
	data         []byte
	current      []byte
	combined     []byte
	newOnly      []byte
	revision     int
	publications []string
}

func (f *fakeConditionalJWKSBackend) CheckAccess(_ context.Context, target string) error {
	*f.events = append(*f.events, "publisher.check-access")
	if target != f.target {
		return fmt.Errorf("target = %q, want %q", target, f.target)
	}
	return nil
}

func (f *fakeConditionalJWKSBackend) ReadJWKS(_ context.Context, target string) (VersionedJWKS, error) {
	label := f.dataLabel(f.data)
	*f.events = append(*f.events, "publisher.read:"+label)
	if target != f.target {
		return VersionedJWKS{}, fmt.Errorf("target = %q, want %q", target, f.target)
	}
	return VersionedJWKS{
		Data:     append([]byte(nil), f.data...),
		Revision: fmt.Sprintf("revision-%d", f.revision),
	}, nil
}

func (f *fakeConditionalJWKSBackend) PublishIfVersion(_ context.Context, target, revision string, data []byte) (EffectOutcome, error) {
	label := f.dataLabel(data)
	*f.events = append(*f.events, "publisher.publish:"+label)
	if target != f.target {
		return EffectNotApplied, fmt.Errorf("target = %q, want %q", target, f.target)
	}
	wantRevision := fmt.Sprintf("revision-%d", f.revision)
	if revision != wantRevision {
		return EffectNotApplied, fmt.Errorf("revision = %q, want %q", revision, wantRevision)
	}
	if label != "combined" && label != "new-only" {
		return EffectNotApplied, fmt.Errorf("unexpected publication payload")
	}
	f.data = append([]byte(nil), data...)
	f.revision++
	f.publications = append(f.publications, label)
	return EffectSubmitted, nil
}

func (f *fakeConditionalJWKSBackend) dataLabel(data []byte) string {
	switch {
	case bytes.Equal(data, f.current):
		return "current"
	case bytes.Equal(data, f.combined):
		return "combined"
	case bytes.Equal(data, f.newOnly):
		return "new-only"
	default:
		return "unknown"
	}
}

type fakeClusterRotation struct {
	events                *[]string
	clusterIdentity       string
	nextReference         *SignerObjectReference
	nextBundle            PublicSignerBundleObservation
	replacementReference  SignerObjectReference
	replacement           PublicSignerObservation
	rebootIntent          RebootIntent
	canonicalReboot       *RebootIntent
	rebootStatus          RebootStatus
	waitForSignerError    error
	replacementRequests   int
	rebootRequests        int
	bundleObservations    int
	applyReplacementAt    int
	requestedReference    SignerObjectReference
	waitedReference       SignerObjectReference
	rolloutKeyID          string
	rebootKeyID           string
	expectations          []ClusterExpectation
	guardReference        *RotationGuardReference
	completedGuards       map[string]struct{}
	guardAcquireCalls     int
	guardAcquireMutations int
	guardReleaseCalls     int
	guardReleaseMutations int
}

func (f *fakeClusterRotation) Preflight(context.Context) (ClusterPreflight, error) {
	*f.events = append(*f.events, "cluster.preflight")
	return ClusterPreflight{
		ClusterIdentity: f.clusterIdentity,
	}, nil
}

func (f *fakeClusterRotation) ObserveRotationGuard(_ context.Context, reference RotationGuardReference) (RotationGuardObservation, error) {
	*f.events = append(*f.events, "cluster.observe-rotation-guard")
	if _, completed := f.completedGuards[reference.OperationID]; completed {
		return RotationGuardObservation{Status: RotationGuardCompleted, OperationID: reference.OperationID}, nil
	}
	if f.guardReference == nil {
		return RotationGuardObservation{Status: RotationGuardNotFound}, nil
	}
	if *f.guardReference == reference {
		return RotationGuardObservation{Status: RotationGuardHeld, OperationID: reference.OperationID}, nil
	}
	return RotationGuardObservation{Status: RotationGuardOwnedByOther, OperationID: f.guardReference.OperationID}, nil
}

func (f *fakeClusterRotation) AcquireRotationGuard(_ context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	*f.events = append(*f.events, "cluster.acquire-rotation-guard")
	f.guardAcquireCalls++
	if f.guardReference == nil {
		stored := reference
		f.guardReference = &stored
		f.guardAcquireMutations++
		return EffectSubmitted, nil
	}
	if *f.guardReference == reference {
		return EffectSubmitted, nil
	}
	return EffectNotApplied, nil
}

func (f *fakeClusterRotation) ReleaseRotationGuard(_ context.Context, reference RotationGuardReference) (EffectOutcome, error) {
	*f.events = append(*f.events, "cluster.release-rotation-guard")
	f.guardReleaseCalls++
	if _, completed := f.completedGuards[reference.OperationID]; completed {
		return EffectSubmitted, nil
	}
	if f.guardReference == nil || *f.guardReference != reference {
		return EffectNotApplied, nil
	}
	f.guardReference = nil
	if f.completedGuards == nil {
		f.completedGuards = make(map[string]struct{})
	}
	f.completedGuards[reference.OperationID] = struct{}{}
	f.guardReleaseMutations++
	return EffectSubmitted, nil
}

func (f *fakeClusterRotation) Reconcile(_ context.Context, guard RotationGuardReference, expectation ClusterExpectation) error {
	*f.events = append(*f.events, "cluster.reconcile:"+string(expectation.Phase))
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return err
	}
	if expectation.RotationGuard != guard {
		return fmt.Errorf("reconciliation guard = %#v, want %#v", guard, expectation.RotationGuard)
	}
	f.expectations = append(f.expectations, cloneClusterExpectationForTest(expectation))
	return nil
}

func (f *fakeClusterRotation) ObserveSignerReference(_ context.Context, guard *RotationGuardReference) (*SignerObjectReference, error) {
	*f.events = append(*f.events, "cluster.observe-signer-reference")
	if guard != nil {
		if err := f.requireHeldRotationGuard(*guard); err != nil {
			return nil, err
		}
	}
	return cloneSignerReferenceForTest(f.nextReference), nil
}

func (f *fakeClusterRotation) ObservePublicSignerBundle(_ context.Context, guard *RotationGuardReference) (PublicSignerBundleObservation, error) {
	*f.events = append(*f.events, "cluster.observe-public-signer-bundle")
	if guard != nil {
		if err := f.requireHeldRotationGuard(*guard); err != nil {
			return PublicSignerBundleObservation{}, err
		}
	}
	f.bundleObservations++
	if f.applyReplacementAt == f.bundleObservations {
		f.applyReplacementForTest()
	}
	return clonePublicSignerBundleForTest(f.nextBundle), nil
}

func (f *fakeClusterRotation) RequestReplacement(_ context.Context, guard RotationGuardReference, reference SignerObjectReference) (EffectOutcome, error) {
	*f.events = append(*f.events, "cluster.request-replacement")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return EffectNotApplied, err
	}
	f.replacementRequests++
	f.requestedReference = reference
	f.applyReplacementForTest()
	return EffectSubmitted, nil
}

func (f *fakeClusterRotation) applyReplacementForTest() {
	f.nextReference = cloneSignerReferenceForTest(&f.replacementReference)
	f.nextBundle.ConfigMapResourceVersion = "1001"
	for _, signer := range f.nextBundle.Signers {
		if signer.Name == f.replacement.Name {
			return
		}
	}
	f.nextBundle.Signers = append(f.nextBundle.Signers, clonePublicSignerObservationForTest(f.replacement))
}

func (f *fakeClusterRotation) WaitForReplacement(_ context.Context, guard RotationGuardReference, reference SignerObjectReference) error {
	*f.events = append(*f.events, "cluster.wait-for-replacement")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return err
	}
	f.waitedReference = reference
	return nil
}

func (f *fakeClusterRotation) WaitForSignerRollout(_ context.Context, guard RotationGuardReference, replacementKeyID string) error {
	*f.events = append(*f.events, "cluster.wait-for-signer-rollout")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return err
	}
	f.rolloutKeyID = replacementKeyID
	if f.waitForSignerError != nil {
		err := f.waitForSignerError
		f.waitForSignerError = nil
		return err
	}
	return nil
}

func (f *fakeClusterRotation) PrepareReboot(_ context.Context, guard RotationGuardReference, replacementKeyID string) (RebootPlan, error) {
	*f.events = append(*f.events, "cluster.prepare-reboot")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return RebootPlan{}, err
	}
	f.rebootKeyID = replacementKeyID
	intent := cloneRebootIntent(f.rebootIntent)
	return RebootPlan{Targets: intent.Targets, Baselines: intent.Baselines}, nil
}

func (f *fakeClusterRotation) ObserveReboot(_ context.Context, guard RotationGuardReference, operationID string) (RebootObservation, error) {
	*f.events = append(*f.events, "cluster.observe-reboot:"+string(f.rebootStatus))
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return RebootObservation{}, err
	}
	if f.rebootStatus == RebootNotStarted {
		return RebootObservation{Status: RebootNotStarted}, nil
	}
	intent := f.rebootIntent
	if f.canonicalReboot != nil {
		intent = *f.canonicalReboot
	} else {
		intent.ID = operationID
	}
	intent = cloneRebootIntent(intent)
	return RebootObservation{Status: f.rebootStatus, CanonicalIntent: &intent}, nil
}

func (f *fakeClusterRotation) RequestReboot(_ context.Context, guard RotationGuardReference, intent RebootIntent) (EffectOutcome, error) {
	*f.events = append(*f.events, "cluster.request-reboot")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return EffectNotApplied, err
	}
	f.rebootRequests++
	if f.canonicalReboot == nil {
		canonical := cloneRebootIntent(intent)
		f.canonicalReboot = &canonical
	}
	f.rebootStatus = RebootInProgress
	return EffectSubmitted, nil
}

func (f *fakeClusterRotation) WaitForReboot(_ context.Context, guard RotationGuardReference, _ RebootIntent) error {
	*f.events = append(*f.events, "cluster.wait-for-reboot")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return err
	}
	f.rebootStatus = RebootComplete
	return nil
}

func (f *fakeClusterRotation) WaitForPostRebootStable(_ context.Context, guard RotationGuardReference, _ RebootIntent) error {
	*f.events = append(*f.events, "cluster.wait-for-post-reboot-stable")
	if err := f.requireHeldRotationGuard(guard); err != nil {
		return err
	}
	return nil
}

func (f *fakeClusterRotation) requireHeldRotationGuard(guard RotationGuardReference) error {
	if f.guardReference == nil {
		return fmt.Errorf("operation does not hold a signer-rotation guard")
	}
	if *f.guardReference != guard {
		return fmt.Errorf("operation guard = %#v, want held guard %#v", guard, *f.guardReference)
	}
	return nil
}

func (f *fakeClusterRotation) reconciledPhases() []Phase {
	phases := make([]Phase, 0, len(f.expectations))
	for _, expectation := range f.expectations {
		phases = append(phases, expectation.Phase)
	}
	return phases
}

func cloneSignerReferenceForTest(reference *SignerObjectReference) *SignerObjectReference {
	if reference == nil {
		return nil
	}
	clone := *reference
	return &clone
}

func clonePublicSignerObservationForTest(observation PublicSignerObservation) PublicSignerObservation {
	observation.PublicKeyPEM = append([]byte(nil), observation.PublicKeyPEM...)
	return observation
}

func clonePublicSignerObservationsForTest(observations []PublicSignerObservation) []PublicSignerObservation {
	clones := make([]PublicSignerObservation, len(observations))
	for index, observation := range observations {
		clones[index] = clonePublicSignerObservationForTest(observation)
	}
	return clones
}

func clonePublicSignerBundleForTest(bundle PublicSignerBundleObservation) PublicSignerBundleObservation {
	bundle.Signers = clonePublicSignerObservationsForTest(bundle.Signers)
	return bundle
}

func cloneClusterExpectationForTest(expectation ClusterExpectation) ClusterExpectation {
	expectation.PreRotationSignerBaseline = clonePublicSignerBaseline(expectation.PreRotationSignerBaseline)
	if expectation.ReplacementSigner != nil {
		evidence := cloneReplacementSignerEvidence(*expectation.ReplacementSigner)
		expectation.ReplacementSigner = &evidence
	}
	if expectation.RebootIntent != nil {
		intent := cloneRebootIntent(*expectation.RebootIntent)
		expectation.RebootIntent = &intent
	}
	return expectation
}

package rotation

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

const stableSignerObservationAttempts = 3

type stableSignerState struct {
	Reference *SignerObjectReference
	Baseline  PublicSignerBaseline
	publicPEM map[string][]byte
}

type signerStateProgress int

const (
	signerStateOriginal signerStateProgress = iota
	signerStateReplacementRequested
	signerStateReplacementReady
)

type replacementSignerCandidate struct {
	Evidence  ReplacementSignerEvidence
	PublicPEM []byte
}

// observeStableSignerState makes the metadata-only Secret reference reads
// surrounding a public ConfigMap read visible to and enforceable by the shared
// engine. A result is accepted only when the same Secret object state bounded
// the complete public bundle observation.
func (o Orchestrator) observeStableSignerState(ctx context.Context, phase Phase, guard *RotationGuardReference) (stableSignerState, error) {
	for attempt := 0; attempt < stableSignerObservationAttempts; attempt++ {
		before, err := o.Cluster.ObserveSignerReference(ctx, guard)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("observe signer Secret metadata before public bundle: %w", err)
		}
		before, err = validatedSignerReference(before)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("validate signer Secret metadata before public bundle: %w", err)
		}

		bundle, err := o.Cluster.ObservePublicSignerBundle(ctx, guard)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("observe public signer bundle: %w", err)
		}
		state, err := normalizePublicSignerBundle(bundle)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("validate public signer bundle: %w", err)
		}

		after, err := o.Cluster.ObserveSignerReference(ctx, guard)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("observe signer Secret metadata after public bundle: %w", err)
		}
		after, err = validatedSignerReference(after)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("validate signer Secret metadata after public bundle: %w", err)
		}
		if reflect.DeepEqual(before, after) {
			state.Reference = after
			return state, nil
		}
	}
	return stableSignerState{}, &ConflictError{
		Phase:  phase,
		Reason: "the signer Secret changed while reading the public signer bundle",
	}
}

func validatedSignerReference(reference *SignerObjectReference) (*SignerObjectReference, error) {
	if reference == nil {
		return nil, nil
	}
	if err := validateSignerObjectReference(*reference); err != nil {
		return nil, err
	}
	clone := *reference
	return &clone, nil
}

func normalizePublicSignerBundle(observation PublicSignerBundleObservation) (stableSignerState, error) {
	baseline := PublicSignerBaseline{
		ConfigMapUID:             observation.ConfigMapUID,
		ConfigMapResourceVersion: observation.ConfigMapResourceVersion,
		Entries:                  make([]PublicSignerBaselineEntry, 0, len(observation.Signers)),
	}
	if err := validateOpaqueCheckpointValue("public signer ConfigMap UID", baseline.ConfigMapUID); err != nil {
		return stableSignerState{}, err
	}
	if err := validateOpaqueCheckpointValue("public signer ConfigMap resource version", baseline.ConfigMapResourceVersion); err != nil {
		return stableSignerState{}, err
	}
	if len(observation.Signers) == 0 {
		return stableSignerState{}, fmt.Errorf("public signer ConfigMap must contain at least one entry")
	}

	publicPEM := make(map[string][]byte, len(observation.Signers))
	for _, signer := range observation.Signers {
		if !publicSignerEntryNamePattern.MatchString(signer.Name) {
			return stableSignerState{}, fmt.Errorf("public signer entry name %q is not supported", signer.Name)
		}
		if _, exists := publicPEM[signer.Name]; exists {
			return stableSignerState{}, fmt.Errorf("public signer ConfigMap contains duplicate entry name %q", signer.Name)
		}
		keySet, err := jwkutil.NewSigner(signer.PublicKeyPEM)
		if err != nil {
			return stableSignerState{}, fmt.Errorf("parse public signer entry %q: %w", signer.Name, err)
		}
		publicPEM[signer.Name] = append([]byte(nil), signer.PublicKeyPEM...)
		baseline.Entries = append(baseline.Entries, PublicSignerBaselineEntry{
			Name:   signer.Name,
			SHA256: publicDigest(signer.PublicKeyPEM),
			KeyID:  keySet.Keys[0].KeyID,
		})
	}
	sort.Slice(baseline.Entries, func(i, j int) bool {
		return baseline.Entries[i].Name < baseline.Entries[j].Name
	})
	if err := validatePublicSignerBaseline(baseline); err != nil {
		return stableSignerState{}, err
	}
	return stableSignerState{Baseline: baseline, publicPEM: publicPEM}, nil
}

func classifySignerState(phase Phase, state stableSignerState, checkpoint Checkpoint) (signerStateProgress, *replacementSignerCandidate, error) {
	if checkpoint.PreRotationSignerBaseline == nil || checkpoint.PreRotationSignerRef == nil {
		return signerStateOriginal, nil, fmt.Errorf("checkpoint is missing pre-rotation signer evidence")
	}
	baseline := checkpoint.PreRotationSignerBaseline
	if state.Baseline.ConfigMapUID != baseline.ConfigMapUID {
		return signerStateOriginal, nil, signerStateConflict(phase, "the public signer ConfigMap UID changed")
	}

	observedByName := make(map[string]PublicSignerBaselineEntry, len(state.Baseline.Entries))
	for _, entry := range state.Baseline.Entries {
		observedByName[entry.Name] = entry
	}
	baselineByName := make(map[string]PublicSignerBaselineEntry, len(baseline.Entries))
	for _, entry := range baseline.Entries {
		baselineByName[entry.Name] = entry
		observed, exists := observedByName[entry.Name]
		if !exists {
			return signerStateOriginal, nil, signerStateConflict(phase, fmt.Sprintf("pre-rotation public signer entry %q disappeared", entry.Name))
		}
		if observed != entry {
			return signerStateOriginal, nil, signerStateConflict(phase, fmt.Sprintf("pre-rotation public signer entry %q changed", entry.Name))
		}
	}

	var appended *PublicSignerBaselineEntry
	for _, entry := range state.Baseline.Entries {
		if _, existed := baselineByName[entry.Name]; existed {
			continue
		}
		if appended != nil {
			return signerStateOriginal, nil, signerStateConflict(phase, "more than one public signer entry was appended after the pre-rotation snapshot")
		}
		entryCopy := entry
		appended = &entryCopy
	}
	if appended == nil {
		if state.Baseline.ConfigMapResourceVersion != baseline.ConfigMapResourceVersion {
			return signerStateOriginal, nil, signerStateConflict(phase, "the public signer ConfigMap resource version changed without one appended signer")
		}
	} else if state.Baseline.ConfigMapResourceVersion == baseline.ConfigMapResourceVersion {
		return signerStateOriginal, nil, signerStateConflict(phase, "the public signer ConfigMap changed without a new resource version")
	}

	oldReference := *checkpoint.PreRotationSignerRef
	switch {
	case state.Reference == nil:
		return signerStateReplacementRequested, nil, nil
	case state.Reference.UID == oldReference.UID:
		if *state.Reference != oldReference {
			return signerStateOriginal, nil, signerStateConflict(phase, "the pre-rotation signer Secret resource version changed without replacement")
		}
		if appended != nil {
			return signerStateOriginal, nil, signerStateConflict(phase, "a public signer was appended while the pre-rotation signer Secret remained current")
		}
		return signerStateOriginal, nil, nil
	case appended == nil:
		return signerStateReplacementRequested, nil, nil
	default:
		candidate := &replacementSignerCandidate{
			Evidence: ReplacementSignerEvidence{
				Entry:     *appended,
				SecretRef: *state.Reference,
			},
			PublicPEM: append([]byte(nil), state.publicPEM[appended.Name]...),
		}
		return signerStateReplacementReady, candidate, nil
	}
}

func validateRecordedSignerState(phase Phase, state stableSignerState, checkpoint Checkpoint) error {
	progress, candidate, err := classifySignerState(phase, state, checkpoint)
	if err != nil {
		return err
	}
	switch {
	case phase == PhasePreflightComplete:
		// A concurrent workspace may have requested the same replacement after
		// this workspace persisted its baseline but before it supplied a manual
		// current JWKS. The exact delta is still safe to adopt; artifact binding
		// is enforced before this workspace can request or publish anything.
		return nil
	case phase == PhaseCurrentJWKSRead:
		return nil
	case phaseAtLeast(phase, PhaseNextPublicKeyRead):
		if progress != signerStateReplacementReady || candidate == nil {
			return signerStateConflict(phase, "the recorded replacement signer is not observable")
		}
		if checkpoint.ReplacementSigner == nil {
			return fmt.Errorf("checkpoint is missing replacement signer evidence")
		}
		if candidate.Evidence != *checkpoint.ReplacementSigner {
			return signerStateConflict(phase, "the observable replacement signer does not match the recorded evidence")
		}
	case phaseAtLeast(phase, PhaseNextKeyRequested):
		if progress == signerStateOriginal {
			return signerStateConflict(phase, "the pre-rotation signer Secret reappeared after replacement was recorded")
		}
	}
	return nil
}

func (o Orchestrator) revalidateRecordedSignerEvidence(ctx context.Context, checkpoint Checkpoint) error {
	state, err := o.observeStableSignerState(ctx, checkpoint.Phase, checkpoint.RotationGuard)
	if err != nil {
		return fmt.Errorf("observe recorded replacement signer: %w", err)
	}
	if err := validateRecordedSignerState(checkpoint.Phase, state, checkpoint); err != nil {
		return err
	}
	return nil
}

func signerStateConflict(phase Phase, reason string) error {
	return &ConflictError{Phase: phase, Reason: reason}
}

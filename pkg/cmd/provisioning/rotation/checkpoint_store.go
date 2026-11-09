package rotation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

const (
	CheckpointFileName = "rotation-state.json"
	maxCheckpointSize  = 1 << 20
	maxArtifactSize    = 10 << 20
	checkpointFileMode = 0o600
	checkpointDirMode  = 0o700
)

var errCheckpointNotFound = errors.New("rotation checkpoint file not found")

// SaveCheckpoint validates and atomically persists a checkpoint. Existing
// checkpoints may stay at the same phase or advance by exactly one phase; they
// cannot regress, skip a phase, change identities, or rewrite prior evidence.
func SaveCheckpoint(checkpoint Checkpoint) error {
	if err := checkpoint.Validate(); err != nil {
		return fmt.Errorf("invalid rotation checkpoint: %w", err)
	}
	return WithRotationWorkspace(checkpoint.OutputDir, func(workspace *RotationWorkspace) error {
		return workspace.SaveCheckpoint(checkpoint)
	})
}

// SaveCheckpoint validates and persists a checkpoint while retaining the
// workspace lease held by the surrounding orchestration operation.
func (w *RotationWorkspace) SaveCheckpoint(checkpoint Checkpoint) error {
	return w.saveCheckpoint(checkpoint, false)
}

// saveCheckpointAdoptingCanonicalRebootIntent is reserved for replacing a
// same-ID local reboot proposal with the cluster-durable canonical intent while
// the checkpoint is still at PhaseRebootIntentRecorded.
func (w *RotationWorkspace) saveCheckpointAdoptingCanonicalRebootIntent(checkpoint Checkpoint) error {
	return w.saveCheckpoint(checkpoint, true)
}

func (w *RotationWorkspace) saveCheckpoint(checkpoint Checkpoint, allowCanonicalRebootIntentAdoption bool) error {
	if err := w.validateActive(); err != nil {
		return err
	}
	outputDir, err := resolveRotationOutputDir(checkpoint.OutputDir)
	if err != nil {
		return err
	}
	if outputDir != w.outputDir {
		return fmt.Errorf("rotation checkpoint output directory %q does not match locked workspace %q", outputDir, w.outputDir)
	}
	checkpoint.OutputDir = w.outputDir
	if err := checkpoint.Validate(); err != nil {
		return fmt.Errorf("invalid rotation checkpoint: %w", err)
	}
	if err := validateArtifactFiles(checkpoint); err != nil {
		return err
	}

	existing, err := w.LoadCheckpoint()
	switch {
	case err == nil:
		if err := validateCheckpointTransitionWithCanonicalRebootIntentAdoption(existing, checkpoint, allowCanonicalRebootIntentAdoption); err != nil {
			return err
		}
	case !errors.Is(err, errCheckpointNotFound):
		return fmt.Errorf("load existing rotation checkpoint: %w", err)
	case checkpoint.Phase != PhaseInitialized:
		return fmt.Errorf("first rotation checkpoint must use phase %q, got %q", PhaseInitialized, checkpoint.Phase)
	}

	payload, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rotation checkpoint: %w", err)
	}
	payload = append(payload, '\n')
	if len(payload) > maxCheckpointSize {
		return fmt.Errorf("encoded rotation checkpoint exceeds %d bytes", maxCheckpointSize)
	}

	if err := writeFileAtomically(checkpoint.OutputDir, CheckpointFileName, payload, checkpointFileMode); err != nil {
		return fmt.Errorf("persist rotation checkpoint: %w", err)
	}

	return nil
}

// LoadCheckpoint reads a checkpoint from outputDir, rejects unsafe file modes
// and unknown JSON fields, binds it to that directory, and validates its state.
func LoadCheckpoint(outputDir string) (Checkpoint, error) {
	resolvedOutputDir, err := resolveRotationOutputDir(outputDir)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := validateCheckpointDirectory(resolvedOutputDir); err != nil {
		return Checkpoint{}, err
	}
	return loadCheckpoint(resolvedOutputDir)
}

// LoadCheckpoint reads the state bound to an active workspace lease.
func (w *RotationWorkspace) LoadCheckpoint() (Checkpoint, error) {
	if err := w.validateActive(); err != nil {
		return Checkpoint{}, err
	}
	return loadCheckpoint(w.outputDir)
}

func loadCheckpoint(resolvedOutputDir string) (Checkpoint, error) {
	var checkpoint Checkpoint
	checkpointPath := filepath.Join(resolvedOutputDir, CheckpointFileName)

	info, err := os.Lstat(checkpointPath)
	if errors.Is(err, os.ErrNotExist) {
		return checkpoint, fmt.Errorf("%w: %q", errCheckpointNotFound, checkpointPath)
	}
	if err != nil {
		return checkpoint, fmt.Errorf("inspect rotation checkpoint %q: %w", checkpointPath, err)
	}
	if !info.Mode().IsRegular() {
		return checkpoint, fmt.Errorf("rotation checkpoint %q must be a regular file", checkpointPath)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return checkpoint, fmt.Errorf("rotation checkpoint %q permissions must not allow group or other access", checkpointPath)
	}

	file, err := os.Open(checkpointPath)
	if err != nil {
		return checkpoint, fmt.Errorf("open rotation checkpoint: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return checkpoint, fmt.Errorf("inspect opened rotation checkpoint: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return checkpoint, fmt.Errorf("rotation checkpoint %q changed while it was opened", checkpointPath)
	}

	payload, err := io.ReadAll(io.LimitReader(file, maxCheckpointSize+1))
	if err != nil {
		return checkpoint, fmt.Errorf("read rotation checkpoint: %w", err)
	}
	if len(payload) > maxCheckpointSize {
		return checkpoint, fmt.Errorf("rotation checkpoint exceeds %d bytes", maxCheckpointSize)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return checkpoint, fmt.Errorf("decode rotation checkpoint: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return checkpoint, fmt.Errorf("decode rotation checkpoint: unexpected trailing JSON value")
		}
		return checkpoint, fmt.Errorf("decode rotation checkpoint trailing data: %w", err)
	}

	checkpointOutputDir, err := filepath.Abs(checkpoint.OutputDir)
	if err != nil {
		return checkpoint, fmt.Errorf("resolve recorded rotation output directory: %w", err)
	}
	if filepath.Clean(checkpointOutputDir) != resolvedOutputDir {
		return checkpoint, fmt.Errorf("rotation checkpoint output directory %q does not match requested directory %q", checkpoint.OutputDir, resolvedOutputDir)
	}
	checkpoint.OutputDir = resolvedOutputDir

	if err := checkpoint.Validate(); err != nil {
		return checkpoint, fmt.Errorf("invalid rotation checkpoint: %w", err)
	}
	if err := validateArtifactFiles(checkpoint); err != nil {
		return checkpoint, err
	}

	return checkpoint, nil
}

func ensureCheckpointDirectory(outputDir string) error {
	info, err := os.Lstat(outputDir)
	if err == nil {
		return validateCheckpointDirectoryInfo(outputDir, info)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect rotation output directory: %w", err)
	}
	if err := createCheckpointDirectories(outputDir); err != nil {
		return err
	}
	return validateCheckpointDirectory(outputDir)
}

func createCheckpointDirectories(outputDir string) error {
	missing := []string{outputDir}
	parent := filepath.Dir(outputDir)
	for {
		info, err := os.Stat(parent)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("rotation output directory parent %q is not a directory", parent)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect rotation output directory parent %q: %w", parent, err)
		}
		missing = append(missing, parent)
		nextParent := filepath.Dir(parent)
		if nextParent == parent {
			return fmt.Errorf("find existing parent for rotation output directory %q", outputDir)
		}
		parent = nextParent
	}

	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		err := os.Mkdir(directory, checkpointDirMode)
		created := err == nil
		if err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create rotation output directory %q: %w", directory, err)
		}
		if created {
			if err := os.Chmod(directory, checkpointDirMode); err != nil {
				return fmt.Errorf("set rotation output directory %q permissions: %w", directory, err)
			}
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect created rotation output directory %q: %w", directory, err)
		}
		if err := validateCheckpointDirectoryInfo(directory, info); err != nil {
			return err
		}
		if created {
			if err := syncDirectory(filepath.Dir(directory)); err != nil {
				return fmt.Errorf("persist rotation output directory %q: %w", directory, err)
			}
		}
	}
	return nil
}

func validateCheckpointDirectory(outputDir string) error {
	info, err := os.Lstat(outputDir)
	if err != nil {
		return fmt.Errorf("inspect rotation output directory: %w", err)
	}
	return validateCheckpointDirectoryInfo(outputDir, info)
}

func validateCheckpointDirectoryInfo(outputDir string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("rotation output directory %q must be a directory and not a symbolic link", outputDir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("rotation output directory %q must not be writable by group or others", outputDir)
	}
	return nil
}

func validateCheckpointTransition(previous, next Checkpoint) error {
	return validateCheckpointTransitionWithCanonicalRebootIntentAdoption(previous, next, false)
}

func validateCheckpointTransitionWithCanonicalRebootIntentAdoption(previous, next Checkpoint, allowCanonicalRebootIntentAdoption bool) error {
	if previous.Provider != next.Provider {
		return fmt.Errorf("rotation checkpoint provider cannot change from %q to %q", previous.Provider, next.Provider)
	}
	if previous.PublicationMode != next.PublicationMode {
		return fmt.Errorf("rotation checkpoint publication mode cannot change from %q to %q", previous.PublicationMode, next.PublicationMode)
	}
	if previous.OutputDir != next.OutputDir {
		return fmt.Errorf("rotation checkpoint output directory cannot change")
	}
	if previous.ClusterIdentity != "" && previous.ClusterIdentity != next.ClusterIdentity {
		return fmt.Errorf("rotation checkpoint cluster identity cannot change")
	}
	if previous.TargetIdentity != "" && previous.TargetIdentity != next.TargetIdentity {
		return fmt.Errorf("rotation checkpoint target identity cannot change")
	}
	if previous.PreRotationSignerBaseline != nil && !reflect.DeepEqual(previous.PreRotationSignerBaseline, next.PreRotationSignerBaseline) {
		return fmt.Errorf("rotation checkpoint pre-rotation public signer baseline cannot change")
	}
	if previous.PreRotationSignerRef != nil && !reflect.DeepEqual(previous.PreRotationSignerRef, next.PreRotationSignerRef) {
		return fmt.Errorf("rotation checkpoint pre-rotation signer object reference cannot change")
	}
	if previous.RotationGuard != nil && !reflect.DeepEqual(previous.RotationGuard, next.RotationGuard) {
		return fmt.Errorf("rotation checkpoint signer-rotation guard reference cannot change")
	}
	if previous.ReplacementSigner != nil && !reflect.DeepEqual(previous.ReplacementSigner, next.ReplacementSigner) {
		return fmt.Errorf("rotation checkpoint replacement signer evidence cannot change")
	}
	if previous.RebootIntent != nil && !reflect.DeepEqual(previous.RebootIntent, next.RebootIntent) {
		canAdoptCanonicalIntent := allowCanonicalRebootIntentAdoption &&
			previous.Phase == PhaseRebootIntentRecorded && next.Phase == PhaseRebootIntentRecorded &&
			next.RebootIntent != nil && previous.RebootIntent.ID == next.RebootIntent.ID
		if !canAdoptCanonicalIntent {
			return fmt.Errorf("rotation checkpoint reboot intent cannot change")
		}
	}

	previousPosition := phasePosition(previous.Phase)
	nextPosition := phasePosition(next.Phase)
	if nextPosition < previousPosition {
		return fmt.Errorf("rotation checkpoint cannot regress from phase %q to %q", previous.Phase, next.Phase)
	}
	if nextPosition > previousPosition+1 {
		return fmt.Errorf("rotation checkpoint cannot skip from phase %q to %q", previous.Phase, next.Phase)
	}

	if err := validatePreservedArtifacts(previous.Artifacts, next.Artifacts); err != nil {
		return err
	}
	if err := validatePreservedPublications(previous.Publications, next.Publications); err != nil {
		return err
	}

	return nil
}

func validatePreservedArtifacts(previous, next []ArtifactMetadata) error {
	nextByName := make(map[string]ArtifactMetadata, len(next))
	for _, artifact := range next {
		nextByName[artifact.Name] = artifact
	}
	for _, artifact := range previous {
		nextArtifact, exists := nextByName[artifact.Name]
		if !exists {
			return fmt.Errorf("rotation checkpoint cannot remove recorded artifact %q", artifact.Name)
		}
		if !reflect.DeepEqual(artifact, nextArtifact) {
			return fmt.Errorf("rotation checkpoint cannot change recorded artifact %q", artifact.Name)
		}
	}
	return nil
}

func validatePreservedPublications(previous, next []PublicationConfirmation) error {
	nextByPhase := make(map[Phase]PublicationConfirmation, len(next))
	for _, publication := range next {
		nextByPhase[publication.Phase] = publication
	}
	for _, publication := range previous {
		nextPublication, exists := nextByPhase[publication.Phase]
		if !exists {
			return fmt.Errorf("rotation checkpoint cannot remove publication confirmation for phase %q", publication.Phase)
		}
		if publication != nextPublication {
			return fmt.Errorf("rotation checkpoint cannot change publication confirmation for phase %q", publication.Phase)
		}
	}
	return nil
}

func validateArtifactFiles(checkpoint Checkpoint) error {
	payloads := make(map[string][]byte, len(checkpoint.Artifacts))
	for _, artifact := range checkpoint.Artifacts {
		artifactPath := filepath.Join(checkpoint.OutputDir, artifact.Name)
		payload, err := readExistingArtifact(artifactPath, artifact.Name)
		if err != nil {
			return fmt.Errorf("validate recorded rotation artifact %q: %w", artifact.Name, err)
		}

		digest := sha256.Sum256(payload)
		if fmt.Sprintf("%x", digest) != artifact.SHA256 {
			return fmt.Errorf("rotation artifact %q does not match its recorded SHA-256 digest", artifact.Name)
		}

		var observedKeyIDs []string
		switch artifact.Name {
		case ArtifactReplacementPublicKey:
			keySet, err := jwkutil.NewSigner(payload)
			if err != nil {
				return fmt.Errorf("validate rotation artifact %q: %w", artifact.Name, err)
			}
			observedKeyIDs = []string{keySet.Keys[0].KeyID}
		case ArtifactCurrentJWKS, ArtifactNewJWKS, ArtifactCombinedJWKS:
			inspected, err := jwkutil.Inspect(payload)
			if err != nil {
				return fmt.Errorf("validate rotation artifact %q: %w", artifact.Name, err)
			}
			observedKeyIDs = inspected.KeyIDs
		}
		if !reflect.DeepEqual(observedKeyIDs, artifact.KeyIDs) {
			return fmt.Errorf("rotation artifact %q key IDs do not match its recorded metadata", artifact.Name)
		}
		payloads[artifact.Name] = payload
	}
	return validateArtifactRelationships(checkpoint, payloads)
}

func validateArtifactRelationships(checkpoint Checkpoint, payloads map[string][]byte) error {
	currentRaw, hasCurrent := payloads[ArtifactCurrentJWKS]
	replacementRaw, hasReplacement := payloads[ArtifactReplacementPublicKey]
	if hasCurrent && checkpoint.PreRotationSignerBaseline != nil {
		currentSet, err := jwkutil.Parse(currentRaw)
		if err != nil {
			return fmt.Errorf("validate current JWKS relationship: %w", err)
		}
		baselineKeyIDs := make(map[string]struct{}, len(checkpoint.PreRotationSignerBaseline.Entries))
		for _, entry := range checkpoint.PreRotationSignerBaseline.Entries {
			baselineKeyIDs[entry.KeyID] = struct{}{}
		}
		for _, key := range currentSet.Keys {
			if _, exists := baselineKeyIDs[key.KeyID]; !exists {
				return fmt.Errorf("current JWKS key %q is not present in the pre-rotation public signer baseline", key.KeyID)
			}
		}
	}
	if !hasReplacement {
		return nil
	}

	replacementSet, err := jwkutil.NewSigner(replacementRaw)
	if err != nil {
		return fmt.Errorf("validate replacement signer relationship: %w", err)
	}
	replacementKeyID := replacementSet.Keys[0].KeyID
	if checkpoint.PreRotationSignerBaseline != nil {
		for _, entry := range checkpoint.PreRotationSignerBaseline.Entries {
			if replacementKeyID == entry.KeyID {
				return fmt.Errorf("replacement signer key %q already exists in the pre-rotation public signer baseline", replacementKeyID)
			}
		}
	}
	if checkpoint.ReplacementSigner != nil {
		if replacementKeyID != checkpoint.ReplacementSigner.Entry.KeyID || publicDigest(replacementRaw) != checkpoint.ReplacementSigner.Entry.SHA256 {
			return fmt.Errorf("replacement signer artifact does not match the recorded replacement evidence")
		}
	}

	if hasCurrent {
		currentSet, err := jwkutil.Parse(currentRaw)
		if err != nil {
			return fmt.Errorf("validate current JWKS relationship: %w", err)
		}
		for _, key := range currentSet.Keys {
			if key.KeyID == replacementKeyID {
				return fmt.Errorf("replacement signer key %q is already present in the saved current JWKS", replacementKeyID)
			}
		}
	}

	if newRaw, exists := payloads[ArtifactNewJWKS]; exists {
		expectedNew, err := jwkutil.Encode(replacementSet)
		if err != nil {
			return fmt.Errorf("encode expected replacement JWKS: %w", err)
		}
		if !bytes.Equal(newRaw, expectedNew.Data) {
			return fmt.Errorf("rotation artifact %q does not exactly represent %q", ArtifactNewJWKS, ArtifactReplacementPublicKey)
		}
	}

	if combinedRaw, exists := payloads[ArtifactCombinedJWKS]; exists {
		if !hasCurrent {
			return fmt.Errorf("rotation artifact %q requires %q", ArtifactCombinedJWKS, ArtifactCurrentJWKS)
		}
		currentSet, err := jwkutil.Parse(currentRaw)
		if err != nil {
			return fmt.Errorf("validate current JWKS relationship: %w", err)
		}
		expectedCombinedSet, err := jwkutil.Merge(currentSet, replacementSet)
		if err != nil {
			return fmt.Errorf("build expected combined JWKS: %w", err)
		}
		expectedCombined, err := jwkutil.Encode(expectedCombinedSet)
		if err != nil {
			return fmt.Errorf("encode expected combined JWKS: %w", err)
		}
		if !bytes.Equal(combinedRaw, expectedCombined.Data) {
			return fmt.Errorf("rotation artifact %q is not the ordered union of %q and %q", ArtifactCombinedJWKS, ArtifactCurrentJWKS, ArtifactReplacementPublicKey)
		}
	}

	return nil
}

func writeFileAtomically(outputDir, name string, payload []byte, mode os.FileMode) (returnErr error) {
	temporary, err := os.CreateTemp(outputDir, "."+name+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary rotation file for %q: %w", name, err)
	}
	temporaryPath := temporary.Name()
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			if closeErr := temporary.Close(); returnErr == nil && closeErr != nil {
				returnErr = fmt.Errorf("close temporary rotation file for %q: %w", name, closeErr)
			}
		}
		if removeErr := os.Remove(temporaryPath); returnErr == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			returnErr = fmt.Errorf("remove temporary rotation file for %q: %w", name, removeErr)
		}
	}()

	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary rotation file permissions for %q: %w", name, err)
	}
	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write temporary rotation file for %q: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary rotation file for %q: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary rotation file for %q: %w", name, err)
	}
	temporaryClosed = true

	checkpointPath := filepath.Join(outputDir, name)
	if err := os.Rename(temporaryPath, checkpointPath); err != nil {
		return fmt.Errorf("replace rotation file %q: %w", name, err)
	}

	return syncDirectory(outputDir)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory %q for sync: %w", path, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory %q: %w", path, err)
	}

	return nil
}

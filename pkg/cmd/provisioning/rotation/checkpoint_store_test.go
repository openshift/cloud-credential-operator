package rotation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

func TestCheckpointStoreRoundTrip(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("SaveCheckpoint() returned unexpected error: %v", err)
	}

	directoryInfo, err := os.Stat(outputDir)
	if err != nil {
		t.Fatalf("stat output directory: %v", err)
	}
	if got := directoryInfo.Mode().Perm(); got != checkpointDirMode {
		t.Fatalf("output directory mode = %o, want %o", got, checkpointDirMode)
	}

	checkpointPath := filepath.Join(outputDir, CheckpointFileName)
	checkpointInfo, err := os.Stat(checkpointPath)
	if err != nil {
		t.Fatalf("stat checkpoint: %v", err)
	}
	if got := checkpointInfo.Mode().Perm(); got != checkpointFileMode {
		t.Fatalf("checkpoint mode = %o, want %o", got, checkpointFileMode)
	}

	loaded, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("LoadCheckpoint() returned unexpected error: %v", err)
	}
	if !filepath.IsAbs(loaded.OutputDir) {
		t.Fatalf("loaded output directory %q is not absolute", loaded.OutputDir)
	}
	if loaded.Phase != PhaseInitialized {
		t.Fatalf("loaded phase = %q, want %q", loaded.Phase, PhaseInitialized)
	}

	loaded.Phase = PhasePreflightComplete
	loaded.ClusterIdentity = "cluster-123"
	loaded.TargetIdentity = "aws://issuer"
	loaded.PreRotationSignerBaseline = testSignerBaseline()
	loaded.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&loaded)
	if err := SaveCheckpoint(loaded); err != nil {
		t.Fatalf("SaveCheckpoint(preflight) returned unexpected error: %v", err)
	}

	loaded, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("LoadCheckpoint(preflight) returned unexpected error: %v", err)
	}
	if loaded.Phase != PhasePreflightComplete || loaded.ClusterIdentity != "cluster-123" || loaded.TargetIdentity != "aws://issuer" || !reflect.DeepEqual(loaded.PreRotationSignerBaseline, testSignerBaseline()) || !reflect.DeepEqual(loaded.PreRotationSignerRef, testSignerObjectReference()) {
		t.Fatalf("loaded preflight checkpoint did not preserve identities: %#v", loaded)
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("read output directory: %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != checkpointLockFileName || entries[1].Name() != CheckpointFileName {
		t.Fatalf("output directory contains unexpected files after checkpoint saves: %v", entries)
	}
	lockInfo, err := os.Stat(filepath.Join(outputDir, checkpointLockFileName))
	if err != nil {
		t.Fatalf("stat checkpoint lock: %v", err)
	}
	if got := lockInfo.Mode().Perm(); got != checkpointFileMode {
		t.Fatalf("checkpoint lock mode = %o, want %o", got, checkpointFileMode)
	}
}

func TestCheckpointStoreCreatesNestedDirectories(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	outputDir := filepath.Join(first, "second")
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("SaveCheckpoint() returned unexpected error: %v", err)
	}

	for _, directory := range []string{first, outputDir} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatalf("stat created directory %q: %v", directory, err)
		}
		if got := info.Mode().Perm(); got != checkpointDirMode {
			t.Fatalf("created directory %q mode = %o, want %o", directory, got, checkpointDirMode)
		}
	}
}

func TestSaveCheckpointRejectsOversizedUpdateAndPreservesReadableState(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}

	checkpointPath := filepath.Join(outputDir, CheckpointFileName)
	originalCheckpoint, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read original checkpoint: %v", err)
	}
	checkpoint.LastErrorCode = strings.Repeat("x", maxCheckpointSize)
	if err := SaveCheckpoint(checkpoint); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("SaveCheckpoint(oversized) error = %v", err)
	}

	preservedCheckpoint, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read preserved checkpoint: %v", err)
	}
	if string(preservedCheckpoint) != string(originalCheckpoint) {
		t.Fatal("checkpoint changed after oversized update")
	}
	if _, err := LoadCheckpoint(outputDir); err != nil {
		t.Fatalf("LoadCheckpoint() after oversized update returned unexpected error: %v", err)
	}
}

func TestSaveCheckpointRejectsUnsafeTransitions(t *testing.T) {
	t.Run("first checkpoint skips initialized", func(t *testing.T) {
		checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, filepath.Join(t.TempDir(), "output"))
		checkpoint.Phase = PhasePreflightComplete
		checkpoint.ClusterIdentity = "cluster-123"
		checkpoint.TargetIdentity = "aws://issuer"
		checkpoint.PreRotationSignerBaseline = testSignerBaseline()
		checkpoint.PreRotationSignerRef = testSignerObjectReference()
		setTestRotationGuard(&checkpoint)
		err := SaveCheckpoint(checkpoint)
		if err == nil || !strings.Contains(err.Error(), "first rotation checkpoint") {
			t.Fatalf("SaveCheckpoint() error = %v, want first-checkpoint error", err)
		}
	})

	t.Run("regression and identity change", func(t *testing.T) {
		outputDir := filepath.Join(t.TempDir(), "output")
		checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
		if err := SaveCheckpoint(checkpoint); err != nil {
			t.Fatalf("save initialized checkpoint: %v", err)
		}

		checkpoint, err := LoadCheckpoint(outputDir)
		if err != nil {
			t.Fatalf("load initialized checkpoint: %v", err)
		}
		checkpoint.Phase = PhasePreflightComplete
		checkpoint.ClusterIdentity = "cluster-123"
		checkpoint.TargetIdentity = "aws://issuer"
		checkpoint.PreRotationSignerBaseline = testSignerBaseline()
		checkpoint.PreRotationSignerRef = testSignerObjectReference()
		setTestRotationGuard(&checkpoint)
		if err := SaveCheckpoint(checkpoint); err != nil {
			t.Fatalf("save preflight checkpoint: %v", err)
		}

		changedIdentity := checkpoint
		changedIdentity.ClusterIdentity = "other-cluster"
		setTestRotationGuard(&changedIdentity)
		err = SaveCheckpoint(changedIdentity)
		if err == nil || !strings.Contains(err.Error(), "cluster identity cannot change") {
			t.Fatalf("SaveCheckpoint(changed identity) error = %v", err)
		}

		changedBaseline := cloneCheckpoint(checkpoint)
		changedBaseline.PreRotationSignerBaseline.Entries[0].KeyID = testOtherKeyID
		setTestRotationGuard(&changedBaseline)
		err = SaveCheckpoint(changedBaseline)
		if err == nil || !strings.Contains(err.Error(), "public signer baseline cannot change") {
			t.Fatalf("SaveCheckpoint(changed signer baseline) error = %v", err)
		}

		changedSignerRef := checkpoint
		changedSignerRef.PreRotationSignerRef = &SignerObjectReference{
			UID:             "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			ResourceVersion: "54321",
		}
		setTestRotationGuard(&changedSignerRef)
		err = SaveCheckpoint(changedSignerRef)
		if err == nil || !strings.Contains(err.Error(), "signer object reference cannot change") {
			t.Fatalf("SaveCheckpoint(changed signer reference) error = %v", err)
		}

		changedGuard := cloneCheckpoint(checkpoint)
		changedGuard.RotationGuard.OperationID = strings.Repeat("f", 64)
		err = validateCheckpointTransition(checkpoint, changedGuard)
		if err == nil || !strings.Contains(err.Error(), "guard reference cannot change") {
			t.Fatalf("validateCheckpointTransition(changed guard) error = %v", err)
		}

		regressed := checkpoint
		regressed.Phase = PhaseInitialized
		err = validateCheckpointTransition(checkpoint, regressed)
		if err == nil || !strings.Contains(err.Error(), "cannot regress") {
			t.Fatalf("validateCheckpointTransition(regression) error = %v", err)
		}
	})

	t.Run("phase skip", func(t *testing.T) {
		outputDir := filepath.Join(t.TempDir(), "output")
		checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
		if err := SaveCheckpoint(checkpoint); err != nil {
			t.Fatalf("save initialized checkpoint: %v", err)
		}

		currentData, currentMetadata := currentJWKSForTest(t)
		if err := os.WriteFile(filepath.Join(outputDir, ArtifactCurrentJWKS), currentData, 0o644); err != nil {
			t.Fatalf("write current JWKS: %v", err)
		}
		checkpoint.OutputDir = outputDir
		checkpoint.Phase = PhaseCurrentJWKSRead
		checkpoint.ClusterIdentity = "cluster-123"
		checkpoint.TargetIdentity = "aws://issuer"
		checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(currentMetadata.KeyIDs[0])
		checkpoint.PreRotationSignerRef = testSignerObjectReference()
		setTestRotationGuard(&checkpoint)
		checkpoint.Artifacts = []ArtifactMetadata{currentMetadata}
		err := SaveCheckpoint(checkpoint)
		if err == nil || !strings.Contains(err.Error(), "cannot skip") {
			t.Fatalf("SaveCheckpoint(skip) error = %v", err)
		}
	})
}

func TestLoadCheckpointRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name      string
		payload   func(string) []byte
		mode      os.FileMode
		wantError string
	}{
		{
			name: "unknown field",
			payload: func(outputDir string) []byte {
				return []byte(fmt.Sprintf(`{"schemaVersion":1,"provider":"aws","publicationMode":"direct","phase":"initialized","outputDir":%q,"unexpected":true}`, outputDir))
			},
			mode:      0o600,
			wantError: "unknown field",
		},
		{
			name: "trailing JSON",
			payload: func(outputDir string) []byte {
				return []byte(fmt.Sprintf(`{"schemaVersion":1,"provider":"aws","publicationMode":"direct","phase":"initialized","outputDir":%q} {}`, outputDir))
			},
			mode:      0o600,
			wantError: "trailing JSON value",
		},
		{
			name: "malformed JSON",
			payload: func(string) []byte {
				return []byte(`{"schemaVersion":`)
			},
			mode:      0o600,
			wantError: "decode rotation checkpoint",
		},
		{
			name: "oversized checkpoint",
			payload: func(string) []byte {
				return []byte(strings.Repeat(" ", maxCheckpointSize+1))
			},
			mode:      0o600,
			wantError: "exceeds",
		},
		{
			name: "insecure permissions",
			payload: func(outputDir string) []byte {
				checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
				payload, err := json.Marshal(checkpoint)
				if err != nil {
					t.Fatalf("marshal checkpoint: %v", err)
				}
				return payload
			},
			mode:      0o644,
			wantError: "permissions",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputDir := t.TempDir()
			checkpointPath := filepath.Join(outputDir, CheckpointFileName)
			if err := os.WriteFile(checkpointPath, test.payload(outputDir), test.mode); err != nil {
				t.Fatalf("write checkpoint fixture: %v", err)
			}
			if err := os.Chmod(checkpointPath, test.mode); err != nil {
				t.Fatalf("chmod checkpoint fixture: %v", err)
			}

			_, err := LoadCheckpoint(outputDir)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("LoadCheckpoint() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		outputDir := t.TempDir()
		target := filepath.Join(outputDir, "target.json")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("write symlink target: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(outputDir, CheckpointFileName)); err != nil {
			t.Fatalf("create checkpoint symlink: %v", err)
		}
		_, err := LoadCheckpoint(outputDir)
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("LoadCheckpoint(symlink) error = %v", err)
		}
	})

	t.Run("group-writable output directory", func(t *testing.T) {
		outputDir := t.TempDir()
		checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
		payload, err := json.Marshal(checkpoint)
		if err != nil {
			t.Fatalf("marshal checkpoint: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, CheckpointFileName), payload, checkpointFileMode); err != nil {
			t.Fatalf("write checkpoint fixture: %v", err)
		}
		if err := os.Chmod(outputDir, 0o770); err != nil {
			t.Fatalf("make output directory group-writable: %v", err)
		}

		_, err = LoadCheckpoint(outputDir)
		if err == nil || !strings.Contains(err.Error(), "must not be writable") {
			t.Fatalf("LoadCheckpoint(writable output directory) error = %v", err)
		}
	})
}

func TestLoadCheckpointRejectsArtifactTampering(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "output")
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}

	checkpoint, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load initialized checkpoint: %v", err)
	}
	currentData, currentMetadata := currentJWKSForTest(t)
	checkpoint.Phase = PhasePreflightComplete
	checkpoint.ClusterIdentity = "cluster-123"
	checkpoint.TargetIdentity = "aws://issuer"
	checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(currentMetadata.KeyIDs[0])
	checkpoint.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&checkpoint)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save preflight checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseGuardAcquired
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save guard-acquired checkpoint: %v", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, ArtifactCurrentJWKS), currentData, 0o644); err != nil {
		t.Fatalf("write current JWKS: %v", err)
	}
	checkpoint.Phase = PhaseCurrentJWKSRead
	checkpoint.Artifacts = []ArtifactMetadata{currentMetadata}
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save current-JWKS checkpoint: %v", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, ArtifactCurrentJWKS), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper with current JWKS: %v", err)
	}
	_, err = LoadCheckpoint(outputDir)
	if err == nil || !strings.Contains(err.Error(), "does not match its recorded") {
		t.Fatalf("LoadCheckpoint(tampered artifact) error = %v", err)
	}
}

func TestSaveCheckpointDoesNotResetStateWhenRecordedArtifactIsMissing(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "output")
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}

	checkpoint, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load initialized checkpoint: %v", err)
	}
	currentData, currentMetadata := currentJWKSForTest(t)
	checkpoint.Phase = PhasePreflightComplete
	checkpoint.ClusterIdentity = "cluster-123"
	checkpoint.TargetIdentity = "aws://issuer"
	checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(currentMetadata.KeyIDs[0])
	checkpoint.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&checkpoint)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save preflight checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseGuardAcquired
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save guard-acquired checkpoint: %v", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, ArtifactCurrentJWKS), currentData, artifactFileMode); err != nil {
		t.Fatalf("write current JWKS: %v", err)
	}
	checkpoint.Phase = PhaseCurrentJWKSRead
	checkpoint.Artifacts = []ArtifactMetadata{currentMetadata}
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save current-JWKS checkpoint: %v", err)
	}

	checkpointPath := filepath.Join(outputDir, CheckpointFileName)
	originalCheckpoint, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read original checkpoint: %v", err)
	}
	if err := os.Remove(filepath.Join(outputDir, ArtifactCurrentJWKS)); err != nil {
		t.Fatalf("remove recorded current JWKS: %v", err)
	}

	reset := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	err = SaveCheckpoint(reset)
	if err == nil || !strings.Contains(err.Error(), "validate recorded rotation artifact") {
		t.Fatalf("SaveCheckpoint(reset with missing artifact) error = %v", err)
	}
	preservedCheckpoint, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read preserved checkpoint: %v", err)
	}
	if string(preservedCheckpoint) != string(originalCheckpoint) {
		t.Fatal("checkpoint changed after recorded artifact was lost")
	}
}

func TestValidateArtifactRelationships(t *testing.T) {
	currentPEM := testPublicKeyPEM(t)
	replacementPEM := testPublicKeyPEM(t)
	unrelatedPEM := testPublicKeyPEM(t)
	currentRaw := encodedJWKSForTest(t, currentPEM)
	valid, err := PrepareJWKSArtifacts(currentRaw, replacementPEM)
	if err != nil {
		t.Fatalf("prepare valid artifact bundle: %v", err)
	}
	unrelatedNew := encodedJWKSForTest(t, unrelatedPEM)
	unrelatedBundle, err := PrepareJWKSArtifacts(currentRaw, unrelatedPEM)
	if err != nil {
		t.Fatalf("prepare unrelated artifact bundle: %v", err)
	}
	replacementSet, err := jwkutil.NewSigner(replacementPEM)
	if err != nil {
		t.Fatalf("derive replacement key ID: %v", err)
	}
	replacementKeyID := replacementSet.Keys[0].KeyID

	validPayloads := map[string][]byte{
		ArtifactCurrentJWKS:          valid.Current.Data,
		ArtifactReplacementPublicKey: replacementPEM,
		ArtifactNewJWKS:              valid.New.Data,
		ArtifactCombinedJWKS:         valid.Combined.Data,
	}

	tests := []struct {
		name           string
		baselineKeyIDs []string
		payloads       map[string][]byte
		wantError      string
	}{
		{name: "valid bundle", payloads: validPayloads},
		{
			name: "replacement without generated artifacts",
			payloads: map[string][]byte{
				ArtifactCurrentJWKS:          valid.Current.Data,
				ArtifactReplacementPublicKey: replacementPEM,
			},
		},
		{
			name: "replacement already in current",
			baselineKeyIDs: []string{
				valid.Current.KeyIDs[0],
				replacementKeyID,
			},
			payloads: map[string][]byte{
				ArtifactCurrentJWKS:          valid.Combined.Data,
				ArtifactReplacementPublicKey: replacementPEM,
			},
			wantError: "already exists",
		},
		{
			name:           "replacement did not change",
			baselineKeyIDs: []string{replacementKeyID},
			payloads: map[string][]byte{
				ArtifactCurrentJWKS:          valid.New.Data,
				ArtifactReplacementPublicKey: replacementPEM,
			},
			wantError: "pre-rotation public signer baseline",
		},
		{
			name: "new JWKS uses unrelated key",
			payloads: map[string][]byte{
				ArtifactCurrentJWKS:          valid.Current.Data,
				ArtifactReplacementPublicKey: replacementPEM,
				ArtifactNewJWKS:              unrelatedNew,
			},
			wantError: "does not exactly represent",
		},
		{
			name: "new JWKS is not canonical",
			payloads: map[string][]byte{
				ArtifactCurrentJWKS:          valid.Current.Data,
				ArtifactReplacementPublicKey: replacementPEM,
				ArtifactNewJWKS:              append([]byte(" \n"), valid.New.Data...),
			},
			wantError: "does not exactly represent",
		},
		{
			name: "combined JWKS uses unrelated replacement",
			payloads: map[string][]byte{
				ArtifactCurrentJWKS:          valid.Current.Data,
				ArtifactReplacementPublicKey: replacementPEM,
				ArtifactNewJWKS:              valid.New.Data,
				ArtifactCombinedJWKS:         unrelatedBundle.Combined.Data,
			},
			wantError: "is not the ordered union",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baselineKeyIDs := test.baselineKeyIDs
			if len(baselineKeyIDs) == 0 {
				baselineKeyIDs = []string{valid.Current.KeyIDs[0]}
			}
			checkpoint := Checkpoint{PreRotationSignerBaseline: testSignerBaselineForKeyIDs(baselineKeyIDs...)}
			err := validateArtifactRelationships(checkpoint, test.payloads)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateArtifactRelationships() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateArtifactRelationships() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateCheckpointTransitionPreservesEvidence(t *testing.T) {
	previous := completeTestCheckpoint()

	tests := []struct {
		name      string
		mutate    func(*Checkpoint)
		wantError string
	}{
		{
			name: "artifact removed",
			mutate: func(next *Checkpoint) {
				next.Artifacts = next.Artifacts[1:]
			},
			wantError: "cannot remove recorded artifact",
		},
		{
			name: "artifact metadata changed",
			mutate: func(next *Checkpoint) {
				next.Artifacts[0].KeyIDs = []string{"changed"}
			},
			wantError: "cannot change recorded artifact",
		},
		{
			name: "publication removed",
			mutate: func(next *Checkpoint) {
				next.Publications = next.Publications[1:]
			},
			wantError: "cannot remove publication confirmation",
		},
		{
			name: "publication changed",
			mutate: func(next *Checkpoint) {
				next.Publications[0].SHA256 = strings.Repeat("b", 64)
			},
			wantError: "cannot change publication confirmation",
		},
		{
			name: "pre-rotation signer baseline changed",
			mutate: func(next *Checkpoint) {
				next.PreRotationSignerBaseline.Entries[0].SHA256 = strings.Repeat("c", 64)
			},
			wantError: "public signer baseline cannot change",
		},
		{
			name: "pre-rotation signer reference changed",
			mutate: func(next *Checkpoint) {
				next.PreRotationSignerRef.ResourceVersion = "54321"
			},
			wantError: "signer object reference cannot change",
		},
		{
			name: "replacement signer evidence changed",
			mutate: func(next *Checkpoint) {
				next.ReplacementSigner.SecretRef.ResourceVersion = "54321"
			},
			wantError: "replacement signer evidence cannot change",
		},
		{
			name: "reboot intent removed",
			mutate: func(next *Checkpoint) {
				next.RebootIntent = nil
			},
			wantError: "reboot intent cannot change",
		},
		{
			name: "reboot intent baseline changed",
			mutate: func(next *Checkpoint) {
				next.RebootIntent.Baselines[0].BootID = "changed-boot-id"
			},
			wantError: "reboot intent cannot change",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := cloneCheckpoint(previous)
			test.mutate(&next)
			err := validateCheckpointTransition(previous, next)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateCheckpointTransition() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateCheckpointTransitionRequiresDurableRebootIntentPhase(t *testing.T) {
	stable := completeTestCheckpoint()
	stable.Phase = PhaseSignerRolloutStable
	stable.Publications = stable.Publications[:1]
	stable.RebootIntent = nil
	if err := stable.Validate(); err != nil {
		t.Fatalf("signer-rollout fixture is invalid: %v", err)
	}

	intentRecorded := stable
	intentRecorded.Phase = PhaseRebootIntentRecorded
	intentRecorded.RebootIntent = testNodeRebootIntent()
	if err := intentRecorded.Validate(); err != nil {
		t.Fatalf("reboot-intent fixture is invalid: %v", err)
	}
	if err := validateCheckpointTransition(stable, intentRecorded); err != nil {
		t.Fatalf("signer rollout to reboot intent transition failed: %v", err)
	}

	nodesRebooted := intentRecorded
	nodesRebooted.Phase = PhaseNodesRebooted
	if err := nodesRebooted.Validate(); err != nil {
		t.Fatalf("nodes-rebooted fixture is invalid: %v", err)
	}
	if err := validateCheckpointTransition(stable, nodesRebooted); err == nil || !strings.Contains(err.Error(), "cannot skip") {
		t.Fatalf("direct signer rollout to nodes rebooted transition error = %v, want phase-skip error", err)
	}
}

func TestValidateCheckpointTransitionAllowsOnlyExplicitCanonicalRebootAdoption(t *testing.T) {
	previous := completeTestCheckpoint()
	previous.Phase = PhaseRebootIntentRecorded
	previous.Publications = previous.Publications[:1]

	next := previous
	next.Artifacts = append([]ArtifactMetadata(nil), previous.Artifacts...)
	next.Publications = append([]PublicationConfirmation(nil), previous.Publications...)
	signerReference := *previous.PreRotationSignerRef
	next.PreRotationSignerRef = &signerReference
	canonical := cloneRebootIntent(*previous.RebootIntent)
	canonical.Targets = []string{"worker"}
	canonical.Baselines = []NodeRebootBaseline{{Target: "worker", Node: "worker-0", BootID: "cluster-canonical-boot-id"}}
	next.RebootIntent = &canonical

	if err := validateCheckpointTransition(previous, next); err == nil || !strings.Contains(err.Error(), "reboot intent cannot change") {
		t.Fatalf("ordinary transition error = %v, want immutable reboot intent rejection", err)
	}
	if err := validateCheckpointTransitionWithCanonicalRebootIntentAdoption(previous, next, true); err != nil {
		t.Fatalf("explicit canonical reboot adoption failed: %v", err)
	}

	differentID := next
	differentIntent := cloneRebootIntent(*next.RebootIntent)
	differentIntent.ID = "different-operation"
	differentID.RebootIntent = &differentIntent
	if err := validateCheckpointTransitionWithCanonicalRebootIntentAdoption(previous, differentID, true); err == nil || !strings.Contains(err.Error(), "reboot intent cannot change") {
		t.Fatalf("different-ID adoption error = %v, want rejection", err)
	}

	afterAdvance := next
	afterAdvance.Phase = PhaseNodesRebooted
	if err := validateCheckpointTransitionWithCanonicalRebootIntentAdoption(previous, afterAdvance, true); err == nil || !strings.Contains(err.Error(), "reboot intent cannot change") {
		t.Fatalf("post-advance adoption error = %v, want rejection", err)
	}
}

func currentJWKSForTest(t *testing.T) ([]byte, ArtifactMetadata) {
	t.Helper()
	artifactData := encodedJWKSForTest(t, testPublicKeyPEM(t))
	artifact, err := jwkutil.Inspect(artifactData)
	if err != nil {
		t.Fatalf("inspect current JWKS: %v", err)
	}
	return artifact.Data, ArtifactMetadata{
		Name:   ArtifactCurrentJWKS,
		SHA256: artifact.SHA256,
		KeyIDs: artifact.KeyIDs,
	}
}

func encodedJWKSForTest(t *testing.T, publicPEM []byte) []byte {
	t.Helper()
	keySet, err := jwkutil.NewSigner(publicPEM)
	if err != nil {
		t.Fatalf("create current JWKS: %v", err)
	}
	artifact, err := jwkutil.Encode(keySet)
	if err != nil {
		t.Fatalf("encode current JWKS: %v", err)
	}
	return artifact.Data
}

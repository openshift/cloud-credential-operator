package rotation

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithRotationWorkspaceHoldsLockAcrossCheckpointOperations(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	var retained *RotationWorkspace
	err := WithRotationWorkspace(outputDir, func(workspace *RotationWorkspace) error {
		retained = workspace
		resolved, err := workspace.OutputDir()
		if err != nil {
			return err
		}
		if !filepath.IsAbs(resolved) {
			t.Fatalf("workspace output directory %q is not absolute", resolved)
		}

		checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
		if err := workspace.SaveCheckpoint(checkpoint); err != nil {
			t.Fatalf("workspace SaveCheckpoint() returned unexpected error: %v", err)
		}
		loaded, err := workspace.LoadCheckpoint()
		if err != nil {
			t.Fatalf("workspace LoadCheckpoint() returned unexpected error: %v", err)
		}
		if loaded.Phase != PhaseInitialized {
			t.Fatalf("loaded phase = %q, want %q", loaded.Phase, PhaseInitialized)
		}
		currentRaw := encodedJWKSForTest(t, testPublicKeyPEM(t))
		currentMetadata, err := workspace.WriteArtifact(ArtifactCurrentJWKS, currentRaw)
		if err != nil {
			t.Fatalf("workspace WriteArtifact() returned unexpected error: %v", err)
		}
		loaded.Phase = PhasePreflightComplete
		loaded.ClusterIdentity = "cluster-123"
		loaded.TargetIdentity = "aws://issuer"
		loaded.PreRotationSignerBaseline = testSignerBaselineForKeyID(currentMetadata.KeyIDs[0])
		loaded.PreRotationSignerRef = testSignerObjectReference()
		setTestRotationGuard(&loaded)
		if err := workspace.SaveCheckpoint(loaded); err != nil {
			t.Fatalf("workspace SaveCheckpoint(preflight) returned unexpected error: %v", err)
		}
		loaded.Phase = PhaseGuardAcquired
		if err := workspace.SaveCheckpoint(loaded); err != nil {
			t.Fatalf("workspace SaveCheckpoint(guard acquired) returned unexpected error: %v", err)
		}
		loaded.Phase = PhaseCurrentJWKSRead
		loaded.Artifacts = []ArtifactMetadata{currentMetadata}
		if err := workspace.SaveCheckpoint(loaded); err != nil {
			t.Fatalf("workspace SaveCheckpoint(current JWKS) returned unexpected error: %v", err)
		}

		err = SaveCheckpoint(checkpoint)
		if err == nil || !errors.Is(err, ErrCheckpointLocked) {
			t.Fatalf("nested top-level SaveCheckpoint() error = %v, want ErrCheckpointLocked", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithRotationWorkspace() returned unexpected error: %v", err)
	}

	if _, err := retained.LoadCheckpoint(); err == nil || !strings.Contains(err.Error(), "lease is not active") {
		t.Fatalf("retained workspace LoadCheckpoint() error = %v, want inactive-lease error", err)
	}
	if _, err := LoadCheckpoint(outputDir); err != nil {
		t.Fatalf("top-level LoadCheckpoint() after lease returned unexpected error: %v", err)
	}
}

func TestRotationWorkspaceRejectsMismatchedCheckpointDirectory(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	err := WithRotationWorkspace(outputDir, func(workspace *RotationWorkspace) error {
		checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, filepath.Join(t.TempDir(), "other-output"))
		return workspace.SaveCheckpoint(checkpoint)
	})
	if err == nil || !strings.Contains(err.Error(), "does not match locked workspace") {
		t.Fatalf("WithRotationWorkspace(mismatched checkpoint) error = %v", err)
	}
}

func TestWithRotationWorkspaceRejectsNilOperation(t *testing.T) {
	err := WithRotationWorkspace(filepath.Join(t.TempDir(), "rotation-output"), nil)
	if err == nil || !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("WithRotationWorkspace(nil) error = %v", err)
	}
}

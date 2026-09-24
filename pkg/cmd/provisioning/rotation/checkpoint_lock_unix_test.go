//go:build linux || darwin

package rotation

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveCheckpointRejectsConcurrentWriter(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	if err := ensureCheckpointDirectory(outputDir); err != nil {
		t.Fatalf("create checkpoint directory: %v", err)
	}
	lockFile, err := acquireCheckpointLock(outputDir)
	if err != nil {
		t.Fatalf("acquire first checkpoint lock: %v", err)
	}

	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	err = SaveCheckpoint(checkpoint)
	if err == nil || !errors.Is(err, ErrCheckpointLocked) {
		_ = releaseCheckpointLock(lockFile)
		t.Fatalf("SaveCheckpoint() error = %v, want ErrCheckpointLocked", err)
	}
	if err := releaseCheckpointLock(lockFile); err != nil {
		t.Fatalf("release first checkpoint lock: %v", err)
	}

	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("SaveCheckpoint() after release returned unexpected error: %v", err)
	}
}

func TestCheckpointLockRejectsSymlink(t *testing.T) {
	outputDir := t.TempDir()
	target := filepath.Join(outputDir, "lock-target")
	if err := os.WriteFile(target, nil, checkpointFileMode); err != nil {
		t.Fatalf("write lock target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(outputDir, checkpointLockFileName)); err != nil {
		t.Fatalf("create checkpoint lock symlink: %v", err)
	}

	_, err := acquireCheckpointLock(outputDir)
	if err == nil || !strings.Contains(err.Error(), "open rotation checkpoint lock") {
		t.Fatalf("acquireCheckpointLock(symlink) error = %v", err)
	}
}

func TestCheckpointLockRejectsInsecurePermissions(t *testing.T) {
	outputDir := t.TempDir()
	lockPath := filepath.Join(outputDir, checkpointLockFileName)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatalf("write checkpoint lock: %v", err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatalf("set insecure checkpoint lock permissions: %v", err)
	}

	_, err := acquireCheckpointLock(outputDir)
	if err == nil || !strings.Contains(err.Error(), "permissions must be 600") {
		t.Fatalf("acquireCheckpointLock(insecure permissions) error = %v", err)
	}
}

func TestCheckpointLockIsReleasedAfterOperationError(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	if err := ensureCheckpointDirectory(outputDir); err != nil {
		t.Fatalf("create checkpoint directory: %v", err)
	}
	wantErr := errors.New("operation failed")
	if err := withCheckpointLock(outputDir, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("withCheckpointLock() error = %v, want %v", err, wantErr)
	}

	lockFile, err := acquireCheckpointLock(outputDir)
	if err != nil {
		t.Fatalf("acquire checkpoint lock after operation error: %v", err)
	}
	if err := releaseCheckpointLock(lockFile); err != nil {
		t.Fatalf("release checkpoint lock: %v", err)
	}
}

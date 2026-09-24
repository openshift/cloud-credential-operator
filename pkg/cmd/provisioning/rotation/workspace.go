package rotation

import (
	"fmt"
	"path/filepath"
	"strings"
)

// RotationWorkspace represents an exclusively locked local rotation working
// directory. It is valid only for the duration of WithRotationWorkspace.
type RotationWorkspace struct {
	outputDir string
	active    bool
}

// WithRotationWorkspace holds one workspace lock for the complete operation.
// Orchestration code must include observation, external mutation, artifact
// persistence, and the following checkpoint update in the same callback.
func WithRotationWorkspace(outputDir string, operation func(*RotationWorkspace) error) error {
	if operation == nil {
		return fmt.Errorf("rotation workspace operation must not be nil")
	}
	resolvedOutputDir, err := resolveRotationOutputDir(outputDir)
	if err != nil {
		return err
	}
	if err := ensureCheckpointDirectory(resolvedOutputDir); err != nil {
		return err
	}

	return withCheckpointLock(resolvedOutputDir, func() error {
		workspace := &RotationWorkspace{outputDir: resolvedOutputDir, active: true}
		defer func() { workspace.active = false }()
		return operation(workspace)
	})
}

// OutputDir returns the canonical directory bound to this workspace lease.
func (w *RotationWorkspace) OutputDir() (string, error) {
	if err := w.validateActive(); err != nil {
		return "", err
	}
	return w.outputDir, nil
}

func (w *RotationWorkspace) validateActive() error {
	if w == nil || !w.active || w.outputDir == "" {
		return fmt.Errorf("rotation workspace lease is not active")
	}
	return nil
}

func resolveRotationOutputDir(outputDir string) (string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return "", fmt.Errorf("rotation output directory must not be empty")
	}
	resolvedOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return "", fmt.Errorf("resolve rotation output directory: %w", err)
	}
	return filepath.Clean(resolvedOutputDir), nil
}

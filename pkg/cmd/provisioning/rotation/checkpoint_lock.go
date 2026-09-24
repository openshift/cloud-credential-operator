package rotation

import (
	"errors"
	"fmt"
	"os"
)

const checkpointLockFileName = ".rotation-state.lock"

// ErrCheckpointLocked indicates that another process is updating the same
// rotation workspace. Callers should fail instead of waiting indefinitely.
var ErrCheckpointLocked = errors.New("rotation checkpoint is locked")

func withCheckpointLock(outputDir string, operation func() error) (returnErr error) {
	lockFile, err := acquireCheckpointLock(outputDir)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseCheckpointLock(lockFile); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release rotation checkpoint lock: %w", err))
		}
	}()

	return operation()
}

func validateCheckpointLockFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect rotation checkpoint lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("rotation checkpoint lock %q must be a regular file", file.Name())
	}
	if info.Mode().Perm() != checkpointFileMode {
		return fmt.Errorf("rotation checkpoint lock %q permissions must be %o", file.Name(), checkpointFileMode)
	}
	return nil
}

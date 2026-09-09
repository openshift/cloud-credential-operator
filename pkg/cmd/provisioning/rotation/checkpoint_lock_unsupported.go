//go:build !linux && !darwin

package rotation

import (
	"fmt"
	"os"
	"runtime"
)

func acquireCheckpointLock(string) (*os.File, error) {
	return nil, fmt.Errorf("rotation checkpoint locking is not supported on %s", runtime.GOOS)
}

func releaseCheckpointLock(lockFile *os.File) error {
	return lockFile.Close()
}

//go:build linux || darwin

package rotation

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func acquireCheckpointLock(outputDir string) (*os.File, error) {
	lockPath := outputDir + string(os.PathSeparator) + checkpointLockFileName
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(lockPath, flags|unix.O_CREAT|unix.O_EXCL, uint32(checkpointFileMode))
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(lockPath, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open rotation checkpoint lock %q: %w", lockPath, err)
	}

	lockFile := os.NewFile(uintptr(fd), lockPath)
	if lockFile == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open rotation checkpoint lock %q", lockPath)
	}
	closeWithError := func(operationErr error) (*os.File, error) {
		if closeErr := lockFile.Close(); closeErr != nil {
			return nil, errors.Join(operationErr, fmt.Errorf("close rotation checkpoint lock: %w", closeErr))
		}
		return nil, operationErr
	}

	if created {
		if err := lockFile.Chmod(checkpointFileMode); err != nil {
			return closeWithError(fmt.Errorf("set rotation checkpoint lock permissions: %w", err))
		}
		if err := syncDirectory(outputDir); err != nil {
			return closeWithError(err)
		}
	}
	if err := validateCheckpointLockFile(lockFile); err != nil {
		return closeWithError(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeWithError(fmt.Errorf("%w: %q", ErrCheckpointLocked, lockPath))
		}
		return closeWithError(fmt.Errorf("lock rotation checkpoint %q: %w", lockPath, err))
	}

	return lockFile, nil
}

func releaseCheckpointLock(lockFile *os.File) error {
	unlockErr := unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	closeErr := lockFile.Close()
	return errors.Join(unlockErr, closeErr)
}

package provisioning

import (
	"fmt"
	"os"
)

// EnsureDir ensures that directory exists at a given path
func EnsureDir(path string) error {
	sResult, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %s", err)
		}
		sResult, err = os.Stat(path)
	} else if err != nil {
		return fmt.Errorf("failed to stat: %+v", err)
	}

	if !sResult.IsDir() {
		return fmt.Errorf("file %s exists and is not a directory", path)
	}

	return nil
}

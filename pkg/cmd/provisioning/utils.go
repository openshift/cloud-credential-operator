package provisioning

import (
	"fmt"
	"os"
	"strings"
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

// CreateShellScript creates a shell script given commands to execute
func CreateShellScript(commands []string) string {
	return fmt.Sprintf("#!/bin/sh\n%s", strings.Join(commands, "\n"))
}

// CountNonDirectoryFiles counts files which are not a directory
func CountNonDirectoryFiles(files []os.FileInfo) int {
	NonDirectoryFiles := 0
	for _, f := range files {
		if !f.IsDir() {
			NonDirectoryFiles++
		}
	}
	return NonDirectoryFiles
}

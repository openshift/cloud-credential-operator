package provisioning

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDirPath = "/tmp/test-Dir"
)

func TestEnsureDir(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T)
		expectError bool
		verify      func(*testing.T)
		cleanup     func(*testing.T)
	}{
		{
			name: "directory does not exist",
			setup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "error clearing out directory that should not exist")
			},
			verify: func(t *testing.T) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.Truef(t, sResult.IsDir(), "unexpected error")
			},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "failed to clean test environment")
			},
		},
		{
			name: "directory already exist",
			setup: func(t *testing.T) {
				err := os.Mkdir(testDirPath, 0700)
				require.NoError(t, err, "error setting up test environment")
			},
			verify: func(t *testing.T) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.True(t, sResult.IsDir(), "unexpected error")
			},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "failed to clean test environment")
			},
		},
		{
			name:        "File exits but not a directory",
			expectError: true,
			setup: func(t *testing.T) {
				_, err := os.Create(testDirPath)
				require.NoError(t, err, "error setting up test environment")
			},
			verify: func(t *testing.T) {},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "failed to clean test environment")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.setup(t)

			err := EnsureDir(testDirPath)
			if test.expectError {
				assert.Error(t, err, "expected error")
			} else {
				assert.NoError(t, err, "unexpected error")
			}

			test.verify(t)

			if test.cleanup != nil {
				test.cleanup(t)
			}
		})
	}
}

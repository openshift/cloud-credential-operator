package provisioning

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	nonExistentDirectory = "/tmp/credprovisiontestdirnotexist"
)

func TestCreate(t *testing.T) {
	tempDirName, err := ioutil.TempDir(os.TempDir(), "credprovisiontestdir")
	require.NoError(t, err, "failed to create temp dir")
	defer os.RemoveAll(tempDirName)

	tests := []struct {
		name    string
		setup   func(*testing.T)
		verify  func(*testing.T)
		cleanup func(*testing.T)
	}{
		{
			name: "no target dir",
			setup: func(t *testing.T) {
				CreateOpts.TargetDir = ""
			},
			verify: func(t *testing.T) {
				pwd, err := os.Getwd()
				require.NoError(t, err, "unexpected error getting current directory")

				assert.Contains(t, CreateOpts.TargetDir, pwd)
			},
		},
		{
			name: "specify target directory",
			setup: func(t *testing.T) {
				CreateOpts.TargetDir = tempDirName
			},
			verify: func(t *testing.T) {

				assert.Equal(t, CreateOpts.TargetDir, tempDirName)
			},
		},
		{
			name: "specify target directory that does not exist",
			setup: func(t *testing.T) {
				err := os.RemoveAll(nonExistentDirectory)
				require.NoError(t, err, "error clearing out directory that should not exist")
				CreateOpts.TargetDir = nonExistentDirectory
			},
			verify: func(t *testing.T) {
				assert.Equal(t, CreateOpts.TargetDir, nonExistentDirectory)

				_, err := os.Stat(nonExistentDirectory)
				require.NoError(t, err, "error stating directory that should exist")
			},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(nonExistentDirectory)
				require.NoError(t, err, "error clearing out directory that should not exist after test completes")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// start from clean dir
			dir, err := ioutil.ReadDir(tempDirName)
			if err != nil {
				t.Fatalf("Failed to read contents of temp dir: %s", err)
			}
			for _, d := range dir {
				os.RemoveAll(path.Join([]string{tempDirName, d.Name()}...))
			}

			test.setup(t)

			initEnv(nil, []string{})

			test.verify(t)

			if test.cleanup != nil {
				test.cleanup(t)
			}
		})
	}
}

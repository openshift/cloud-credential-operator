package ibmcloud

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	apiKey        = "testapiKey"
	testDirPrefix = "createtestdir"
)

func TestIAMRoles(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T) string
		verify      func(t *testing.T, tempDirName string)
		cleanup     func(*testing.T)
		expectError bool
	}{
		{
			name: "Generate Secret for one CredentialsRequest",
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "Errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "Unexpected error listing files in targetDir")

				assert.Equal(t, 1, len(files), "Should be exactly 1 Secret generated for 1 CredentialsRequest")
			},
			cleanup: func(t *testing.T) {
				return
			},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credReqDir := test.setup(t)
			defer os.RemoveAll(credReqDir)

			targetDir, err := ioutil.TempDir(os.TempDir(), "ibmcloudcreatetest")
			require.NoError(t, err, "Unexpected error creating temp dir for test")

			manifestsDir := filepath.Join(targetDir, manifestsDirName)
			err = provisioning.EnsureDir(manifestsDir)
			require.NoError(t, err, "Unexpected error creating manifests dir for test")

			err = create(credReqDir, targetDir, apiKey)

			if test.expectError {
				require.Error(t, err, "Expected error returned")
			} else {
				require.NoError(t, err, "Unexpected error creating secrets")
				test.verify(t, targetDir)
			}
		})
	}
}

func testCredentialsRequest(t *testing.T, crName, targetSecretNamespace, targetSecretName, targetDir string) error {
	credReqTemplate := `---
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: %s
  namespace: openshift-cloud-credential-operator
spec:
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: IBMCloudProviderSpec
  secretRef:
    namespace: %s
    name: %s
  serviceAccountNames:
  - testServiceAccount1`

	credReq := fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)

	f, err := ioutil.TempFile(targetDir, "testCredReq")
	require.NoError(t, err, "error creating temp file for CredentialsRequest")
	defer f.Close()

	_, err = f.Write([]byte(credReq))
	require.NoError(t, err, "error while writing out contents of CredentialsRequest file")

	return nil
}

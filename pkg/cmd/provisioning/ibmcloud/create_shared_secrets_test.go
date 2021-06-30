package ibmcloud

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	apiKey        = "testapiKey"
	testDirPrefix = "createtestdir"
)

func TestCreateSecretsCmd(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T) string
		verify      func(t *testing.T, tempDirName string)
		cleanup     func(*testing.T)
		expectError bool
	}{
		{
			name: "CreateSecretsCmd should populate secret with API key environment variable",
			setup: func(t *testing.T) string {
				os.Setenv(APIKeyEnvVar, apiKey)
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "Errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string) {
				manifestsDir := filepath.Join(targetDir, manifestsDirName)
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "Unexpected error listing files in manifestsDir")

				assert.Equal(t, 1, len(files), "Should be exactly 1 Secret generated for 1 CredentialsRequest")

				f, err := os.Open(filepath.Join(manifestsDir, files[0].Name()))
				require.NoError(t, err, "Unexpected error opening secret file")
				defer f.Close()
				decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
				secret := &corev1.Secret{}
				if err := decoder.Decode(secret); err != nil && err != io.EOF {
					require.NoError(t, err, "Unexpected error decoding secret file")
				}
				assert.Equal(t, apiKey, secret.StringData["ibmcloud_api_key"])
			},
			cleanup: func(t *testing.T) {
				return
			},
			expectError: false,
		},
		{
			name: "CreateSharedSecretsCmd with unset API key environment variable should fail",
			setup: func(t *testing.T) string {
				os.Setenv(APIKeyEnvVar, "")
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "Errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string) {
				return
			},
			cleanup: func(t *testing.T) {
				return
			},
			expectError: true,
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

			args := []string{
				fmt.Sprintf("--credentials-request-dir=%s", credReqDir),
				fmt.Sprintf("--output-dir=%s", targetDir),
			}
			CreateOpts.CredRequestDir = credReqDir
			CreateOpts.TargetDir = targetDir
			err = createSharedSecretsCmd(&cobra.Command{}, args)

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

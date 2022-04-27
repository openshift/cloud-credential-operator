package nutanix

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCredReqDirPrefix     = "nutanix_test_dir_credreq"
	testTargetDirPrefix      = "nutanix_test_dir_target"
	testCredentialsDirPrefix = "nutanix_test_dir_credentials"

	credReqTemplate = `---
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: %s
  namespace: openshift-cloud-credential-operator
spec:
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: %s
  secretRef:
    name: %s
    namespace: %s`

	basicAuthCredentialsTemplate = `
credentials:
- type: basic_auth
  data:
    prismCentral:
      username: %s
      password: %s`

	basicAuthCredentialsTemplateWithPE = `
credentials:
- type: basic_auth
  data:
    prismCentral:
      username: %s
      password: %s
    prismElements:
      - name: %s
        username: %s
        password: %s
`
)

func TestCreateSharedSecrets(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T) (credReqDir, targetDir, credentialsSourceFilepath string)
		verify      func(*testing.T, string)
		expectedErr string
	}{
		{
			name: "No CredentialsRequest manifests in directory",
			setup: func(t *testing.T) (credReqDir, targetDir, credentialsSourceFilepath string) {
				credReqDir, err := ioutil.TempDir(os.TempDir(), testCredReqDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				targetDir, err = ioutil.TempDir(os.TempDir(), testTargetDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				credentialsDir, err := ioutil.TempDir(os.TempDir(), testCredentialsDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials")
				credentialsSourceFilepath = testBasicAuthCredentials(t, "username", "password", credentialsDir)
				return
			},
			verify: func(t *testing.T, manifestsDir string) {
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Zero(t, len(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
			expectedErr: "no CredentialsRequest manifests found",
		},
		{
			name: "One CredentialsRequest manifests in directory",
			setup: func(t *testing.T) (credReqDir, targetDir, credentialsSourceFilepath string) {
				credReqDir, err := ioutil.TempDir(os.TempDir(), testCredReqDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")
				testCredentialsRequest(t, "credreq-test", "NutanixProviderSpec", "secret-ns", "secret-name", credReqDir)

				targetDir, err = ioutil.TempDir(os.TempDir(), testTargetDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				credentialsDir, err := ioutil.TempDir(os.TempDir(), testCredentialsDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials")
				credentialsSourceFilepath = testBasicAuthCredentials(t, "username", "password", credentialsDir)
				return
			},
			verify: func(t *testing.T, manifestsDir string) {
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Len(t, files, 1, "Should be exactly one files in manifestsDir when one CredReq to process")
			},
			expectedErr: "",
		},
		{
			name: "Credential generated based on credentials source file with only Prism Central Credentials",
			setup: func(t *testing.T) (credReqDir, targetDir, credentialsSourceFilepath string) {
				credReqDir, err := ioutil.TempDir(os.TempDir(), testCredReqDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")
				testCredentialsRequest(t, "credreq-test", "NutanixProviderSpec", "secret-ns", "secret-name", credReqDir)

				targetDir, err = ioutil.TempDir(os.TempDir(), testTargetDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				credentialsDir, err := ioutil.TempDir(os.TempDir(), testCredentialsDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials")
				credentialsSourceFilepath = testBasicAuthCredentials(t, "username", "password", credentialsDir)
				return
			},
			verify: func(t *testing.T, manifestsDir string) {
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Len(t, files, 1, "Should be exactly one files in manifestsDir when one CredReq to process")
				contents := getSecretFromFileContents(t, filepath.Join(manifestsDir, files[0].Name()))
				assert.Equal(t, "username", contents.PrismCentral.Username)
				assert.Equal(t, "password", contents.PrismCentral.Password)
				assert.Nil(t, contents.PrismElements, "should have no Prism Element credential")
			},
			expectedErr: "",
		},
		{
			name: "Credential generated based on credentials source file with Prism Element Credentials included",
			setup: func(t *testing.T) (credReqDir, targetDir, credentialsSourceFilepath string) {
				credReqDir, err := ioutil.TempDir(os.TempDir(), testCredReqDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")
				testCredentialsRequest(t, "credreq-test", "NutanixProviderSpec", "secret-ns", "secret-name", credReqDir)

				targetDir, err = ioutil.TempDir(os.TempDir(), testTargetDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				credentialsDir, err := ioutil.TempDir(os.TempDir(), testCredentialsDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials")
				credentialsSourceFilepath = testBasicAuthCredentialsWithPE(t, "username", "password", "pe", "username", "password", credentialsDir)
				return
			},
			verify: func(t *testing.T, manifestsDir string) {
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Len(t, files, 1, "Should be exactly one files in manifestsDir when one CredReq to process")
				contents := getSecretFromFileContents(t, filepath.Join(manifestsDir, files[0].Name()))
				assert.Equal(t, "username", contents.PrismCentral.Username)
				assert.Equal(t, "password", contents.PrismCentral.Password)
				assert.Len(t, contents.PrismElements, 1, "should have 1 Prism Element credential")
				assert.Equal(t, "pe", contents.PrismElements[0].Name)
				assert.Equal(t, "username", contents.PrismElements[0].Username)
				assert.Equal(t, "password", contents.PrismElements[0].Password)
			},
			expectedErr: "",
		},
		{
			name: "Non-existent source credentials file",
			setup: func(t *testing.T) (credReqDir, targetDir, credentialsSourceFilepath string) {
				credReqDir, err := ioutil.TempDir(os.TempDir(), testCredReqDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				targetDir, err = ioutil.TempDir(os.TempDir(), testTargetDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				credentialsSourceFilepath = "does/not/exist"
				return
			},
			verify: func(t *testing.T, manifestsDir string) {
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Zero(t, len(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
			expectedErr: "The source credentials file does/not/exist does not exist",
		},
		{
			name: "Non-existent credentials requests directory",
			setup: func(t *testing.T) (credReqDir, targetDir, credentialsSourceFilepath string) {
				credReqDir = "does/not/exist"

				targetDir, err := ioutil.TempDir(os.TempDir(), testTargetDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials requests")

				credentialsDir, err := ioutil.TempDir(os.TempDir(), testCredentialsDirPrefix)
				require.NoError(t, err, "Failed to create temp directory for credentials")
				credentialsSourceFilepath = testBasicAuthCredentials(t, "username", "password", credentialsDir)
				return
			},
			verify: func(t *testing.T, manifestsDir string) {
				files, err := ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Zero(t, len(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
			expectedErr: "Failed to process files containing CredentialsRequests: open does/not/exist: no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credReqDir, targetDir, credentialsSource := tt.setup(t)
			defer os.RemoveAll(credReqDir)
			defer os.RemoveAll(targetDir)
			defer os.RemoveAll(credentialsSource)

			cmd := NewNutanixCmd()
			// Swap stdout and stderr with a buffer to keep test logs clean
			b := bytes.NewBufferString("")
			cmd.SetOut(b)
			cmd.SetErr(b)

			cmd.SetArgs([]string{"create-shared-secrets",
				"--credentials-requests-dir", credReqDir,
				"--output-dir", targetDir,
				"--credentials-source-filepath", credentialsSource,
			})

			if err := cmd.Execute(); err != nil && !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("createSharedSecrets() error %q, expectedErr %q", err, tt.expectedErr)
			}

			manifestsDir := filepath.Join(targetDir, manifestsDirName)
			tt.verify(t, manifestsDir)
		})
	}
}

func testCredentialsRequest(t *testing.T, crName, kind, targetSecretNamespace, targetSecretName, targetDir string) string {
	credReq := getCredentialsRequest(crName, kind, targetSecretNamespace, targetSecretName)
	return writeToTempFile(t, targetDir, credReq, "nutanix_test_credreq", "yaml")
}

func getCredentialsRequest(crName, kind, targetSecretNamespace, targetSecretName string) string {
	return fmt.Sprintf(credReqTemplate, crName, kind, targetSecretName, targetSecretNamespace)
}

func testBasicAuthCredentials(t *testing.T, username, password, targetDir string) string {
	creds := getBasicAuthCredentials(username, password)
	return writeToTempFile(t, targetDir, creds, "nutanix_test_basic_auth", "yaml")
}

func testBasicAuthCredentialsWithPE(t *testing.T, pcUsername, pcPassword, peName, peUsername, pePassword, targetDir string) string {
	creds := getBasicAuthCredentialsWithPE(pcUsername, pcPassword, peName, peUsername, pePassword)
	return writeToTempFile(t, targetDir, creds, "nutanix_test_basic_auth", "yaml")
}

func getBasicAuthCredentials(username, password string) string {
	return fmt.Sprintf(basicAuthCredentialsTemplate, username, password)
}

func getBasicAuthCredentialsWithPE(pcUsername, pcPassword, peName, peUsername, pePassword string) string {
	return fmt.Sprintf(basicAuthCredentialsTemplateWithPE, pcUsername, pcPassword, peName, peUsername, pePassword)
}

func writeToTempFile(t *testing.T, targetDir, content, prefix, extension string) string {
	filePattern := fmt.Sprintf("%s*.%s", prefix, extension)
	f, err := ioutil.TempFile(targetDir, filePattern)
	require.NoError(t, err, "error creating temp file for %s", filePattern)
	defer f.Close()

	_, err = f.Write([]byte(content))
	require.NoError(t, err, "error while writing out contents of %s file", f.Name())
	return f.Name()
}

func getSecretFromFileContents(t *testing.T, path string) *BasicAuthCredential {
	contents, err := ioutil.ReadFile(path)
	require.NoError(t, err, "should be able to real contents of file")

	data := struct {
		Data struct {
			Credentials string `json:"credentials"`
		} `json:"data"`
	}{}
	err = yaml.NewDecoder(strings.NewReader(string(contents))).Decode(&data)
	require.NoError(t, err, "should be able to decode credentials out of contents")

	decoded, err := base64.StdEncoding.DecodeString(data.Data.Credentials)
	require.NoError(t, err, "should be able to decode base64")

	creds := make([]Credential, 0)
	err = json.NewDecoder(bytes.NewReader(decoded)).Decode(&creds)
	require.NoError(t, err, "should be able to decode json")
	require.Len(t, creds, 1, "should not be more than one credential")
	require.Equal(t, BasicAuthCredentialType, creds[0].Type)

	basicAuthCreds := BasicAuthCredential{}
	err = json.NewDecoder(bytes.NewReader(creds[0].Data.Raw)).Decode(&basicAuthCreds)
	require.NoError(t, err, "should be able to decode json")

	return &basicAuthCreds
}

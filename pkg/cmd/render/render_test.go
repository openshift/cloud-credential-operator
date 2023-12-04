package render

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/openshift/api/config/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	testDestinationDirName = "renderHere"
)

type testFile struct {
	name string
	data string
}

func TestRender(t *testing.T) {
	tests := []struct {
		name          string
		existingFiles []*testFile
		expectPodFile bool
		expectMode    string
		expectError   bool
	}{
		{
			name: "install config default",
			existingFiles: []*testFile{
				testInstallConfig(""),
			},
			expectPodFile: true,
			// default is no setting in the config
			expectMode: "",
		},
		{
			name: "install config manual mode",
			existingFiles: []*testFile{
				testInstallConfig(string(operatorv1.CloudCredentialsModeManual)),
			},
			expectPodFile: false,
			expectMode:    string(operatorv1.CloudCredentialsModeManual),
		},
		{
			name: "deprecated configmap disables cco",
			existingFiles: []*testFile{
				testInstallConfig(""),
				testConfigMap("true"),
			},
			expectPodFile: false,
			expectMode:    string(operatorv1.CloudCredentialsModeManual),
		},
		{
			name: "install config mint mode",
			existingFiles: []*testFile{
				testInstallConfig(string(operatorv1.CloudCredentialsModeMint)),
			},
			expectPodFile: true,
			expectMode:    string(operatorv1.CloudCredentialsModeMint),
		},
		{
			name: "configmap and installconfig conflict",
			existingFiles: []*testFile{
				testInstallConfig(string(operatorv1.CloudCredentialsModeMint)),
				testConfigMap("true"),
			},
			expectError: true,
		},
		{
			name: "configmap and installconfig concur",
			existingFiles: []*testFile{
				testInstallConfig(string(operatorv1.CloudCredentialsModeManual)),
				testConfigMap("true"),
			},
			expectPodFile: false,
			expectMode:    string(operatorv1.CloudCredentialsModeManual),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifestsDir, err := os.MkdirTemp("/tmp", "rendertestmanifests")
			require.NoError(t, err, "errored setting up test")
			defer os.RemoveAll(manifestsDir)

			for _, file := range test.existingFiles {
				filePath := filepath.Join(manifestsDir, file.name)
				err := os.WriteFile(filePath, []byte(file.data), 0644)
				require.NoError(t, err, "failed writing out manifests for test")
			}
			destDir, err := os.MkdirTemp("/tmp", "rendertestdestination")
			require.NoError(t, err, "errored setting up test")
			defer os.RemoveAll(destDir)

			destDirRenderPath := filepath.Join(destDir, testDestinationDirName)

			renderOpts.manifestsDir = manifestsDir
			renderOpts.destinationDir = destDirRenderPath
			renderOpts.ccoImage = "testCCOImage"
			renderOpts.logLevel = "debug"

			err = render()

			if test.expectError {
				require.Error(t, err, "expected error for test case")
			} else {
				require.NoError(t, err, "unexpected error")

				verifyPodFile(t, destDirRenderPath, test.expectPodFile)

				verifyConfigMode(t, destDirRenderPath, test.expectMode)
			}
		})
	}
}

func testInstallConfig(credMode string) *testFile {
	instConfFile := testFile{
		name: "install-config.yaml",
	}

	installConfigData := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-config-v1
  namespace: kube-system
data:
  install-config: |
    baseDomain: test.openshift.io
    credentialsMode: %s`

	instConfFile.data = fmt.Sprintf(installConfigData, credMode)

	return &instConfFile
}

func verifyPodFile(t *testing.T, destDir string, expectFileToExist bool) {
	podFilePath := filepath.Join(destDir, bootstrapManifestsDir, podYamlFilename)
	_, err := os.Stat(podFilePath)

	if expectFileToExist {
		assert.NoError(t, err, "expected pod yaml to be rendered")
	} else {
		assert.True(t, os.IsNotExist(err), "expect pod yaml to not be rendered")
	}
}

func verifyConfigMode(t *testing.T, destDir, expectMode string) {
	configFilePath := filepath.Join(destDir, manifestsDir, operatorConfigFilename)

	file, err := os.Open(configFilePath)
	require.NoError(t, err, "error reading in rendered config file")

	conf := operatorv1.CloudCredential{}
	decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
	err = decoder.Decode(&conf)
	require.NoError(t, err, "error decoding rendered config")

	assert.Equal(t, expectMode, string(conf.Spec.CredentialsMode), "config file has unexpected mode set")
}

func TestInstallConfig(t *testing.T) {
	installConfigData := `baseDomain: test.openshift.io
credentialsMode: Manual
capabilities:
  baselineCapabilitySet: v4.13
  additionalEnabledCapabilities:
  - CloudCredential`

	capSpec := &v1.ClusterVersionCapabilitiesSpec{
		BaselineCapabilitySet:         v1.ClusterVersionCapabilitySet4_13,
		AdditionalEnabledCapabilities: []v1.ClusterVersionCapability{v1.ClusterVersionCapabilityCloudCredential},
	}

	ic := &basicInstallConfig{}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewBufferString(installConfigData), 4096)
	err := decoder.Decode(&ic)
	assert.NoError(t, err)
	assert.Equal(t, operatorv1.CloudCredentialsModeManual, ic.CredentialsMode)
	assert.Equal(t, capSpec, ic.Capabilities)

	assert.Equal(t, false, isDisabledViaCapability(ic.Capabilities))
}

func testConfigMap(disabled string) *testFile {
	configMapFile := testFile{
		name: "configmap.yaml",
	}

	data := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cloud-credential-operator-config
  namespace: openshift-cloud-credential-operator
data:
  disabled: "%s"`

	configMapFile.data = fmt.Sprintf(data, disabled)

	return &configMapFile
}

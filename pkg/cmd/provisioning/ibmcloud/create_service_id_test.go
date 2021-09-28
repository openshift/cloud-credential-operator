package ibmcloud

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	pmv1 "github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	mockibmcloud "github.com/openshift/cloud-credential-operator/pkg/ibmcloud/mock"
)

const (
	testDirPrefix = "createtestdir"
)

var (
	apiKeyID        = "fakeID"
	apiKeyIamID     = "fakeIamID"
	apiKeyApikey    = "fakeApikey"
	apiKeyAccountID = "fakeAccountID"
	policyID        = "fakePolicyID"
	policyType      = "access"
	serviceID       = "fakeServiceID"
	serviceIDName   = "fakeServiceIDName"
	serviceIDIamID  = "fakeServiceIDIamID"
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
			name: "CreateSharedSecretsCmd with unset API key environment variable should fail",
			setup: func(t *testing.T) string {
				os.Setenv(APIKeyEnvVars[0], "")
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

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
				fmt.Sprintf("--name=%s", "ibmcloud-cluster"),
			}
			Options.CredRequestDir = credReqDir
			Options.TargetDir = targetDir
			err = createServiceIDCmd(&cobra.Command{}, args)

			if test.expectError {
				require.Error(t, err, "Expected error returned")
			} else {
				require.NoError(t, err, "Unexpected error creating secrets")
				test.verify(t, targetDir)
			}
		})
	}
}

func TestCreateSharedSecrets(t *testing.T) {
	tests := []struct {
		name               string
		mockIBMCloudClient func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient
		resourceGroupName  string
		setup              func(*testing.T) string
		verify             func(*testing.T, string, string)
		wantErr            bool
	}{
		{
			name: "createServiceIDs No CredReqs",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockCreatePolicy(mockIBMCloudClient, 0, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")
				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
		},
		{
			name: "Create for one CredReq",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockDeleteServiceID(mockIBMCloudClient, 0, false)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
		},
		{
			name:              "CredReq with ResourceGroupName",
			resourceGroupName: "resource-group-exist",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListResourceGroups(mockIBMCloudClient, true, false)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockDeleteServiceID(mockIBMCloudClient, 0, false)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				//TODO(mkumatag): add validation to check for the rules created for the resource group if mentioned
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
		},
		{
			name:              "CredReq with invalid ResourceGroupName",
			resourceGroupName: "resource-group-doesnotexist",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListResourceGroups(mockIBMCloudClient, false, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				//TODO(mkumatag): add validation to check for the rules created for the resource group if mentioned
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 0, countNonDirectoryFiles(files), "Should not any secret in manifestsDir")
			},
			wantErr: true,
		},
		{
			name:              "failed to ListResourceGroups",
			resourceGroupName: "resource-group",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListResourceGroups(mockIBMCloudClient, true, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
		{
			name: "CredReq with non-ibm spec",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequestNonIBM(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 0, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
			wantErr: true,
		},
		{
			name: "CredReq with non-existing credReqDir",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				return "non-existingdir"
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 0, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
			wantErr: true,
		},
		{
			name: "failed to CreateServiceID",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
		{
			name: "failed to createPolicy",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, true)
				mockDeleteServiceID(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
		{
			name: "failed to CreateAPIKey",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, false)
				mockCreateAPIKey(mockIBMCloudClient, 1, true)
				mockDeleteServiceID(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
		{
			name: "failed to DeleteServiceID",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, false)
				mockCreateAPIKey(mockIBMCloudClient, 1, true)
				mockDeleteServiceID(mockIBMCloudClient, 1, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
		{
			name: "Create with Existing ServiceID",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 1, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
		{
			name: "failed to ListServiceID",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockIBMCloudClient := tt.mockIBMCloudClient(mockCtrl)

			credReqDir := tt.setup(t)
			defer os.RemoveAll(credReqDir)

			targetDir, err := ioutil.TempDir(os.TempDir(), "iamroletest")
			require.NoError(t, err, "unexpected error creating target dir for test")
			defer os.RemoveAll(targetDir)

			manifestsDir := filepath.Join(targetDir, manifestsDirName)
			err = provisioning.EnsureDir(manifestsDir)
			require.NoError(t, err, "unexpected error creating manifests dir for test")
			defer os.RemoveAll(manifestsDir)

			if err := createServiceIDs(mockIBMCloudClient, core.StringPtr("1234"), "name", tt.resourceGroupName, credReqDir, targetDir); (err != nil) != tt.wantErr {
				t.Errorf("createServiceIDs() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.verify(t, targetDir, manifestsDir)
		})
	}
}

func TestCreateSharedSecretsInvalidTargetDir(t *testing.T) {
	tests := []struct {
		name               string
		mockIBMCloudClient func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient
		resourceGroupName  string
		setup              func(*testing.T) string
		verify             func(*testing.T, string, string)
		wantErr            bool
	}{
		{
			name: "with invalid target dir",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockDeleteServiceID(mockIBMCloudClient, 0, false)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, false)
				mockDeleteServiceID(mockIBMCloudClient, 1, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)

				return tempDirName
			},
			verify:  func(t *testing.T, targetDir string, manifestsDir string) {},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockIBMCloudClient := tt.mockIBMCloudClient(mockCtrl)

			credReqDir := tt.setup(t)
			defer os.RemoveAll(credReqDir)

			targetDir := "doesnotexist"

			if err := createServiceIDs(mockIBMCloudClient, core.StringPtr("1234"), "name1", tt.resourceGroupName, credReqDir, targetDir); (err != nil) != tt.wantErr {
				t.Errorf("createServiceIDs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func writeToTempFile(t *testing.T, targetDir, content string) {
	f, err := ioutil.TempFile(targetDir, "testCredReq")
	require.NoError(t, err, "error creating temp file for CredentialsRequest")
	defer f.Close()

	_, err = f.Write([]byte(content))
	require.NoError(t, err, "error while writing out contents of CredentialsRequest file")
}

func testCredentialsRequest(t *testing.T, crName, targetSecretNamespace, targetSecretName, targetDir string) {
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
    policies:
      - roles:
          - "crn:v1:bluemix:public:iam::::serviceRole:Manager"
          - "crn:v1:bluemix:public:iam::::role:Editor"
          - "crn:v1:bluemix:public:iam::::role:Viewer"
        attributes:
          - name: "serviceName"
            value: "is"
  secretRef:
    namespace: %s
    name: %s`

	credReq := fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)

	writeToTempFile(t, targetDir, credReq)
}

func testCredentialsRequestNonIBM(t *testing.T, crName, targetSecretNamespace, targetSecretName, targetDir string) {
	credReqTemplate := `---
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: %s
  namespace: openshift-cloud-credential-operator
spec:
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    policies:
      - roles:
          - "crn:v1:bluemix:public:iam::::serviceRole:Manager"
          - "crn:v1:bluemix:public:iam::::role:Editor"
          - "crn:v1:bluemix:public:iam::::role:Viewer"
        attributes:
          - name: "serviceName"
            value: "is"
  secretRef:
    namespace: %s
    name: %s`

	credReq := fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)

	writeToTempFile(t, targetDir, credReq)
}

func Test_getEnv(t *testing.T) {
	type env struct {
		variable, value string
	}
	tests := []struct {
		name string
		envs []env
		want string
	}{
		{
			name: "Return IC_API_KEY value",
			envs: []env{
				{"IBMCLOUD_API_KEY", "IBMCLOUD_API_KEY_apikey"},
				{"BM_API_KEY", "BM_API_KEY_apikey"},
				{"IC_API_KEY", "IC_API_KEY_apikey"},
				{"BLUEMIX_API_KEY", "BLUEMIX_API_KEY_apikey"},
			},
			want: "IC_API_KEY_apikey",
		},
		{
			name: "Return IBMCLOUD_API_KEY value",
			envs: []env{
				{"BM_API_KEY", "BM_API_KEY_apikey"},
				{"BLUEMIX_API_KEY", "BLUEMIX_API_KEY_apikey"},
				{"IBMCLOUD_API_KEY", "IBMCLOUD_API_KEY_apikey"},
			},
			want: "IBMCLOUD_API_KEY_apikey",
		},
		{
			name: "Returns empty value",
			envs: []env{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, env := range tt.envs {
				os.Setenv(env.variable, env.value)
				defer os.Unsetenv(env.variable)
			}
			if got := getEnv(APIKeyEnvVars); got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getMockedAPIKey() *iamidentityv1.APIKey {
	return &iamidentityv1.APIKey{
		ID:        &apiKeyID,
		IamID:     &apiKeyIamID,
		Apikey:    &apiKeyApikey,
		AccountID: &apiKeyAccountID,
	}
}

func mockDeleteServiceID(client *mockibmcloud.MockClient, times int, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf("failed to get APIKeyDetails")
	}
	client.EXPECT().DeleteServiceID(gomock.Any()).Return(nil, err).Times(times)
}

func mockCreatePolicy(client *mockibmcloud.MockClient, times int, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf("failed to get APIKeyDetails")
	}
	client.EXPECT().CreatePolicy(gomock.Any()).Return(
		&pmv1.Policy{
			ID:   &policyID,
			Type: &policyType,
		}, nil, err).Times(times)
}

func mockCreateAPIKey(client *mockibmcloud.MockClient, times int, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf("failed to get APIKeyDetails")
	}
	apiKey := getMockedAPIKey()
	client.EXPECT().CreateAPIKey(gomock.Any()).Return(apiKey, nil, err).Times(times)
}

func mockCreateServiceID(client *mockibmcloud.MockClient, times int, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf("failed to get APIKeyDetails")
	}
	client.EXPECT().CreateServiceID(gomock.Any()).Return(
		&iamidentityv1.ServiceID{
			ID:    &serviceID,
			Name:  &serviceIDName,
			IamID: &serviceIDIamID,
		}, nil, err).Times(times)
}

func mockListResourceGroups(client *mockibmcloud.MockClient, resourceGroupExist, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf("failed to get ListResourceGroups")
	}
	list := &resourcemanagerv2.ResourceGroupList{}
	if resourceGroupExist {
		list.Resources = append(list.Resources,
			resourcemanagerv2.ResourceGroup{
				ID: core.StringPtr("1395aa936dd1434b9317f8ed4c7a2345"),
			})
	}
	client.EXPECT().ListResourceGroups(gomock.Any()).Return(list, nil, err).Times(1)
}

func mockListServiceID(client *mockibmcloud.MockClient, namePrefix string, count int, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf("failed to get ListServiceID")
	}
	list := &iamidentityv1.ServiceIDList{
		Serviceids: []iamidentityv1.ServiceID{},
	}
	if namePrefix == "" {
		namePrefix = "service-id"
	}
	for i := 0; i < count; i++ {
		list.Serviceids = append(list.Serviceids,
			iamidentityv1.ServiceID{
				Name: core.StringPtr(namePrefix + "-" + strconv.Itoa(i)),
				ID:   core.StringPtr("ServiceId-" + uuid.New().String()),
			})
	}
	client.EXPECT().ListServiceID(gomock.Any()).Return(list, nil, err).Times(1)
}

// countNonDirectoryFiles counts files which are not a directory
// TODO(mkumatag): duplicate code from aws tests, need to explore moving to some common location
func countNonDirectoryFiles(files []os.FileInfo) int {
	NonDirectoryFiles := 0
	for _, f := range files {
		if !f.IsDir() {
			NonDirectoryFiles++
		}
	}
	return NonDirectoryFiles
}

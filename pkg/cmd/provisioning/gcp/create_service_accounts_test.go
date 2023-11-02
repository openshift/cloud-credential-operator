package gcp

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	mockgcp "github.com/openshift/cloud-credential-operator/pkg/gcp/mock"
)

const (
	testProjectNumber       = int64(123456789)
	testCredReqName         = "test-cred-req"
	testTargetNamespaceName = "test-namespace"
	testTargetSecretName    = "test-secret"
	testCustomRoleName      = "test-custom-role-name"
)

var (
	testCustomRolePermissions = []string{
		"iam.roles.get",
		"iam.roles.list",
		"resourcemanager.projects.get",
		"resourcemanager.projects.getIamPolicy",
	}
)

func TestCreateServiceAccounts(t *testing.T) {

	tests := []struct {
		name          string
		mockGCPClient func(mockCtrl *gomock.Controller) *mockgcp.MockClient
		setup         func(*testing.T) string
		verify        func(t *testing.T, targetDir, manifestsDir string)
		cleanup       func(*testing.T)
		generateOnly  bool
		expectError   bool
	}{
		{
			name:         "No CredReqs",
			generateOnly: true,
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient, 1)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")
				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "Unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "Unexpected error listing files in manifestsDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
		},
		{
			name:         "Generate for one CredReq",
			generateOnly: true,
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient, 3)
				mockGetProject(mockGCPClient)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, testCredReqName, testTargetNamespaceName, testTargetSecretName, tempDirName)
				require.NoError(t, err, "Error while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "Unexpected error listing files in targetDir")
				assert.Equal(t, 4, countNonDirectoryFiles(files), "Should be exactly 4 shell scripts")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "Unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
		},
		{
			name:         "Create for one CredReq",
			generateOnly: false,
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockListServiceAccountsEmpty(mockGCPClient)
				mockListRolesEmpty(mockGCPClient)
				mockCreateServiceAccountSuccessful(mockGCPClient)
				mockGetProjectName(mockGCPClient, 8)
				mockGetProject(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient)
				mockSetProjectIamPolicy(mockGCPClient)
				mockGetServiceAccountIamPolicy(mockGCPClient)
				mockSetServiceAccountIamPolicy(mockGCPClient)
				mockCreateRole(mockGCPClient)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, testCredReqName, testTargetNamespaceName, testTargetSecretName, tempDirName)
				require.NoError(t, err, "Error while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "Unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no generated files when not in generate mode")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "Unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
		},
		{
			name:         "Failed to create service account",
			expectError:  true,
			generateOnly: false,
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient, 4)
				mockGetProject(mockGCPClient)
				mockListServiceAccountsEmpty(mockGCPClient)
				mockCreateServiceAccountFailed(mockGCPClient)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, testCredReqName, testTargetNamespaceName, testTargetSecretName, tempDirName)
				require.NoError(t, err, "Error while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir, manifestsDir string) {},
		},
		{
			name:         "Service account already exists, along with custom role created for permissions",
			generateOnly: false,
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockListServiceAccountsNotEmpty(mockGCPClient)
				mockListRolesNotEmpty(mockGCPClient)
				mockGetProjectName(mockGCPClient, 8)
				mockGetProject(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient)
				mockSetProjectIamPolicy(mockGCPClient)
				mockGetServiceAccountIamPolicy(mockGCPClient)
				mockSetServiceAccountIamPolicy(mockGCPClient)
				mockUpdateRole(mockGCPClient)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, testCredReqName, testTargetNamespaceName, testTargetSecretName, tempDirName)
				require.NoError(t, err, "Error while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir, manifestsDir string) {},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockGCPClient := test.mockGCPClient(mockCtrl)

			credReqDir := test.setup(t)
			defer os.RemoveAll(credReqDir)

			targetDir, err := ioutil.TempDir(os.TempDir(), "create_service_account_test")
			require.NoError(t, err, "Unexpected error creating target dir for test")
			defer os.RemoveAll(targetDir)

			manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)
			err = provisioning.EnsureDir(manifestsDir)
			require.NoError(t, err, "Unexpected error creating manifests dir for test")
			defer os.RemoveAll(manifestsDir)

			err = createServiceAccounts(context.TODO(), mockGCPClient, testName, testName, testName, credReqDir, targetDir, false, test.generateOnly)

			if test.expectError {
				require.Error(t, err, "expected error returned")
			} else {
				test.verify(t, targetDir, manifestsDir)
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
    kind: GCPProviderSpec
    predefinedRoles:
    - roles/iam.securityReviewer
    permissions:
    - iam.roles.get
    - iam.roles.list
    - resourcemanager.projects.get
    - resourcemanager.projects.getIamPolicy
    skipServiceCheck: true
  secretRef:
    namespace: %s
    name: %s
  serviceAccountNames:
  - testServiceAccount1
  - testServiceAccount2`

	credReq := fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)

	f, err := ioutil.TempFile(targetDir, "testCredReq*.yaml")
	require.NoError(t, err, "error creating temp file for CredentialsRequest")
	defer f.Close()

	_, err = f.Write([]byte(credReq))
	require.NoError(t, err, "error while writing out contents of CredentialsRequest file")

	return nil
}

// countNonDirectoryFiles counts files which are not a directory
func countNonDirectoryFiles(files []os.FileInfo) int {
	NonDirectoryFiles := 0
	for _, f := range files {
		if !f.IsDir() {
			NonDirectoryFiles++
		}
	}
	return NonDirectoryFiles
}

func mockListServiceAccountsEmpty(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Return(
		[]*iamadminpb.ServiceAccount{}, nil).Times(1)
}

func mockListServiceAccountsNotEmpty(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Return(
		[]*iamadminpb.ServiceAccount{
			{
				DisplayName: fmt.Sprintf("%s-%s", testName, testCredReqName),
				Email:       fmt.Sprintf("%s-%s@test.domain.com", testName, testCredReqName),
			},
		}, nil).Times(1)
}

func mockListRolesEmpty(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListRoles(gomock.Any(), gomock.Any()).Return(
		&iamadminpb.ListRolesResponse{}, nil).Times(1)
}

func mockListRolesNotEmpty(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListRoles(gomock.Any(), gomock.Any()).Return(
		&iamadminpb.ListRolesResponse{
			Roles: []*iamadminpb.Role{
				{
					Title: fmt.Sprintf("%s-%s", testProject, testCredReqName),
				},
			},
		}, nil).Times(1)
}

func mockCreateServiceAccountSuccessful(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(
		&iamadminpb.ServiceAccount{
			DisplayName: fmt.Sprintf("%s-service-account", testName),
			Email:       fmt.Sprintf("%s-service-account@test.domain.com", testName),
		}, nil).Times(1)
}

func mockCreateServiceAccountFailed(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(
		nil, fmt.Errorf("failed to create service account")).Times(1)
}

func mockGetProjectName(mockGCPClient *mockgcp.MockClient, times int) {
	mockGCPClient.EXPECT().GetProjectName().Return(testProject).Times(times)
}

func mockGetProject(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetProject(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.Project{
		Name:          testProject,
		ProjectNumber: testProjectNumber,
	}, nil).Times(1)
}

func mockGetProjectIamPolicy(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetProjectIamPolicy(gomock.Any(), gomock.Any()).Return(
		&cloudresourcemanager.Policy{}, nil).Times(1)
}

func mockGetServiceAccountIamPolicy(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetServiceAccountIamPolicy(gomock.Any()).Return(
		&iam.Policy{}, nil).Times(2)
}

func mockSetProjectIamPolicy(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().SetProjectIamPolicy(gomock.Any(), gomock.Any()).Return(
		&cloudresourcemanager.Policy{}, nil).Times(1)
}

func mockSetServiceAccountIamPolicy(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().SetServiceAccountIamPolicy(gomock.Any(), gomock.Any()).Return(
		&iam.Policy{}, nil).Times(2)
}

func mockCreateRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().CreateRole(gomock.Any(), gomock.Any()).Return(&iamadminpb.Role{
		Name:                testCustomRoleName,
		IncludedPermissions: testCustomRolePermissions,
	}, nil)
}

func mockUpdateRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().UpdateRole(gomock.Any(), gomock.Any()).Return(&iamadminpb.Role{
		Name:                testCustomRoleName,
		IncludedPermissions: testCustomRolePermissions,
	}, nil)
}

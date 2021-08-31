package aws

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"

	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	testIdentityProviderARN    = "arn:aws:iam::123456789012:oidc-provider/testing123-oidc.s3.amazonaws.com"
	testPermissionsBoundaryARN = "arn:aws:iam::123456789012:policy/testing123-permissions-boundary"
	testIdentityProviderURL    = "testing123-oidc.s3.amazonaws.com"
	testNamePrefix             = "test-cluster1"
)

func TestIAMRoles(t *testing.T) {

	tests := []struct {
		name          string
		mockAWSClient func(mockCtrl *gomock.Controller) *mockaws.MockClient
		setup         func(*testing.T) string
		verify        func(t *testing.T, targetDir, manifestsDir string)
		cleanup       func(*testing.T)
		generateOnly  bool
		expectError   bool
	}{
		{
			name:         "No CredReqs",
			generateOnly: true,
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetOpenIDConnectProvider(mockAWSClient)
				return mockAWSClient
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
			name:         "Generate for one CredReq",
			generateOnly: true,
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetOpenIDConnectProvider(mockAWSClient)
				return mockAWSClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir string, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Equal(t, 2, countNonDirectoryFiles(files), "Should be exactly 1 IAM Role JSON and 1 IAM Role Policy file for each CredReq")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
		},
		{
			name:         "Create for one CredReq",
			generateOnly: false,
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetOpenIDConnectProvider(mockAWSClient)
				mockGetRole(mockAWSClient)
				roleName := fmt.Sprintf("%s-namespace1-secretName1", testNamePrefix)
				mockCreateRole(mockAWSClient, roleName)
				mockPutRolePolicy(mockAWSClient)
				return mockAWSClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir, manifestsDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, countNonDirectoryFiles(files), "Should be no generated files when not in generate mode")

				files, err = ioutil.ReadDir(manifestsDir)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, countNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
		},
		{
			name:         "failed to create Role",
			expectError:  true,
			generateOnly: false,
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetOpenIDConnectProvider(mockAWSClient)
				mockGetRole(mockAWSClient)
				roleName := fmt.Sprintf("%s-namespace1-secretName1", testNamePrefix)
				mockFailedCreateRole(mockAWSClient, roleName)
				return mockAWSClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir, manifestsDir string) {},
		},
		{
			name:         "Role already exists",
			generateOnly: false,
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetOpenIDConnectProvider(mockAWSClient)
				roleName := fmt.Sprintf("%s-namespace1-secretName1", testNamePrefix)
				mockGetRoleExists(mockAWSClient, roleName)
				mockPutRolePolicy(mockAWSClient)
				return mockAWSClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, targetDir, manifestsDir string) {},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAWSClient := test.mockAWSClient(mockCtrl)

			credReqDir := test.setup(t)
			defer os.RemoveAll(credReqDir)

			targetDir, err := ioutil.TempDir(os.TempDir(), "iamroletest")
			require.NoError(t, err, "unexpected error creating target dir for test")
			defer os.RemoveAll(targetDir)

			manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)
			err = provisioning.EnsureDir(manifestsDir)
			require.NoError(t, err, "unexpected error creating manifests dir for test")
			defer os.RemoveAll(manifestsDir)

			err = createIAMRoles(mockAWSClient, testIdentityProviderARN, testPermissionsBoundaryARN, testNamePrefix, credReqDir, targetDir, test.generateOnly)

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
    kind: AWSProviderSpec
    statementEntries:
    - action:
      - ec2:DescribeInstances
      effect: Allow
      resource: '*'
    - action:
      - kms:Decrypt
      - kms:Encrypt
      - kms:GenerateDataKey
      - kms:GenerateDataKeyWithoutPlainText
      - kms:DescribeKey
      effect: Allow
      resource: '*'
  secretRef:
    namespace: %s
    name: %s
  serviceAccountNames:
  - testServiceAccount1
  - testServiceAccount2`

	credReq := fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)

	f, err := ioutil.TempFile(targetDir, "testCredReq")
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

func mockGetOpenIDConnectProvider(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetOpenIDConnectProvider(gomock.Any()).Return(
		&iam.GetOpenIDConnectProviderOutput{
			Url: awssdk.String(testIdentityProviderURL),
		}, nil).AnyTimes()
}

func mockGetRole(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetRole(gomock.Any()).Return(
		nil, awserr.New(iam.ErrCodeNoSuchEntityException, "Role does not exist", fmt.Errorf("fake error")),
	).Times(1)
}

func mockGetRoleExists(mockAWSClient *mockaws.MockClient, roleName string) {
	mockAWSClient.EXPECT().GetRole(gomock.Any()).Return(
		&iam.GetRoleOutput{
			Role: &iam.Role{
				Arn:      awssdk.String("test-role-arn"),
				RoleName: awssdk.String(roleName),
			},
		}, nil,
	).Times(1)
}

func mockCreateRole(mockAWSClient *mockaws.MockClient, roleName string) {
	mockAWSClient.EXPECT().CreateRole(gomock.Any()).Return(
		&iam.CreateRoleOutput{
			Role: &iam.Role{
				Arn:      awssdk.String("test-role-arn"),
				RoleName: awssdk.String(roleName),
			},
		}, nil,
	).Times(1)
}

func mockFailedCreateRole(mockAWSClient *mockaws.MockClient, roleName string) {
	mockAWSClient.EXPECT().CreateRole(gomock.Any()).Return(
		&iam.CreateRoleOutput{}, fmt.Errorf("test error on role create"),
	).Times(1)
}

func mockPutRolePolicy(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().PutRolePolicy(gomock.Any()).Return(
		&iam.PutRolePolicyOutput{}, nil,
	).Times(1)
}

func mockUpdateAssumeRolePolicy(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().UpdateAssumeRolePolicy(gomock.Any()).Return(
		&iam.UpdateAssumeRolePolicyOutput{}, nil,
	).Times(1)
}

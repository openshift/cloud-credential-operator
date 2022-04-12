package alibabacloud

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"

	mockalibaba "github.com/openshift/cloud-credential-operator/pkg/alibabacloud/mock"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	testNamePrefix = "test-cluster1"
	testDirPrefix  = "ramtestdir"
)

var mockPolicyInCreatePolicy = ram.PolicyInCreatePolicy{
	PolicyName:     "alibaba-mock-default-test",
	PolicyType:     "Custom",
	Description:    "alibaba-mock-test",
	DefaultVersion: "v1",
	CreateDate:     "2021-01-23T12:33:18Z",
}

var mockPolicyInGetPolicy = ram.PolicyInGetPolicy{
	PolicyName:     "alibaba-mock-default-test",
	PolicyType:     "Custom",
	Description:    "alibaba-mock-test",
	DefaultVersion: "v1",
	CreateDate:     "2021-01-23T12:33:18Z",
}

var mockPolicyVersionInCreatePolicyVersion = ram.PolicyVersionInCreatePolicyVersion{
	VersionId:        "v2",
	IsDefaultVersion: true,
}

var mockUserInCreateUser = ram.UserInCreateUser{
	UserName: "mock-ram-user-name",
}

var mockAccessKeyInCreateAccessKey = ram.AccessKeyInCreateAccessKey{
	AccessKeyId:     "test-ak",
	AccessKeySecret: "test-sk",
}

func TestCreateRAMUsers(t *testing.T) {
	tests := []struct {
		name              string
		mockAlibabaClient func(mockCtrl *gomock.Controller) *mockalibaba.MockClient
		setup             func(*testing.T) string
		verify            func(t *testing.T, manifestDir string)
		cleanup           func(*testing.T)
		generateOnly      bool
		expectError       bool
	}{
		{
			name:         "No CredReqs",
			generateOnly: true,
			mockAlibabaClient: func(mockCtrl *gomock.Controller) *mockalibaba.MockClient {
				mockAlibabaClient := mockalibaba.NewMockClient(mockCtrl)
				mockCreatePolicy(mockAlibabaClient)
				return mockAlibabaClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")
				return tempDirName
			},
			verify: func(t *testing.T, manifestDir string) {
				files, err := ioutil.ReadDir(manifestDir)
				require.NoError(t, err, "unexpected error listing files in manifestDir")
				assert.Zero(t, len(files), "Should be no files in manifestDir when no CredReqs to process")

			},
		},
		{
			name:         "Generate for one CredReq",
			generateOnly: true,
			mockAlibabaClient: func(mockCtrl *gomock.Controller) *mockalibaba.MockClient {
				mockAlibabaClient := mockalibaba.NewMockClient(mockCtrl)
				mockCreateUser(mockAlibabaClient)
				mockCreatePolicy(mockAlibabaClient)
				mockAttachPolicyToUser(mockAlibabaClient)
				mockCreateAccessKey(mockAlibabaClient)
				mockGetPolicy(mockAlibabaClient)
				mockCreatePolicyVersion(mockAlibabaClient)
				return mockAlibabaClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "errored while setting up test CredReq files")

				return tempDirName
			},
			verify: func(t *testing.T, manifestDir string) {
				files, err := ioutil.ReadDir(manifestDir)
				require.NoError(t, err, "unexpected error listing files in manifestDir")

				assert.Equal(t, 1, len(files), "The target user ak/sk secret manifest file should created for each CredReq")

			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAlibabaClient := test.mockAlibabaClient(mockCtrl)

			credReqDir := test.setup(t)
			defer os.RemoveAll(credReqDir)

			targetDir, err := ioutil.TempDir(os.TempDir(), "rampolicytest")
			require.NoError(t, err, "unexpected error creating target dir for test")
			defer os.RemoveAll(targetDir)

			manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)
			err = provisioning.EnsureDir(manifestsDir)
			require.NoError(t, err, "unexpected error creating manifests dir for test")
			defer os.RemoveAll(manifestsDir)

			err = createRAMUsers(mockAlibabaClient, testNamePrefix, credReqDir, targetDir, false)

			if test.expectError {
				require.Error(t, err, "expected error returned")
			} else {
				test.verify(t, manifestsDir)
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
    kind: AlibabaCloudProviderSpec
    statementEntries:
    - action:
      - ecs:CopySnapshot
      - ecs:DeleteDisk
      - ecs:DescribeInstanceAttribute
      - ecs:DescribeInstances
      effect: Allow
      resource: '*'
    - action:
      - nas:DescribeFileSystems
      - nas:DescribeMountTargets
      - nas:AddTags
      - nas:DescribeTags
      - nas:RemoveTags
      - nas:CreateFileSystem
      effect: Allow
      resource: '*'
  secretRef:
    namespace: %s
    name: %s`

	credReq := fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)

	f, err := ioutil.TempFile(targetDir, "testCredReq*.yaml")
	require.NoError(t, err, "error creating temp file for CredentialsRequest")
	defer f.Close()

	_, err = f.Write([]byte(credReq))
	require.NoError(t, err, "error while writing out contents of CredentialsRequest file")

	return nil
}

func mockCreateUser(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().CreateUser(gomock.Any()).Return(
		&ram.CreateUserResponse{
			User: mockUserInCreateUser,
		}, nil).AnyTimes()
}

func mockCreateAccessKey(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().CreateAccessKey(gomock.Any()).Return(
		&ram.CreateAccessKeyResponse{
			AccessKey: mockAccessKeyInCreateAccessKey,
		}, nil).AnyTimes()
}

func mockAttachPolicyToUser(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().AttachPolicyToUser(gomock.Any()).Return(
		&ram.AttachPolicyToUserResponse{}, nil,
	).AnyTimes()
}

func mockCreatePolicy(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().CreatePolicy(gomock.Any()).Return(
		&ram.CreatePolicyResponse{
			Policy: mockPolicyInCreatePolicy,
		}, nil).AnyTimes()
}

func mockGetPolicy(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().GetPolicy(gomock.Any()).Return(
		&ram.GetPolicyResponse{
			Policy: mockPolicyInGetPolicy,
		}, nil).AnyTimes()
}

func mockCreatePolicyVersion(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().CreatePolicyVersion(gomock.Any()).Return(
		&ram.CreatePolicyVersionResponse{
			PolicyVersion: mockPolicyVersionInCreatePolicyVersion,
		}, nil).AnyTimes()
}

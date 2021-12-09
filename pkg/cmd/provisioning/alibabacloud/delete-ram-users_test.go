package alibabacloud

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/golang/mock/gomock"
	mockalibaba "github.com/openshift/cloud-credential-operator/pkg/alibabacloud/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockPolicyInListPoliciesForUser = ram.PolicyInListPoliciesForUser{
	PolicyName:     "alibaba-mock-default-test",
	PolicyType:     "Custom",
	Description:    "alibaba-mock-test",
	DefaultVersion: "v1",
	AttachDate:     "2021-01-23T12:33:18Z",
}

var mockPoliciesInListPoliciesForUser = ram.PoliciesInListPoliciesForUser{
	Policy: []ram.PolicyInListPoliciesForUser{mockPolicyInListPoliciesForUser},
}

func TestDetachRAMPolicy(t *testing.T) {
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
				mockDetachPolicyFromUser(mockAlibabaClient)
				return mockAlibabaClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")
				return tempDirName
			},
			expectError: false,
		},
		{
			name:         "detach ram policy for one CredReq",
			generateOnly: true,
			mockAlibabaClient: func(mockCtrl *gomock.Controller) *mockalibaba.MockClient {
				mockAlibabaClient := mockalibaba.NewMockClient(mockCtrl)
				mockDetachPolicyFromUser(mockAlibabaClient)
				mockDeletePolicy(mockAlibabaClient)
				mockListPoliciesForUser(mockAlibabaClient)
				mockListPolicyVersions(mockAlibabaClient)
				mockListAccessKeys(mockAlibabaClient)
				mockDeleteUser(mockAlibabaClient)
				return mockAlibabaClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", tempDirName)
				require.NoError(t, err, "errored while setting up test CredReq files")

				return tempDirName
			},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAlibabaClient := test.mockAlibabaClient(mockCtrl)

			credReqDir := test.setup(t)
			defer os.RemoveAll(credReqDir)

			err := deleteRAMUsers(mockAlibabaClient, testNamePrefix, credReqDir)
			if test.expectError {
				require.Error(t, err, "expected error returned")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func mockDeletePolicy(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().DeletePolicy(gomock.Any()).Return(
		&ram.DeletePolicyResponse{}, nil).AnyTimes()
}

func mockDeleteUser(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().DeleteUser(gomock.Any()).Return(
		&ram.DeleteUserResponse{}, nil).AnyTimes()
}

func mockDetachPolicyFromUser(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().DetachPolicyFromUser(gomock.Any()).Return(
		&ram.DetachPolicyFromUserResponse{}, nil,
	).AnyTimes()
}

func mockListPoliciesForUser(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().ListPoliciesForUser(gomock.Any()).Return(
		&ram.ListPoliciesForUserResponse{
			Policies: mockPoliciesInListPoliciesForUser,
		}, nil).AnyTimes()
}

func mockListPolicyVersions(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().ListPolicyVersions(gomock.Any()).Return(
		&ram.ListPolicyVersionsResponse{}, nil,
	).AnyTimes()
}

func mockListAccessKeys(mockAlibabaClient *mockalibaba.MockClient) {
	mockAlibabaClient.EXPECT().ListAccessKeys(gomock.Any()).Return(
		&ram.ListAccessKeysResponse{}, nil,
	).AnyTimes()
}

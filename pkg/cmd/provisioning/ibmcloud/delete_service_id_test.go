package ibmcloud

import (
	"fmt"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"

	mockibmcloud "github.com/openshift/cloud-credential-operator/pkg/ibmcloud/mock"
)

func Test_deleteServiceIDCmd(t *testing.T) {
	type args struct {
		cmd  *cobra.Command
		args []string
	}
	tests := []struct {
		name        string
		args        args
		expectError string
	}{
		{
			name:        "CreateSharedSecretsCmd with unset API key environment variable should fail",
			expectError: "environment variable not set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := deleteServiceIDCmd(tt.args.cmd, tt.args.args)
			if tt.expectError == "" {
				assert.NoError(t, err)
			} else {
				assert.Containsf(t, err.Error(), tt.expectError, "expected error containing %q, got %s", tt.expectError, err)
			}
		})
	}
}

func Test_deleteServiceIDs(t *testing.T) {
	tests := []struct {
		name               string
		mockIBMCloudClient func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient
		setup              func(*testing.T) string
		force              bool
		expectError        string
	}{
		{
			// Tests the delete-service-id command without any CredReqs present in the credentials-requests-dir directory.
			name: "deleteServiceIDs No CredReqs",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockDeleteServiceID(mockIBMCloudClient, 0, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")
				return tempDirName
			},
		},
		{
			// Tests the delete-service-id command with one CredReq
			name: "deleteServiceIDs for one CredReq",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "name-namespace1-secret-name", 1, false)
				mockDeleteServiceID(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secret-name-0", tempDirName)

				return tempDirName
			},
		},
		{
			// Tests the delete-service-id command with more than one service ID with the same name, this will throw
			// an error message without the force option
			name: "deleteServiceIDs for a CredReq with multiple service ids with same name",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDWithSameName(mockIBMCloudClient, "name-namespace1-secret-name", 2, false)
				mockDeleteServiceID(mockIBMCloudClient, 0, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secret-name", tempDirName)

				return tempDirName
			},
			expectError: "more than one ServiceIDs present",
		},
		{
			// Tests the delete-service-id command with more than one service ID with the same name, this will throw
			// an error message with the force option
			name:  "deleteServiceIDs for a CredReq with multiple service ids with same name with force option",
			force: true,
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDWithSameName(mockIBMCloudClient, "name-namespace1-secret-name", 2, false)
				mockDeleteServiceID(mockIBMCloudClient, 2, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secret-name", tempDirName)

				return tempDirName
			},
		},
		{
			// Tests the delete-service-id command when failed to listServiceIDs
			name: "deleteServiceIDs when failed to listServiceIDs",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "name-namespace1-secret-name", 1, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secret-name-0", tempDirName)

				return tempDirName
			},
			expectError: "Error listing Service Ids",
		},
		{
			// Tests the delete-service-id command when failed to DeleteServiceID
			name: "deleteServiceIDs when failed to DeleteServiceID",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "name-namespace1-secret-name", 1, false)
				mockDeleteServiceID(mockIBMCloudClient, 1, true)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secret-name-0", tempDirName)

				return tempDirName
			},
			expectError: "Failed to delete the serviceIDs",
		},
		{
			// Tests the delete-service-id command when no matching service ID found, in this case command will just run
			// fine without any error
			name: "deleteServiceIDs when no matching service ID found",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, "", 0, false)
				return mockIBMCloudClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, "firstcredreq", "namespace1", "secret-name-0", tempDirName)

				return tempDirName
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockIBMCloudClient := tt.mockIBMCloudClient(mockCtrl)

			credReqDir := tt.setup(t)
			defer os.RemoveAll(credReqDir)

			err := deleteServiceIDs(mockIBMCloudClient, "1234", "name", credReqDir, tt.force)
			if tt.expectError == "" {
				assert.NoError(t, err)
			} else {
				assert.Containsf(t, err.Error(), tt.expectError, "expected error containing %q, got %s", tt.expectError, err)
			}
		})
	}
}

func mockListServiceIDWithSameName(client *mockibmcloud.MockClient, name string, count int, fail bool) {
	var err error
	if fail {
		err = fmt.Errorf(core.ERRORMSG_NO_AUTHENTICATOR)
	}
	list := &iamidentityv1.ServiceIDList{
		Serviceids: []iamidentityv1.ServiceID{},
	}
	for i := 0; i < count; i++ {
		list.Serviceids = append(list.Serviceids,
			iamidentityv1.ServiceID{
				Name: core.StringPtr(name),
				ID:   core.StringPtr("ServiceId-" + uuid.New().String()),
			})
	}
	client.EXPECT().ListServiceID(gomock.Any()).Return(list, nil, err).Times(1)
}

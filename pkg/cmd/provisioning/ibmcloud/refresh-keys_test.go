package ibmcloud

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	mockibmcloud "github.com/openshift/cloud-credential-operator/pkg/ibmcloud/mock"
)

var (
	testCRName          = "testingCR"
	testAccountID       = "123"
	testName            = "testing"
	targetNamespace     = "namespace1"
	targetSecretPrefix  = "secret"
	targetSecretName    = targetSecretPrefix + "-0"
	testServiceIDprefix = testName + "-" + targetNamespace + "-" + targetSecretPrefix
)

func Test_refreshKeys(t *testing.T) {
	tests := []struct {
		name               string
		mockIBMCloudClient func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient
		fakeKubeClient     func() *fake.Clientset
		setup              func(*testing.T) string
		resourceGroupName  string
		create             bool
		expectError        string
	}{
		{
			name: "with one CredReq",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 1, false, 2)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockListAPIKeys(mockIBMCloudClient, 2, false)
				mockDeleteAPIKey(mockIBMCloudClient, false, 1)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				fakeClient := fake.NewSimpleClientset(
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: targetSecretName, Namespace: targetNamespace}})

				fakeClient.PrependReactor("patch", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, nil
				})
				return fakeClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
		},
		{
			name: "with no service ID exist",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 0, false, 1)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "does not exist, rerun with --create flag to create it",
		},
		{
			name: "with no service ID exist with --create, --resource-group-name flag",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListResourceGroups(mockIBMCloudClient, true, false)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 0, false, 2)
				mockCreateServiceID(mockIBMCloudClient, 1, false)
				mockCreatePolicy(mockIBMCloudClient, 1, false)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockListAPIKeys(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				fakeClient := fake.NewSimpleClientset()
				fakeClient.PrependReactor("patch", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, nil
				})
				return fakeClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			resourceGroupName: "resource-group-test",
			create:            true,
		},
		{
			name: "with more than one service ID with same name",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDWithSameName(mockIBMCloudClient, "service-id", 2, false)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "more than one ServiceID found",
		},
		{
			name: "failed to list serviceID",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceID(mockIBMCloudClient, testServiceIDprefix, 0, true)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "Failed to check an existance for the ServiceID",
		},
		{
			name: "failed to create api keys",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 1, false, 2)
				mockCreateAPIKey(mockIBMCloudClient, 1, true)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "Failed to create API Key for ServiceID",
		},
		{
			name: "failed to list api keys",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 1, false, 2)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockListAPIKeys(mockIBMCloudClient, 1, true)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				fakeClient := fake.NewSimpleClientset()
				fakeClient.PrependReactor("patch", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, nil
				})
				return fakeClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "Failed to ListAPIKeys",
		},
		{
			name: "failed to create k8s secret",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 1, false, 2)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				fakeClient := fake.NewSimpleClientset()
				fakeClient.PrependReactor("patch", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("failed to patch the secret")
				})
				return fakeClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "Failed to create/update secret",
		},
		{
			name: "failed to delete the api key",
			mockIBMCloudClient: func(mockCtrl *gomock.Controller) *mockibmcloud.MockClient {
				mockIBMCloudClient := mockibmcloud.NewMockClient(mockCtrl)
				mockListServiceIDTimes(mockIBMCloudClient, testServiceIDprefix, 1, false, 2)
				mockCreateAPIKey(mockIBMCloudClient, 1, false)
				mockListAPIKeys(mockIBMCloudClient, 2, false)
				mockDeleteAPIKey(mockIBMCloudClient, true, 1)
				return mockIBMCloudClient
			},
			fakeKubeClient: func() *fake.Clientset {
				fakeClient := fake.NewSimpleClientset()
				fakeClient.PrependReactor("patch", "secrets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, nil
				})
				return fakeClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				testCredentialsRequest(t, testCRName, targetNamespace, targetSecretName, tempDirName)

				return tempDirName
			},
			expectError: "Failed to remove the stale API Keys",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockIBMCloudClient := tt.mockIBMCloudClient(mockCtrl)
			fakeKubeClient := tt.fakeKubeClient()

			credReqDir := tt.setup(t)
			defer os.RemoveAll(credReqDir)

			err := refreshKeys(mockIBMCloudClient, fakeKubeClient, &testAccountID, testName, tt.resourceGroupName, credReqDir, tt.create, false)
			if tt.expectError == "" {
				assert.NoError(t, err)
			} else {
				assert.Containsf(t, err.Error(), tt.expectError, "expected error containing %q, got %s", tt.expectError, err)
			}
		})
	}
}

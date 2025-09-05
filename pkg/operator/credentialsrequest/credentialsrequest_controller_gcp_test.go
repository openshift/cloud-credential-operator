/*
Copyright 2019 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package credentialsrequest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/api/cloudresourcemanager/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	mintergcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/gcp/actuator"
	mockgcp "github.com/openshift/cloud-credential-operator/pkg/gcp/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	gcpconst "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testRootGCPAuth                  = "ROOTAUTH"
	testReadOnlyGCPAuth              = "READONLYAUTH"
	testServiceAccountKeyPrivateData = "SECRET SERVICE ACCOUNT KEY DATA"
	testOldPassthroughPrivateData    = "OLD SERVICE ACCOUNT KEY DATA"
	testGCPServiceAccountID          = "a-test-svc-acct"
	testCustomRoleID                 = "a-test-role-id"
	testRoleName                     = "roles/appengine.appAdmin"
	testCustomRoleName               = "projects/test-GCP-project/roles/a-test-role-id"
	testServiceAPIName               = "appengine.googleapis.com"
	testGCPProjectName               = "test-GCP-project"
	testServiceAccountKeyName        = "testGCPKeyName"
)

var (
	testRolePermissions = []string{
		"appengine.applications.get",
	}

	emptyPolicyBindings = []*cloudresourcemanager.Binding{}

	testValidPolicyBindings = []*cloudresourcemanager.Binding{
		{
			Members: []string{
				fmt.Sprintf("serviceAccount:%s@%s.iam.gserviceaccount.com", testGCPServiceAccountID, testGCPProjectName),
			},
			Role: testRoleName,
		},
	}
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestCredentialsRequestGCPReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name              string
		existing          []runtime.Object
		existingAdmin     []runtime.Object
		expectErr         bool
		mockRootGCPClient func(mockCtrl *gomock.Controller) *mockgcp.MockClient
		mockReadGCPClient func(mockCtrl *gomock.Controller) *mockgcp.MockClient
		validate          func(client.Client, *testing.T)
		// Expected conditions on the credentials request:
		expectedConditions []ExpectedCondition
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []ExpectedCOCondition
	}{
		{
			name: "new credential",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needsupdate
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				// create service account
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, nil)
				mockSetProjectIamPolicy(mockGCPClient)
				mockListServiceAccountKeysEmpty(mockGCPClient)
				mockCreateServiceAccountKey(mockGCPClient, "")

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testServiceAccountKeyPrivateData, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "new credential with permissions set to create custom role",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequestWithPermissions(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needsupdate
				mockListServicesEnabled(mockGCPClient)

				// create custom role
				mockGetRole(mockGCPClient)
				mockGetRoleFailed(mockGCPClient)
				mockCreateRole(mockGCPClient)

				// create service account
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, nil)
				mockSetProjectIamPolicy(mockGCPClient)
				mockListServiceAccountKeysEmpty(mockGCPClient)
				mockCreateServiceAccountKey(mockGCPClient, "")

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testServiceAccountKeyPrivateData, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "new credential cluster has no infra name",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(""),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				// create serviceaccount
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, nil)
				mockSetProjectIamPolicy(mockGCPClient)
				mockListServiceAccountKeysEmpty(mockGCPClient)
				mockCreateServiceAccountKey(mockGCPClient, "")

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testServiceAccountKeyPrivateData, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "new credential no root creds available",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				return mockGCPClient
			},
			expectErr: true,
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
				cr := getCredRequest(c)
				assert.False(t, cr.Status.Provisioned)
			},
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "new credential only read-only creds available",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),

				// only the read-only creds exist
				testGCPCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-gcp-ro-creds", testReadOnlyGCPAuth),
			},
			existingAdmin: []runtime.Object{},
			mockReadGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetProjectName(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)

				return mockGCPClient
			},
			expectErr: true,
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
				cr := getCredRequest(c)
				assert.False(t, cr.Status.Provisioned)
			},
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionTrue,
				},
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.CredentialsProvisionFailure,
					reason:        "CredentialsProvisionFailure",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "cred missing access key exists", // expect old key(s) deleted, new key created/saved
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				// new service account key
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, testValidPolicyBindings)
				mockListServiceAccountKeys(mockGCPClient, testServiceAccountKeyName)
				mockDeleteServiceAccountKey(mockGCPClient, testServiceAccountKeyName)
				mockCreateServiceAccountKey(mockGCPClient, "NEW PRIVATE DATA")

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, "NEW PRIVATE DATA", string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				annotation := fmt.Sprintf("%s/%s", testNamespace, testCRName)
				assert.Equal(t, annotation, targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				cr := getCredRequest(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred exists access key missing",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testServiceAccountKeyPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)

				// create service account key
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, testValidPolicyBindings)
				mockListServiceAccountKeysEmpty(mockGCPClient)
				mockCreateServiceAccountKey(mockGCPClient, "NEW AUTH KEY DATA")

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, "NEW AUTH KEY DATA", string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				annotation := fmt.Sprintf("%s/%s", testNamespace, testCRName)
				assert.Equal(t, annotation, targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				cr := getCredRequest(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred exists but service account is deleted",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testProvisionedGCPCredentialsRequest(t),
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
				testGCPCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-gcp-ro-creds", testReadOnlyGCPAuth),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testServiceAccountKeyPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetDeletedServiceAccount(mockGCPClient)

				// create service account key
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetDeletedServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, testValidPolicyBindings)
				mockListServiceAccountKeys(mockGCPClient, testServiceAccountKeyName)
				mockCreateServiceAccount(mockGCPClient)
				mockSetProjectIamPolicy(mockGCPClient)
				mockDeleteServiceAccountKey(mockGCPClient, testServiceAccountKeyName)
				mockCreateServiceAccountKey(mockGCPClient, "NEW AUTH KEY DATA")

				return mockGCPClient
			},
			mockReadGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)

				// needs update
				mockGetProjectName(mockGCPClient)
				mockGetServiceAccountFailed(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, "NEW AUTH KEY DATA", string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				annotation := fmt.Sprintf("%s/%s", testNamespace, testCRName)
				assert.Equal(t, annotation, targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				cr := getCredRequest(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred minted and up to date and secret exist without root creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testClusterVersion(),
				testInfrastructure(testInfraName),

				// already minted, last synced 2 hours ago
				func() *minterv1.CredentialsRequest {
					cr := testGCPCredentialsRequest(t)
					cr.Status.Provisioned = true
					cr.Status.LastSyncTimestamp = &metav1.Time{Time: time.Now().Add(-2 * time.Hour)}

					return cr
				}(),

				// target secret exists
				createTestNamespace(testSecretNamespace),
				testGCPCredsSecret(testSecretNamespace, testSecretName, `{"private_key_id": "fakeServiceAccountID"}`),

				// only the read-only creds exist
				testGCPCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-gcp-ro-creds", testReadOnlyGCPAuth),
			},
			existingAdmin: []runtime.Object{},
			mockReadGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetProjectName(mockGCPClient)
				mockListServiceAccountKeys(mockGCPClient, "fakeServiceAccountID")
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, testValidPolicyBindings)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCredRequest(c)

				lastSynced := cr.Status.LastSyncTimestamp.Time
				assert.WithinDuration(t, time.Now(), lastSynced, time.Second*5, "expected a recent last synced status")
			},
		},
		{
			name: "updated cred with only read only creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testClusterVersion(),
				testInfrastructure(testInfraName),

				// already minted, last synced 2 hours ago
				func() *minterv1.CredentialsRequest {
					cr := testGCPCredentialsRequest(t)
					cr.Status.Provisioned = true
					cr.Status.LastSyncTimestamp = &metav1.Time{Time: time.Now().Add(-2 * time.Hour)}

					return cr
				}(),

				// target secret exists
				createTestNamespace(testSecretNamespace),
				testGCPCredsSecret(testSecretNamespace, testSecretName, `{"private_key_id": "fakeServiceAccountID"}`),

				// only the read-only creds exist
				testGCPCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-gcp-ro-creds", testReadOnlyGCPAuth),
			},
			existingAdmin: []runtime.Object{},
			mockReadGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetProjectName(mockGCPClient)
				mockListServiceAccountKeys(mockGCPClient, "fakeServiceAccountID")
				mockGetServiceAccount(mockGCPClient)

				// return a present IAM policy binding list that doesn't match the current credReq spec
				// so that we need the root creds to perform IAM modifications
				mockGetProjectIamPolicy(mockGCPClient, []*cloudresourcemanager.Binding{
					{
						Members: []string{
							fmt.Sprintf("serviceAccount:%s@%s.iam.gserviceaccount.com", testGCPServiceAccountID, testGCPProjectName),
						},
						Role: "role/outOfDateRoleBinding",
					},
				})

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCredRequest(c)

				assert.False(t, cr.Status.Provisioned, "expected credreq to be marked unprovisioned")
			},
			expectErr: true,
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.CredentialsProvisionFailure,
					reason:        "CredentialsProvisionFailure",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "updated permissions for provisioned credentials request",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testClusterVersion(),
				testInfrastructure(testInfraName),

				// already minted, last synced 2 hours ago
				func() *minterv1.CredentialsRequest {
					cr := testGCPCredentialsRequestWithPermissions(t)
					gcpStatus, err := minterv1.Codec.EncodeProviderStatus(
						&minterv1.GCPProviderStatus{
							TypeMeta: metav1.TypeMeta{
								Kind: "GCPProviderSpec",
							},
							ServiceAccountID: testGCPServiceAccountID,
							RoleID:           testCustomRoleID,
						},
					)
					if err != nil {
						t.Logf("error encoding: %v", err)
						t.FailNow()
						return nil
					}

					cr.Status.ProviderStatus = gcpStatus
					cr.Status.LastSyncTimestamp = &metav1.Time{Time: time.Now().Add(-2 * time.Hour)}

					return cr
				}(),

				// target secret exists
				createTestNamespace(testSecretNamespace),
				testGCPCredsSecret(testSecretNamespace, testSecretName, `{"private_key_id": "testGCPKeyName"}`),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needsupdate
				mockListServicesEnabled(mockGCPClient)

				// update custom role
				mockGetRole(mockGCPClient)
				mockGetCustomRoleSuccess(mockGCPClient)
				mockUpdateRole(mockGCPClient)

				// create service account
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, nil)
				mockSetProjectIamPolicy(mockGCPClient)
				mockListServiceAccountKeys(mockGCPClient, testServiceAccountKeyName)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, `{"private_key_id": "testGCPKeyName"}`, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "cred deletion",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequestWithDeletionTimestamp(t),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testServiceAccountKeyPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, testValidPolicyBindings)
				mockSetProjectIamPolicy(mockGCPClient)
				mockDeleteServiceAccount(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
			},
		},
		{
			name: "cred deletion when permissions are set in CR and custom role is created",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequestWithPermissionsWithDeletionTimestamp(t),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testServiceAccountKeyPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockGetServiceAccount(mockGCPClient)
				mockGetProjectIamPolicy(mockGCPClient, testValidPolicyBindings)
				mockSetProjectIamPolicy(mockGCPClient)
				mockDeleteServiceAccount(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
			},
		},
		{
			name: "failed to mint condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				// create service account
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockGetServiceAccountFailed(mockGCPClient)

				return mockGCPClient
			},
			expectErr: true,
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.CredentialsProvisionFailure,
					reason:        "CredentialsProvisionFailure",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "cred deletion failure condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequestWithDeletionTimestamp(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecret("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockGetServiceAccountFailed(mockGCPClient)

				return mockGCPClient
			},
			expectErr: true,
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.CredentialsDeprovisionFailure,
					reason:        "CloudCredDeprovisionFailure",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "new cred passthrough",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecretPassthrough("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockQueryableTestablePermissions(mockGCPClient)
				mockTestIamPermissions(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testRootGCPAuth, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "new cred passthrough fail permissions",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecretPassthrough("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockTestIamPermissionsFail(mockGCPClient)

				return mockGCPClient
			},
			expectErr: true,
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
				cr := getCredRequest(c)
				assert.False(t, cr.Status.Provisioned)
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.CredentialsProvisionFailure,
					reason:        "CredentialsProvisionFailure",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "existing cr up to date",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testGCPPassthroughCredentialsRequest(t),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecretPassthrough("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockTestIamPermissions(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testRootGCPAuth, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "existing secret has old secret content",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testGCPPassthroughCredentialsRequest(t),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testOldPassthroughPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			existingAdmin: []runtime.Object{
				testGCPCredsSecretPassthrough("kube-system", constants.GCPCloudCredSecretName, testRootGCPAuth),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)
				mockTestIamPermissions(mockGCPClient)

				// sync passthrough
				mockGetRole(mockGCPClient)
				mockTestIamPermissions(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// existing secret has old/unchanged content
				assert.Equal(t, testRootGCPAuth, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockRootGCPClient := mockgcp.NewMockClient(mockCtrl)
			if test.mockRootGCPClient != nil {
				mockRootGCPClient = test.mockRootGCPClient(mockCtrl)
			}

			mockReadGCPClient := mockgcp.NewMockClient(mockCtrl)
			if test.mockReadGCPClient != nil {
				mockReadGCPClient = test.mockReadGCPClient(mockCtrl)
			}

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(&minterv1.CredentialsRequest{}).
				WithRuntimeObjects(test.existing...).Build()
			fakeAdminClient := fake.NewClientBuilder().
				WithRuntimeObjects(test.existingAdmin...).Build()
			rcr := &ReconcileCredentialsRequest{
				Client:      fakeClient,
				AdminClient: fakeAdminClient,
				Actuator: &actuator.Actuator{
					ProjectName:    testGCPProjectName,
					Client:         fakeClient,
					RootCredClient: fakeAdminClient,
					GCPClientBuilder: func(name string, jsonAUTH []byte, endpoints []configv1.GCPServiceEndpoint) (mintergcp.Client, error) {
						if string(jsonAUTH) == testRootGCPAuth {
							return mockRootGCPClient, nil
						} else if string(jsonAUTH) == testReadOnlyGCPAuth {
							return mockReadGCPClient, nil
						}
						return nil, fmt.Errorf("unknown client to return for provided auth data")
					},
				},
				platformType: configv1.GCPPlatformType,
			}

			_, err := rcr.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testCRName,
					Namespace: testNamespace,
				},
			})

			if test.validate != nil {
				test.validate(fakeClient, t)
			}

			if err != nil && !test.expectErr {
				t.Errorf("Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}

			cr := getCredRequest(fakeClient)
			for _, condition := range test.expectedConditions {
				foundCondition := utils.FindCredentialsRequestCondition(cr.Status.Conditions, condition.conditionType)
				assert.NotNil(t, foundCondition)
				assert.Exactly(t, condition.status, foundCondition.Status)
				assert.Exactly(t, condition.reason, foundCondition.Reason)
			}

			if test.expectedCOConditions != nil {
				logger := log.WithFields(log.Fields{"controller": controllerName})
				currentConditions, err := rcr.GetConditions(logger)
				require.NoError(t, err, "failed getting conditions")

				for _, expectedCondition := range test.expectedCOConditions {
					foundCondition := utils.FindClusterOperatorCondition(currentConditions, expectedCondition.conditionType)
					require.NotNil(t, foundCondition)
					assert.Equal(t, string(expectedCondition.status), string(foundCondition.Status), "condition %s had unexpected status", expectedCondition.conditionType)
					if expectedCondition.reason != "" {
						assert.Exactly(t, expectedCondition.reason, foundCondition.Reason)
					}
				}
			}
		})
	}
}

func testGCPCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	cr := testGCPPassthroughCredentialsRequest(t)

	gcpStatus, err := minterv1.Codec.EncodeProviderStatus(
		&minterv1.GCPProviderStatus{
			TypeMeta: metav1.TypeMeta{
				Kind: "GCPProviderSpec",
			},
			ServiceAccountID: testGCPServiceAccountID,
		},
	)
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	cr.Status.ProviderStatus = gcpStatus
	return cr
}

func testProvisionedGCPCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	cr := testGCPCredentialsRequest(t)
	cr.Status.Provisioned = true
	return cr
}

func testGCPCredentialsRequestWithDeletionTimestamp(t *testing.T) *minterv1.CredentialsRequest {
	cr := testGCPCredentialsRequest(t)
	now := metav1.Now()
	cr.DeletionTimestamp = &now
	cr.Status.Provisioned = true
	return cr
}

func testGCPCredentialsRequestWithPermissionsWithDeletionTimestamp(t *testing.T) *minterv1.CredentialsRequest {
	cr := testGCPCredentialsRequestWithPermissions(t)

	gcpStatus, err := minterv1.Codec.EncodeProviderStatus(
		&minterv1.GCPProviderStatus{
			TypeMeta: metav1.TypeMeta{
				Kind: "GCPProviderSpec",
			},
			ServiceAccountID: testGCPServiceAccountID,
			RoleID:           testCustomRoleID,
		},
	)
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}
	cr.Status.ProviderStatus = gcpStatus

	now := metav1.Now()
	cr.DeletionTimestamp = &now
	cr.Status.Provisioned = true
	return cr
}

func testGCPPassthroughCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	gcpProvSpec, err := minterv1.Codec.EncodeProviderSpec(
		&minterv1.GCPProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "GCPProviderSpec",
			},
			PredefinedRoles: []string{
				testRoleName,
			},
		},
	)
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	return &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testCRName,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
			Generation:  testCRGeneration,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			ProviderSpec: gcpProvSpec,
		},
	}
}

func testGCPCredsSecretPassthrough(namespace, name, jsonAUTH string) *corev1.Secret {
	s := testGCPCredsSecret(namespace, name, jsonAUTH)
	s.Annotations[constants.AnnotationKey] = constants.PassthroughAnnotation
	return s
}

func testGCPCredsSecret(namespace, name, jsonAUTH string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.MintAnnotation,
			},
		},
		Data: map[string][]byte{
			gcpconst.GCPAuthJSONKey: []byte(jsonAUTH),
		},
	}
	return s
}

func testGCPCredentialsRequestWithPermissions(t *testing.T) *minterv1.CredentialsRequest {
	gcpProvSpec, err := minterv1.Codec.EncodeProviderSpec(
		&minterv1.GCPProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "GCPProviderSpec",
			},
			Permissions: []string{
				testServiceAPIName,
			},
			PredefinedRoles: []string{
				testRoleName,
			},
		},
	)
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	return &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testCRName,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
			Generation:  testCRGeneration,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			ProviderSpec: gcpProvSpec,
		},
	}
}

func mockGetProjectName(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetProjectName().AnyTimes().Return(testGCPProjectName)
}

func mockGetServiceAccount(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).AnyTimes().Return(&iamadminpb.ServiceAccount{
		Name:  testGCPServiceAccountID,
		Email: fmt.Sprintf("%s@%s.iam.gserviceaccount.com", testGCPServiceAccountID, testGCPProjectName),
	}, nil)
}

func mockGetServiceAccountFailed(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("TEST ERROR"))
}

func mockGetDeletedServiceAccount(mockGCPClient *mockgcp.MockClient) {
	serviceAccountNotFoundError := status.Error(codes.NotFound, "service account not found")
	mockGCPClient.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(nil, serviceAccountNotFoundError)
}

func mockGetProjectIamPolicy(mockGCPClient *mockgcp.MockClient, bindings []*cloudresourcemanager.Binding) {
	mockBindings := emptyPolicyBindings
	if len(bindings) > 0 {
		mockBindings = bindings
	}
	mockGCPClient.EXPECT().GetProjectIamPolicy(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.Policy{
		Bindings: mockBindings,
	}, nil).MaxTimes(2)
}

func mockGetRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetRole(gomock.Any(), &iamadminpb.GetRoleRequest{
		Name: testRoleName,
	}).Return(&iamadminpb.Role{
		Name:                testRoleName,
		IncludedPermissions: testRolePermissions,
	}, nil).MaxTimes(2)
}

func mockGetCustomRoleSuccess(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetRole(gomock.Any(), &iamadminpb.GetRoleRequest{
		Name: testCustomRoleName,
	}).Return(&iamadminpb.Role{
		Name:                testCustomRoleName,
		IncludedPermissions: testRolePermissions,
	}, nil)
}

func mockGetRoleFailed(mockGCPClient *mockgcp.MockClient) {
	roleNotFoundError := status.Error(codes.NotFound, "role not found")
	mockGCPClient.EXPECT().GetRole(gomock.Any(), gomock.Any()).Return(nil, roleNotFoundError)
}

func mockCreateRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().CreateRole(gomock.Any(), gomock.Any()).Return(&iamadminpb.Role{
		Name:                testCustomRoleName,
		IncludedPermissions: testRolePermissions,
	}, nil)
}

func mockUpdateRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().UpdateRole(gomock.Any(), gomock.Any()).Return(&iamadminpb.Role{
		Name:                testCustomRoleName,
		IncludedPermissions: testRolePermissions,
	}, nil)
}

func mockDeleteRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().DeleteRole(gomock.Any(), gomock.Any()).Return(nil, nil)
}

func mockListServicesEnabled(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServicesEnabled().Return(map[string]bool{
		testServiceAPIName: true,
	}, nil)
}

func mockQueryableTestablePermissions(mockGCPClient *mockgcp.MockClient) {
	permResponse := []*iamadminpb.Permission{}

	for _, perm := range testRolePermissions {
		permResponse = append(permResponse, &iamadminpb.Permission{Name: perm})
	}
	mockGCPClient.EXPECT().QueryTestablePermissions(gomock.Any(), gomock.Any()).Return(&iamadminpb.QueryTestablePermissionsResponse{
		Permissions: permResponse,
	}, nil)
}

func mockTestIamPermissions(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().TestIamPermissions(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.TestIamPermissionsResponse{
		Permissions: testRolePermissions,
	}, nil).MaxTimes(2)
}

func mockTestIamPermissionsFail(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().TestIamPermissions(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.TestIamPermissionsResponse{
		Permissions: []string{"not.expected.permission"},
	}, nil)
}

func mockSetProjectIamPolicy(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().SetProjectIamPolicy(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.Policy{
		Bindings: emptyPolicyBindings,
	}, nil)
}

func mockDeleteServiceAccountKey(mockGCPClient *mockgcp.MockClient, customName string) {
	keyName := testServiceAccountKeyName
	if customName != "" {
		keyName = customName
	}
	mockGCPClient.EXPECT().DeleteServiceAccountKey(gomock.Any(), &iamadminpb.DeleteServiceAccountKeyRequest{Name: keyName}).Return(nil)
}

func mockListServiceAccountKeysEmpty(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServiceAccountKeys(gomock.Any(), gomock.Any()).Return(&iamadminpb.ListServiceAccountKeysResponse{}, nil)
}

func mockListServiceAccountKeys(mockGCPClient *mockgcp.MockClient, customName string) {
	keyName := testServiceAccountKeyName
	if customName != "" {
		keyName = customName
	}
	mockGCPClient.EXPECT().ListServiceAccountKeys(gomock.Any(), gomock.Any()).Return(&iamadminpb.ListServiceAccountKeysResponse{
		Keys: []*iamadminpb.ServiceAccountKey{
			{
				Name: keyName,
			},
		},
	}, nil).MaxTimes(2)
}

func mockDeleteServiceAccount(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().DeleteServiceAccount(gomock.Any(), gomock.Any()).Return(nil)
}

func mockCreateServiceAccount(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(&iamadminpb.ServiceAccount{
		DisplayName: testServiceAccountKeyName,
	}, nil)
}

func mockCreateServiceAccountKey(mockGCPClient *mockgcp.MockClient, privateKeyData string) {
	if privateKeyData == "" {
		privateKeyData = testServiceAccountKeyPrivateData
	}
	mockGCPClient.EXPECT().CreateServiceAccountKey(gomock.Any(), gomock.Any()).Return(&iamadminpb.ServiceAccountKey{
		PrivateKeyData: []byte(privateKeyData),
	}, nil)
}

func getCredRequestTargetSecret(c client.Client) *corev1.Secret {
	s := &corev1.Secret{}
	err := c.Get(context.TODO(), client.ObjectKey{Name: testSecretName, Namespace: testSecretNamespace}, s)
	if err != nil {
		return nil
	}
	return s
}

func getCredRequest(c client.Client) *minterv1.CredentialsRequest {
	cr := &minterv1.CredentialsRequest{}
	err := c.Get(context.TODO(), client.ObjectKey{Name: testCRName, Namespace: testNamespace}, cr)
	if err != nil {
		return nil
	}
	return cr
}

func getClusterOperator(c client.Client) *configv1.ClusterOperator {
	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: constants.CloudCredClusterOperatorName}}
	err := c.Get(context.TODO(), types.NamespacedName{Name: co.Name}, co)
	if err != nil {
		return nil
	}
	return co
}

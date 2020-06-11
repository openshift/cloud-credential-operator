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

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openshift/cloud-credential-operator/pkg/apis"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	mintergcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/gcp/actuator"
	mockgcp "github.com/openshift/cloud-credential-operator/pkg/gcp/mock"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
	gcpconst "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	"github.com/openshift/cloud-credential-operator/pkg/util/clusteroperator"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

const (
	testRootGCPAuth                  = "ROOTAUTH"
	testServiceAccountKeyPrivateData = "SECRET SERVICE ACCOUNT KEY DATA"
	testOldPassthroughPrivateData    = "OLD SERVICE ACCOUNT KEY DATA"
	testGCPServiceAccountID          = "a-test-svc-acct"
	testRoleName                     = "roles/appengine.appAdmin"
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
	apis.AddToScheme(scheme.Scheme)
	configv1.Install(scheme.Scheme)

	codec, err := minterv1.NewCodec()
	if err != nil {
		fmt.Printf("error creating codec: %v", err)
		t.FailNow()
		return
	}

	tests := []struct {
		name                        string
		existing                    []runtime.Object
		expectErr                   bool
		mockRootGCPClient           func(mockCtrl *gomock.Controller) *mockgcp.MockClient
		mockCredRequestSecretClient func(mockCtrl *gomock.Controller) *mockgcp.MockClient
		validate                    func(client.Client, *testing.T)
		// Expected conditions on the credentials request:
		expectedConditions []ExpectedCondition
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []ExpectedCOCondition
	}{
		{
			name: "new credential",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				if assert.NotNil(t, targetSecret, "expected non-empty target secret to exist") {
					assert.Equal(t, testServiceAccountKeyPrivateData, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				}
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorAvailable,
					status:        corev1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        corev1.ConditionFalse,
				},
			},
		},
		{
			name: "new credential cluster has no infra name",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(""),
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
				if assert.NotNil(t, targetSecret) {
					assert.Equal(t, testServiceAccountKeyPrivateData, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				}
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorAvailable,
					status:        corev1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        corev1.ConditionFalse,
				},
			},
		},
		{
			name: "new credential no root creds available",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
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
					conditionType: configv1.OperatorAvailable,
					status:        corev1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "cred missing access key exists", // expect old key(s) deleted, new key created/saved
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				if assert.NotNil(t, targetSecret) {
					assert.Equal(t, "NEW PRIVATE DATA", string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
					annotation := fmt.Sprintf("%s/%s", testNamespace, testCRName)
					assert.Equal(t, annotation, targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				}
				cr := getCredRequest(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred exists access key missing",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testServiceAccountKeyPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				// needs update
				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

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
				if assert.NotNil(t, targetSecret) {
					assert.Equal(t, "NEW AUTH KEY DATA", string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
					annotation := fmt.Sprintf("%s/%s", testNamespace, testCRName)
					assert.Equal(t, annotation, targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				}
				cr := getCredRequest(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred deletion",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequestWithDeletionTimestamp(t),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testServiceAccountKeyPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequestWithDeletionTimestamp(t),
				testGCPCredsSecret("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecretPassthrough("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockListServicesEnabled(mockGCPClient)

				mockGetRole(mockGCPClient)
				mockTestIamPermissions(mockGCPClient)

				return mockGCPClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				if assert.NotNil(t, targetSecret, "expected non-empty target secret to exist") {
					assert.Equal(t, testRootGCPAuth, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				}
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
				createTestNamespace(testSecretNamespace),
				testGCPCredentialsRequest(t),
				testGCPCredsSecretPassthrough("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				createTestNamespace(testSecretNamespace),
				testGCPPassthroughCredentialsRequest(t),
				testGCPCredsSecretPassthrough("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testRootGCPAuth),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				if assert.NotNil(t, targetSecret, "expected non-empty target secret to exist") {
					assert.Equal(t, testRootGCPAuth, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				}
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
				createTestNamespace(testSecretNamespace),
				testGCPPassthroughCredentialsRequest(t),
				testGCPCredsSecretPassthrough("kube-system", annotatorconst.GCPCloudCredSecretName, testRootGCPAuth),
				testGCPCredsSecret(testSecretNamespace, testSecretName, testOldPassthroughPrivateData),
				testClusterVersion(),
				testInfrastructure(testInfraName),
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
				if assert.NotNil(t, targetSecret, "expected non-empty target secret to exist") {
					// existing secret has old/unchanged content
					assert.Equal(t, testRootGCPAuth, string(targetSecret.Data[gcpconst.GCPAuthJSONKey]))
				}
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

			mockRootGCPClient := test.mockRootGCPClient(mockCtrl)

			mockSecretClient := mockgcp.NewMockClient(mockCtrl)
			if test.mockCredRequestSecretClient != nil {
				mockSecretClient = test.mockCredRequestSecretClient(mockCtrl)
			}

			fakeClient := fake.NewFakeClient(test.existing...)
			rcr := &ReconcileCredentialsRequest{
				Client: fakeClient,
				Actuator: &actuator.Actuator{
					Client: fakeClient,
					Codec:  codec,
					GCPClientBuilder: func(name string, jsonAUTH []byte) (mintergcp.Client, error) {
						if string(jsonAUTH) == testRootGCPAuth {
							return mockRootGCPClient, nil
						} else {
							return mockSecretClient, nil
						}
					},
				},
				platformType: configv1.GCPPlatformType,
			}
			clusteroperator.AddStatusHandler(rcr)

			_, err := rcr.Reconcile(reconcile.Request{
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

			for _, condition := range test.expectedCOConditions {
				co := getClusterOperator(fakeClient)
				assert.NotNil(t, co)
				foundCondition := findClusterOperatorCondition(co.Status.Conditions, condition.conditionType)
				assert.NotNil(t, foundCondition)
				assert.Equal(t, string(condition.status), string(foundCondition.Status), "condition %s had unexpected status", condition.conditionType)
				if condition.reason != "" {
					assert.Exactly(t, condition.reason, foundCondition.Reason)
				}
			}
		})
	}
}

func testGCPCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	cr := testGCPPassthroughCredentialsRequest(t)

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}

	gcpStatus, err := codec.EncodeProviderStatus(
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

func testGCPCredentialsRequestWithDeletionTimestamp(t *testing.T) *minterv1.CredentialsRequest {
	cr := testGCPCredentialsRequest(t)
	now := metav1.Now()
	cr.DeletionTimestamp = &now
	cr.Status.Provisioned = true
	return cr
}

func testGCPPassthroughCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}
	gcpProvSpec, err := codec.EncodeProviderSpec(
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
	s.Annotations[annotatorconst.AnnotationKey] = annotatorconst.PassthroughAnnotation
	return s
}

func testGCPCredsSecret(namespace, name, jsonAUTH string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				annotatorconst.AnnotationKey: annotatorconst.MintAnnotation,
			},
		},
		Data: map[string][]byte{
			gcpconst.GCPAuthJSONKey: []byte(jsonAUTH),
		},
	}
	return s
}

func mockGetProjectName(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetProjectName().AnyTimes().Return(testGCPProjectName)
}

func mockGetServiceAccount(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&iamadminpb.ServiceAccount{
		Name:  testGCPServiceAccountID,
		Email: fmt.Sprintf("%s@%s.iam.gserviceaccount.com", testGCPServiceAccountID, testGCPProjectName),
	}, nil)
}

func mockGetServiceAccountFailed(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("TEST ERROR"))
}

func mockGetProjectIamPolicy(mockGCPClient *mockgcp.MockClient, bindings []*cloudresourcemanager.Binding) {
	mockBindings := emptyPolicyBindings
	if len(bindings) > 0 {
		mockBindings = bindings
	}
	mockGCPClient.EXPECT().GetProjectIamPolicy(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.Policy{
		Bindings: mockBindings,
	}, nil)
}

func mockGetRole(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetRole(gomock.Any(), gomock.Any()).Return(&iamadminpb.Role{
		Name:                testRoleName,
		IncludedPermissions: testRolePermissions,
	}, nil)
}

func mockListServicesEnabled(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServicesEnabled().Return(map[string]bool{
		testServiceAPIName: true,
	}, nil)
}

func mockTestIamPermissions(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().TestIamPermissions(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.TestIamPermissionsResponse{
		Permissions: testRolePermissions,
	}, nil)
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
	}, nil)
}

func mockDeleteServiceAccount(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().DeleteServiceAccount(gomock.Any(), gomock.Any()).Return(nil)
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
	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: cloudCredClusterOperator}}
	err := c.Get(context.TODO(), types.NamespacedName{Name: co.Name}, co)
	if err != nil {
		return nil
	}
	return co
}

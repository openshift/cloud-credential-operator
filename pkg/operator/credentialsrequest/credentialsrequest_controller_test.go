/*
Copyright 2018 The OpenShift Authors.

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
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	minteraws "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/aws/actuator"
	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

var c client.Client

const (
	openshiftClusterIDKey = "openshiftClusterID"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

type ExpectedCondition struct {
	conditionType minterv1.CredentialsRequestConditionType
	reason        string
	status        corev1.ConditionStatus
}

type ExpectedCOCondition struct {
	conditionType configv1.ClusterStatusConditionType
	reason        string
	status        corev1.ConditionStatus
}

func TestCredentialsRequestReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// Utility function to get the test credentials request from the fake client
	getCR := func(c client.Client) *minterv1.CredentialsRequest {
		cr := &minterv1.CredentialsRequest{}
		err := c.Get(context.TODO(), client.ObjectKey{Name: testCRName, Namespace: testNamespace}, cr)
		if err == nil {
			return cr
		}
		return nil
	}

	getSecret := func(c client.Client) *corev1.Secret {
		secret := &corev1.Secret{}
		err := c.Get(context.TODO(), client.ObjectKey{Name: testSecretName, Namespace: testSecretNamespace}, secret)
		if err == nil {
			return secret
		}
		return nil
	}

	codec, err := minterv1.NewCodec()
	if err != nil {
		fmt.Printf("error creating codec: %v", err)
		t.FailNow()
		return
	}

	tests := []struct {
		name                string
		existing            []runtime.Object
		expectErr           bool
		mockRootAWSClient   func(mockCtrl *gomock.Controller) *mockaws.MockClient
		mockReadAWSClient   func(mockCtrl *gomock.Controller) *mockaws.MockClient
		mockSecretAWSClient func(mockCtrl *gomock.Controller) *mockaws.MockClient
		validate            func(client.Client, *testing.T)
		// Expected conditions on the credentials request:
		expectedConditions []ExpectedCondition
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []ExpectedCOCondition
	}{
		{
			name: "add finalizer",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				func() *minterv1.CredentialsRequest {
					cr := testCredentialsRequest(t)
					// Remove the finalizer
					cr.ObjectMeta.Finalizers = []string{}
					return cr
				}(),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				if cr == nil || !HasFinalizer(cr, minterv1.FinalizerDeprovision) {
					t.Errorf("did not get expected finalizer")
				}
				assert.False(t, cr.Status.Provisioned)
			},
		},
		{
			name: "new credential",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockCreateUser(mockAWSClient)
				mockPutUserPolicy(mockAWSClient)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID, testAWSSecretAccessKey)
				mockTagUser(mockAWSClient)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserNotFound(mockAWSClient)
				mockGetUserPolicyMissing(mockAWSClient)
				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
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
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(""),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockCreateUser(mockAWSClient)
				mockPutUserPolicy(mockAWSClient)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID, testAWSSecretAccessKey)
				mockTagUserLegacy(mockAWSClient)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserNotFound(mockAWSClient)
				mockGetUserPolicyMissing(mockAWSClient)
				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			// This tests the case where we create our own read only creds initially:
			name: "new credential no read-only creds available",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockCreateUser(mockAWSClient)
				mockPutUserPolicy(mockAWSClient)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID, testAWSSecretAccessKey)
				mockTagUser(mockAWSClient)
				// These calls should defer to the root AWS client because we have no ro creds:
				mockGetUserNotFound(mockAWSClient)
				mockGetUserPolicyMissing(mockAWSClient)
				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			// This indicates an error state.
			name: "new credential no root creds available",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				assert.Nil(t, targetSecret)
				cr := getCR(c)
				assert.False(t, cr.Status.Provisioned)
			},
			expectErr: true,
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "cred and secret exist user tagged",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred and secret exist user missing tag",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockTagUser(mockAWSClient)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserUntagged(mockAWSClient)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				return mockAWSClient
			},
			mockSecretAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred and secret exist no root creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testLegacyAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred missing access key exists",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID2, testAWSSecretAccessKey2)
				mockDeleteAccessKey(mockAWSClient, testAWSAccessKeyID)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID2,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey2,
					string(targetSecret.Data["aws_secret_access_key"]))
				assert.Equal(t, fmt.Sprintf("%s/%s", testNamespace, testCRName), targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred exists access key missing",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID2, testAWSSecretAccessKey2)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeysEmpty(mockAWSClient)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID2,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey2,
					string(targetSecret.Data["aws_secret_access_key"]))
				assert.Equal(t, fmt.Sprintf("%s/%s", testNamespace, testCRName), targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred exists but user is deleted",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testProvisionedCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID, testAWSSecretAccessKey)
				mockGetUser(mockAWSClient)
				mockCreateUser(mockAWSClient)
				mockTagUser(mockAWSClient)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserNotFound(mockAWSClient)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				assert.Equal(t, fmt.Sprintf("%s/%s", testNamespace, testCRName), targetSecret.Annotations[minterv1.AnnotationCredentialsRequest])

				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred exists credentials key missing",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testLegacyAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				require.Contains(t, targetSecret.Data, "credentials", "expected Secret to be updated with 'credentials' field")
				assert.Contains(t, string(targetSecret.Data["credentials"]), testAWSAccessKeyID, "didn't find access key data in credentials field")
				assert.Contains(t, string(targetSecret.Data["credentials"]), testAWSSecretAccessKey, "didn't find secret key data in credentials field")

				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "cred deletion",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequestWithDeletionTimestamp(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockDeleteUser(mockAWSClient)
				mockDeleteUserPolicy(mockAWSClient)
				mockDeleteAccessKey(mockAWSClient, testAWSAccessKeyID)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				assert.Nil(t, targetSecret)
			},
		},
		{
			name: "new passthrough credential",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testPassthroughCredentialsRequest(t),
				testPassthroughAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testRootAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testRootAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "existing passthrough credential",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testPassthroughCredentialsRequest(t),
				testPassthroughAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				// will simulate to check that the creds in the target secret actually satisfy the requested perms
				mockSimulatePrincipalPolicyPagesSuccess(mockAWSClient)
				return mockAWSClient
			},
			mockSecretAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "existing passthrough credential bypassing simulations",
			existing: []runtime.Object{
				testOperatorConfig(operatorv1.CloudCredentialsModePassthrough), // indicates that CCO should not perform permissions simulations
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testPassthroughCredentialsRequest(t),
				testPassthroughAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				return mockAWSClient
			},
			mockSecretAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "passthrough cred deletion",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testPassthroughCredentialsRequestWithDeletionTimestamp(t),
				testPassthroughAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
		},
		{
			name: "no namespace condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(testInfraName),
				testCredentialsRequest(t),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.MissingTargetNamespace,
					reason:        "NamespaceMissing",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "insufficient creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testInsufficientAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			expectErr: true,
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.InsufficientCloudCredentials,
					reason:        "CloudCredsInsufficient",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "failed to mint condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testClusterVersion(),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockFailedGetUser(mockAWSClient)
				return mockAWSClient
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
				testInfrastructure(testInfraName),
				testCredentialsRequestWithDeletionTimestamp(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret(testNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockDeleteUserPolicy(mockAWSClient)
				mockDeleteAccessKey(mockAWSClient, testAWSAccessKeyID)
				mockDeleteUserFailure(mockAWSClient)
				return mockAWSClient
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
			name: "skip AWS if recently synced",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequestWithRecentLastSync(t),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				assert.Equal(t, testTwentyMinuteOldTimestamp.Unix(), cr.Status.LastSyncTimestamp.Time.Unix())
			},
		},
		{
			name: "regenerate secret if missing",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				testClusterVersion(),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequestWithRecentLastSync(t),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				// delete the "old" (now missing secret) access key details
				mockDeleteAccessKey(mockAWSClient, testAWSAccessKeyID)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID2, testAWSSecretAccessKey2)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID2,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey2,
					string(targetSecret.Data["aws_secret_access_key"]))
			},
		},
		{
			name: "recently synced but modified",
			existing: func() []runtime.Object {
				objects := []runtime.Object{}
				objects = append(objects, testOperatorConfig(""))
				objects = append(objects, createTestNamespace(testNamespace))
				objects = append(objects, createTestNamespace(testSecretNamespace))

				cr := testCredentialsRequestWithRecentLastSync(t)
				cr.Generation = cr.Generation + 1 // rev the generation to trigger the sync
				objects = append(objects, cr)

				objects = append(objects, testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey))
				objects = append(objects, testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey))
				objects = append(objects, testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey))
				objects = append(objects, testClusterVersion())
				objects = append(objects, testInfrastructure(testInfraName))

				return objects
			}(),
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				assert.NotEqual(t, testTwentyMinuteOldTimestamp.Unix(), cr.Status.LastSyncTimestamp.Time.Unix())
			},
		},
		{
			name: "skip nonAWS credreq",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testGCPCredentialsRequest(t),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				return mockaws.NewMockClient(mockCtrl)
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				assert.False(t, cr.Status.Provisioned, "CRs for wrong cloud should be unprovisioned")
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.Ignored,
					reason:        "InfrastructureMismatch",
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "clear conditions when ignoring cred request",
			existing: []runtime.Object{
				testOperatorConfig(""),
				func() runtime.Object {
					cr := testGCPCredentialsRequest(t)
					for _, cond := range minterv1.FailureConditionTypes {
						cr.Status.Conditions = append(cr.Status.Conditions, minterv1.CredentialsRequestCondition{
							Type:   cond,
							Status: corev1.ConditionTrue,
						})
					}

					return cr
				}(),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				return mockaws.NewMockClient(mockCtrl)
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)

				// verify all the other conditions that would put CCO in a failed state are cleared
				for _, cond := range cr.Status.Conditions {
					if cond.Type != minterv1.Ignored {
						assert.Equal(t, corev1.ConditionFalse, cond.Status, "ignored CR should have other condition cleared")
					}
				}
			},
		},
		{
			name: "pass along any existing permissions boundary",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserWithPermissionsBoundary(mockAWSClient)

				mockCreateUserWithPermissionsBoundary(mockAWSClient)
				mockPutUserPolicy(mockAWSClient)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID, testAWSSecretAccessKey)
				mockTagUser(mockAWSClient)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserNotFound(mockAWSClient)
				mockGetUserPolicyMissing(mockAWSClient)
				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "new credential but operator disabled via configmap",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testOperatorConfigMap("true"),
				testCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
		},
		{
			name: "new credential but operator disabled via config",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
				testCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
		},
		{
			name: "old configmap data ignored because of new config",
			existing: []runtime.Object{
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
				testOperatorConfigMap("false"),
				testCredentialsRequest(t),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
		},
		{
			name: "recently synced but with error condition set",
			existing: []runtime.Object{
				testOperatorConfig(""),
				func() *minterv1.CredentialsRequest {
					cr := testCredentialsRequestWithRecentLastSync(t)
					cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions,
						minterv1.CredentialsProvisionFailure, corev1.ConditionTrue, credentialsProvisionFailure,
						"Please investigate", utils.UpdateConditionAlways)
					return cr
				}(),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testClusterVersion(),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				return mockAWSClient
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.CredentialsProvisionFailure,
					reason:        credentialsProvisionSuccess,
					status:        corev1.ConditionFalse,
				},
			},
		},
		{
			name: "recently synced but not provisioned",
			existing: []runtime.Object{
				testOperatorConfig(""),
				func() *minterv1.CredentialsRequest {
					cr := testCredentialsRequestWithRecentLastSync(t)
					cr.Status.Provisioned = false
					return cr
				}(),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testClusterVersion(),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)
				mockGetUserPolicy(mockAWSClient, testPolicy1)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "provision with aws policy condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				func() *minterv1.CredentialsRequest {
					cr := testCredentialsRequest(t)
					awsProvSpec, err := codec.EncodeProviderSpec(
						&minterv1.AWSProviderSpec{
							TypeMeta: metav1.TypeMeta{
								Kind: "AWSProviderSpec",
							},
							StatementEntries: []minterv1.StatementEntry{
								{
									Effect: "Allow",
									Action: []string{
										"iam:GetUser",
										"iam:GetUserPolicy",
										"iam:ListAccessKeys",
									},
									Resource: "*",
									PolicyCondition: minterv1.IAMPolicyCondition{
										"StringEquals": minterv1.IAMPolicyConditionKeyValue{
											"aws:userid": "testuser",
										},
									},
								},
							},
						})
					require.NoError(t, err, "unexpected error encoding AWSProviderSpec")

					cr.Spec.ProviderSpec = awsProvSpec
					return cr
				}(),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),
				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testClusterVersion(),
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				// Just mock up GetUser that doesn't fail for the read-only account test
				// And it is set up for AnyTimes() so that the next check for whether the credreq user
				// exists forces the actuator to create a new user.
				mockGetUserNotFound(mockAWSClient)

				mockGetUserPolicyMissing(mockAWSClient)

				mockListAccessKeysEmpty(mockAWSClient)
				return mockAWSClient
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserNotFound(mockAWSClient)
				mockCreateUser(mockAWSClient)
				mockTagUser(mockAWSClient)
				mockPutUserPolicyWithExpectedPolicy(mockAWSClient, testPolicyWithConditions)
				mockCreateAccessKey(mockAWSClient, testAWSAccessKeyID, testAWSSecretAccessKey)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "already provisioned with aws policy condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				func() *minterv1.CredentialsRequest {
					cr := testCredentialsRequest(t)
					awsProvSpec, err := codec.EncodeProviderSpec(
						&minterv1.AWSProviderSpec{
							TypeMeta: metav1.TypeMeta{
								Kind: "AWSProviderSpec",
							},
							StatementEntries: []minterv1.StatementEntry{
								{
									Effect: "Allow",
									Action: []string{
										"iam:GetUser",
										"iam:GetUserPolicy",
										"iam:ListAccessKeys",
									},
									Resource: "*",
									PolicyCondition: minterv1.IAMPolicyCondition{
										"StringEquals": minterv1.IAMPolicyConditionKeyValue{
											"aws:userid": "testuser",
										},
									},
								},
							},
						})
					require.NoError(t, err, "unexpected error encoding AWSProviderSpec")

					cr.Spec.ProviderSpec = awsProvSpec

					awsStatus, err := codec.EncodeProviderStatus(
						&minterv1.AWSProviderStatus{
							User:   testAWSUser,
							Policy: testAWSUser + "-policy",
						})
					require.NoError(t, err, "unexpected error creating aws provider status")

					cr.Status.ProviderStatus = awsStatus
					cr.Status.Provisioned = true

					return cr
				}(),
				createTestNamespace(testNamespace),
				testInfrastructure(testInfraName),
				createTestNamespace(testSecretNamespace),

				// Already provisioned secret for cred req
				testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),

				testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey),
				testClusterVersion(),
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				// Just mock up GetUser that doesn't fail for the read-only account test
				// And it is set up for AnyTimes() so that the next check for whether the credreq user
				// exists forces the actuator to handle an already provisioned user.
				mockGetUser(mockAWSClient)

				mockListAccessKeys(mockAWSClient, testAWSAccessKeyID)

				mockGetUserPolicy(mockAWSClient, testPolicyWithConditions)
				return mockAWSClient
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)

				// no expected calls as we are just verifying that the cred request is still valid
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "error reconcile without operator config",
			existing: []runtime.Object{
				testCredentialsRequest(t),
			},
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			expectErr: true,
		},
		{
			name: "root creds updated in passthrough mode",
			existing: func() []runtime.Object {
				objects := []runtime.Object{}
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))
				objects = append(objects, createTestNamespace(testNamespace))
				objects = append(objects, createTestNamespace(testSecretNamespace))

				cr := testPassthroughCredentialsRequest(t)
				cr.Generation = cr.Generation + 1                       // rev the generation to trigger the sync
				cr.Status.LastSyncCloudCredsSecretResourceVersion = "1" // resource version of root creds before update
				objects = append(objects, cr)

				credentialsRootSecret := testPassthroughAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey)
				credentialsRootSecret.ResourceVersion = testCredRootSecretResourceVersion // resource version of root creds after update
				objects = append(objects, credentialsRootSecret)
				objects = append(objects, testAWSCredsSecret("openshift-cloud-credential-operator", "cloud-credential-operator-iam-ro-creds", testReadAWSAccessKeyID, testReadAWSSecretAccessKey))
				objects = append(objects, testAWSCredsSecret(testSecretNamespace, testSecretName, testAWSAccessKeyID, testAWSSecretAccessKey))
				objects = append(objects, testClusterVersion())
				objects = append(objects, testInfrastructure(testInfraName))

				return objects
			}(),
			mockRootAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			mockReadAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				return mockAWSClient
			},
			mockSecretAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getSecret(c)
				require.NotNil(t, targetSecret)
				assert.Equal(t, testRootAWSAccessKeyID,
					string(targetSecret.Data["aws_access_key_id"]))
				assert.Equal(t, testRootAWSSecretAccessKey,
					string(targetSecret.Data["aws_secret_access_key"]))
				cr := getCR(c)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, testCredRootSecretResourceVersion, cr.Status.LastSyncCloudCredsSecretResourceVersion)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockRootAWSClient := test.mockRootAWSClient(mockCtrl)
			mockReadAWSClient := mockaws.NewMockClient(mockCtrl)
			if test.mockReadAWSClient != nil {
				mockReadAWSClient = test.mockReadAWSClient(mockCtrl)
			}

			mockSecretAWSClient := mockaws.NewMockClient(mockCtrl)
			if test.mockSecretAWSClient != nil {
				mockSecretAWSClient = test.mockSecretAWSClient(mockCtrl)
			}

			fakeClient := fake.NewFakeClient(test.existing...)
			rcr := &ReconcileCredentialsRequest{
				Client: fakeClient,
				Actuator: &actuator.AWSActuator{
					Client: fakeClient,
					Codec:  codec,
					Scheme: scheme.Scheme,
					AWSClientBuilder: func(accessKeyID, secretAccessKey []byte, c client.Client) (minteraws.Client, error) {
						if string(accessKeyID) == testRootAWSAccessKeyID {
							return mockRootAWSClient, nil
						} else if string(accessKeyID) == testAWSAccessKeyID {
							return mockSecretAWSClient, nil
						} else {
							return mockReadAWSClient, nil
						}
					},
				},
				platformType: configv1.AWSPlatformType,
			}

			_, err = rcr.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testCRName,
					Namespace: testNamespace,
				},
			})

			if test.validate != nil {
				test.validate(fakeClient, t)
			}

			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}

			cr := getCR(fakeClient)
			for _, condition := range test.expectedConditions {
				foundCondition := utils.FindCredentialsRequestCondition(cr.Status.Conditions, condition.conditionType)
				require.NotNil(t, foundCondition, "unexpected unable to find condition")
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

const (
	testCRGeneration                  = 1 // just non-zero
	testCredRootSecretResourceVersion = "123"
	testCRName                        = "openshift-component-a"
	testNamespace                     = "openshift-cloud-credential-operator"
	testClusterName                   = "testcluster"
	testClusterID                     = "e415fe1c-f894-11e8-8eb2-f2801f1b9fd1"
	testInfraName                     = "testcluster-abc123"
	testSecretName                    = "test-secret"
	testSecretNamespace               = "myproject"
	testAWSUser                       = "mycluster-test-aws-user"
	testAWSARN                        = "arn:aws:iam::1234:user/testuser"
	testAWSUserID                     = "FAKEAWSUSERID"
	testAWSAccessKeyID                = "FAKEAWSACCESSKEYID"
	testAWSAccessKeyID2               = "FAKEAWSACCESSKEYID2"
	testAWSSecretAccessKey            = "KEEPITSECRET"
	testAWSSecretAccessKey2           = "KEEPITSECRET2"
	testRootAWSAccessKeyID            = "rootaccesskey"
	testRootAWSSecretAccessKey        = "rootsecretkey"
	testReadAWSAccessKeyID            = "readaccesskey"
	testReadAWSSecretAccessKey        = "readsecretkey"
	testPermissionsBoundaryARN        = "some:boundary:ARN:1234"
	testPermissionBoundaryType        = "Policy" // currently the only allowed value in AWS
)

var (
	testPolicy1              = fmt.Sprintf("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:GetUser\",\"iam:GetUserPolicy\",\"iam:ListAccessKeys\"],\"Resource\":\"*\"},{\"Effect\":\"Allow\",\"Action\":[\"iam:GetUser\"],\"Resource\":\"%s\"}]}", testAWSARN)
	testPolicyWithConditions = fmt.Sprintf("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:GetUser\",\"iam:GetUserPolicy\",\"iam:ListAccessKeys\"],\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:userid\":\"testuser\"}}},{\"Effect\":\"Allow\",\"Action\":[\"iam:GetUser\"],\"Resource\":\"%s\"}]}", testAWSARN)

	testTwentyMinuteOldTimestamp = time.Now().Add(-20 * time.Minute)
)

func testPassthroughCredentialsRequestWithDeletionTimestamp(t *testing.T) *minterv1.CredentialsRequest {
	cr := testPassthroughCredentialsRequest(t)
	now := metav1.Now()
	cr.DeletionTimestamp = &now
	return cr
}

func testCredentialsRequestWithRecentLastSync(t *testing.T) *minterv1.CredentialsRequest {
	cr := testCredentialsRequest(t)
	cr.Status.LastSyncGeneration = cr.Generation
	cr.Status.LastSyncTimestamp = &metav1.Time{
		// fake 20 minute old last sync
		Time: testTwentyMinuteOldTimestamp,
	}
	cr.Status.Provisioned = true
	return cr
}

func testCredentialsRequestWithDeletionTimestamp(t *testing.T) *minterv1.CredentialsRequest {
	cr := testCredentialsRequest(t)
	now := metav1.Now()
	cr.DeletionTimestamp = &now
	cr.Status.Provisioned = true
	return cr
}

// passthrough credentialsrequest objects have no awsStatus
func testPassthroughCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}
	awsProvSpec, err := codec.EncodeProviderSpec(
		&minterv1.AWSProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AWSProviderSpec",
			},
			StatementEntries: []minterv1.StatementEntry{
				{
					Effect: "Allow",
					Action: []string{
						"iam:GetUser",
						"iam:GetUserPolicy",
						"iam:ListAccessKeys",
					},
					Resource: "*",
				},
			},
		})
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
			ProviderSpec: awsProvSpec,
		},
	}
}

func testCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	cr := testPassthroughCredentialsRequest(t)

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}

	awsStatus, err := codec.EncodeProviderStatus(
		&minterv1.AWSProviderStatus{
			User: testAWSUser,
		})
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	cr.Status.ProviderStatus = awsStatus
	return cr
}

func testProvisionedCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	cr := testCredentialsRequest(t)
	cr.Status.Provisioned = true
	return cr
}

func createTestNamespace(namespace string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
}

func testInsufficientAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := testAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey)
	s.Annotations[constants.AnnotationKey] = constants.InsufficientAnnotation
	return s
}

func testPassthroughAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := testAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey)
	s.Annotations[constants.AnnotationKey] = constants.PassthroughAnnotation
	return s
}

func testLegacyAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.MintAnnotation,
			},
		},
		Data: map[string][]byte{
			"aws_access_key_id":     []byte(accessKeyID),
			"aws_secret_access_key": []byte(secretAccessKey),
		},
	}
	return s
}

func testAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := testLegacyAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey)

	s.Data["credentials"] = []byte(fmt.Sprintf(`[default]
aws_access_key_id = %s
aws_secret_access_key = %s`, accessKeyID, secretAccessKey))

	return s
}

func genericAWSError() error {
	return awserr.New("GenericFailure", "An error besides NotFound", fmt.Errorf("Just a generic AWS error for test purposes"))
}

func mockFailedGetUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(nil, genericAWSError()).AnyTimes()
}

func mockGetUserNotFound(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(nil, awserr.New(iam.ErrCodeNoSuchEntityException, "no such entity", nil)).AnyTimes()
}

func mockGetUserWithPermissionsBoundary(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(
		&iam.GetUserOutput{
			User: &iam.User{
				PermissionsBoundary: &iam.AttachedPermissionsBoundary{
					PermissionsBoundaryArn:  aws.String(testPermissionsBoundaryARN),
					PermissionsBoundaryType: aws.String(testPermissionBoundaryType),
				},
			},
		}, nil)
}

func mockGetUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(
		&iam.GetUserOutput{
			User: &iam.User{
				UserId:   aws.String(testAWSUserID),
				UserName: aws.String(testAWSUser),
				Arn:      aws.String(testAWSARN),
				Tags: []*iam.Tag{
					{
						Key:   aws.String(fmt.Sprintf("kubernetes.io/cluster/%s", testInfraName)),
						Value: aws.String("owned"),
					},
				},
			},
		}, nil).AnyTimes()
}

func mockGetUserUntagged(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(
		&iam.GetUserOutput{
			User: &iam.User{
				UserId:   aws.String(testAWSUserID),
				UserName: aws.String(testAWSUser),
				Arn:      aws.String(testAWSARN),
			},
		}, nil).AnyTimes()
}

func mockDeleteUserFailure(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().DeleteUser(gomock.Any()).Return(nil, genericAWSError())
}

func mockDeleteUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().DeleteUser(gomock.Any()).Return(
		&iam.DeleteUserOutput{}, nil)
}

func mockDeleteUserPolicy(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().DeleteUserPolicy(gomock.Any()).Return(
		&iam.DeleteUserPolicyOutput{}, nil)
}

func mockListAccessKeysEmpty(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().ListAccessKeys(
		&iam.ListAccessKeysInput{
			UserName: aws.String(testAWSUser),
		}).Return(
		&iam.ListAccessKeysOutput{
			AccessKeyMetadata: []*iam.AccessKeyMetadata{},
		}, nil)
}

func mockListAccessKeys(mockAWSClient *mockaws.MockClient, accessKeyID string) {
	mockAWSClient.EXPECT().ListAccessKeys(
		&iam.ListAccessKeysInput{
			UserName: aws.String(testAWSUser),
		}).Return(
		&iam.ListAccessKeysOutput{
			AccessKeyMetadata: []*iam.AccessKeyMetadata{
				{
					AccessKeyId: aws.String(accessKeyID),
				},
			},
		}, nil)
}

func mockCreateUserWithPermissionsBoundary(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().CreateUser(
		&iam.CreateUserInput{
			UserName:            aws.String(testAWSUser),
			PermissionsBoundary: aws.String(testPermissionsBoundaryARN),
		}).Return(
		&iam.CreateUserOutput{
			User: &iam.User{
				UserName: aws.String(testAWSUser),
				UserId:   aws.String(testAWSUserID),
				Arn:      aws.String(testAWSARN),
				PermissionsBoundary: &iam.AttachedPermissionsBoundary{
					PermissionsBoundaryArn:  aws.String(testPermissionsBoundaryARN),
					PermissionsBoundaryType: aws.String(testPermissionBoundaryType),
				},
			},
		}, nil)
}

func mockCreateUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().CreateUser(
		&iam.CreateUserInput{
			UserName: aws.String(testAWSUser),
			// TODO: tags?
		}).Return(
		&iam.CreateUserOutput{
			User: &iam.User{
				UserName: aws.String(testAWSUser),
				UserId:   aws.String(testAWSUserID),
				Arn:      aws.String(testAWSARN),
			},
		}, nil)
}

func mockCreateAccessKey(mockAWSClient *mockaws.MockClient, accessKeyID, secretAccessKey string) {
	mockAWSClient.EXPECT().CreateAccessKey(
		&iam.CreateAccessKeyInput{
			UserName: aws.String(testAWSUser),
		}).Return(
		&iam.CreateAccessKeyOutput{
			AccessKey: &iam.AccessKey{
				AccessKeyId:     aws.String(accessKeyID),
				SecretAccessKey: aws.String(secretAccessKey),
			},
		}, nil)
}

func mockTagUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().TagUser(
		&iam.TagUserInput{
			UserName: aws.String(testAWSUser),
			Tags: []*iam.Tag{
				{
					Key:   aws.String(fmt.Sprintf("kubernetes.io/cluster/%s", testInfraName)),
					Value: aws.String("owned"),
				},
			},
		}).Return(&iam.TagUserOutput{}, nil)
}

// mockTagUserLegacy should be used when infraname is not set in the cluster.
func mockTagUserLegacy(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().TagUser(
		&iam.TagUserInput{
			UserName: aws.String(testAWSUser),
			Tags: []*iam.Tag{
				{
					Key:   aws.String(openshiftClusterIDKey),
					Value: aws.String(testClusterID),
				},
			},
		}).Return(&iam.TagUserOutput{}, nil)
}

func mockDeleteAccessKey(mockAWSClient *mockaws.MockClient, accessKeyID string) {
	mockAWSClient.EXPECT().DeleteAccessKey(
		&iam.DeleteAccessKeyInput{
			UserName:    aws.String(testAWSUser),
			AccessKeyId: aws.String(accessKeyID),
		}).Return(&iam.DeleteAccessKeyOutput{}, nil)
}

func mockPutUserPolicyWithExpectedPolicy(mockAWSClient *mockaws.MockClient, policyDoc string) {
	mockAWSClient.EXPECT().PutUserPolicy(&iam.PutUserPolicyInput{
		UserName:       aws.String(testAWSUser),
		PolicyName:     aws.String(testAWSUser + "-policy"),
		PolicyDocument: aws.String(policyDoc),
	}).Return(&iam.PutUserPolicyOutput{}, nil)
}

func mockPutUserPolicy(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().PutUserPolicy(gomock.Any()).Return(&iam.PutUserPolicyOutput{}, nil)
}

func mockGetUserPolicy(mockAWSClient *mockaws.MockClient, policyDoc string) {
	policyDoc = url.QueryEscape(policyDoc)
	mockAWSClient.EXPECT().GetUserPolicy(gomock.Any()).Return(&iam.GetUserPolicyOutput{
		PolicyDocument: aws.String(policyDoc),
	}, nil)
}

func mockGetUserPolicyMissing(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUserPolicy(gomock.Any()).Return(nil, awserr.New(iam.ErrCodeNoSuchEntityException, "no such policy", nil))
}

func testClusterVersion() *configv1.ClusterVersion {
	return &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name: "version",
		},
		Spec: configv1.ClusterVersionSpec{
			ClusterID: testClusterID,
		},
	}
}

func mockSimulatePrincipalPolicyPagesSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicyPages(gomock.Any(), gomock.Any()).Return(nil)
}

func mockSimulatePrincipalPolicySuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any()).Return(&iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{EvalDecision: aws.String("allowed")},
		},
	}, nil)
}

func testInfrastructure(infraName string) *configv1.Infrastructure {
	return &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.InfrastructureStatus{
			Platform:           configv1.AWSPlatformType,
			InfrastructureName: infraName,
			PlatformStatus: &configv1.PlatformStatus{
				AWS: &configv1.AWSPlatformStatus{
					Region: "test-region-2",
				},
			},
		},
	}
}

func testOperatorConfigMap(disabled string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CloudCredOperatorConfigMap,
			Namespace: minterv1.CloudCredOperatorNamespace,
		},
		Data: map[string]string{
			"disabled": disabled,
		},
	}
}

func testOperatorConfig(mode operatorv1.CloudCredentialsMode) *operatorv1.CloudCredential {
	conf := &operatorv1.CloudCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name: constants.CloudCredOperatorConfig,
		},
		Spec: operatorv1.CloudCredentialSpec{
			CredentialsMode: mode,
		},
	}

	return conf
}

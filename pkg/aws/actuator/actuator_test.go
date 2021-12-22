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

package actuator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openshift/cloud-credential-operator/pkg/apis"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testROAccessKeyID     = "TestROAccessKeyID"
	testROSecretAccessKey = "TestROSecretAccessKey"

	testRootAccessKeyID     = "TestRootAccessKeyID"
	testRootSecretAccessKey = "TestRootSecretAccessKey"

	testTargetSecret    = "testTargetSecretName"
	testTargetNamespace = "testTargetNamespace"
)

type awsClientBuilderRecorder struct {
	accessKeyID     []byte
	secretAccessKey []byte

	fakeAWSClient      *mockaws.MockClient
	fakeAWSClientError error
}

func (a *awsClientBuilderRecorder) ClientBuilder(accessKeyID, secretAccessKey []byte, client client.Client) (ccaws.Client, error) {
	a.accessKeyID = accessKeyID
	a.secretAccessKey = secretAccessKey

	return a.fakeAWSClient, a.fakeAWSClientError
}

func TestCredentialsFetching(t *testing.T) {
	util.SetupScheme(scheme.Scheme)

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("failed to set up codec for tests: %v", err)
	}

	tests := []struct {
		name                  string
		existing              []runtime.Object
		credentialsRequest    *minterv1.CredentialsRequest
		expectedError         bool
		validate              func(*testing.T, *awsClientBuilderRecorder)
		clientBuilderRecorder func(*gomock.Controller) *awsClientBuilderRecorder
	}{
		{
			name: "read only secret exists",
			existing: []runtime.Object{
				testReadOnlySecret(),
			},
			clientBuilderRecorder: func(mockCtrl *gomock.Controller) *awsClientBuilderRecorder {
				r := &awsClientBuilderRecorder{}

				awsClient := mockaws.NewMockClient(mockCtrl)
				awsClient.EXPECT().GetUser(gomock.Any()).Return(nil, nil)

				r.fakeAWSClient = awsClient

				return r
			},
			validate: func(t *testing.T, clientRecorder *awsClientBuilderRecorder) {
				assert.Equal(t, testROAccessKeyID, string(clientRecorder.accessKeyID))
				assert.Equal(t, testROSecretAccessKey, string(clientRecorder.secretAccessKey))
			},
		},
		{
			name: "no read only secret",
			existing: []runtime.Object{
				testRootSecret(),
			},
			clientBuilderRecorder: func(mockCtrl *gomock.Controller) *awsClientBuilderRecorder {
				r := &awsClientBuilderRecorder{}

				awsClient := mockaws.NewMockClient(mockCtrl)
				r.fakeAWSClient = awsClient

				return r
			},
			validate: func(t *testing.T, clientRecorder *awsClientBuilderRecorder) {
				assert.Equal(t, testRootAccessKeyID, string(clientRecorder.accessKeyID))
				assert.Equal(t, testRootSecretAccessKey, string(clientRecorder.secretAccessKey))
			},
		},
		{
			name: "read only creds not ready",
			existing: []runtime.Object{
				testReadOnlySecret(),
				testRootSecret(),
			},
			clientBuilderRecorder: func(mockCtrl *gomock.Controller) *awsClientBuilderRecorder {
				r := &awsClientBuilderRecorder{}

				awsClient := mockaws.NewMockClient(mockCtrl)
				awsClient.EXPECT().GetUser(gomock.Any()).Return(nil, &testAWSError{
					code: "InvalidClientTokenId",
				})
				r.fakeAWSClient = awsClient

				return r
			},
			validate: func(t *testing.T, clientRecorder *awsClientBuilderRecorder) {
				assert.Equal(t, testRootAccessKeyID, string(clientRecorder.accessKeyID))
				assert.Equal(t, testRootSecretAccessKey, string(clientRecorder.secretAccessKey))
			},
		},
		{
			name:          "error creating client",
			expectedError: true,
			existing: []runtime.Object{
				testReadOnlySecret(),
			},
			clientBuilderRecorder: func(mockCtrl *gomock.Controller) *awsClientBuilderRecorder {
				r := &awsClientBuilderRecorder{
					fakeAWSClientError: fmt.Errorf("test error"),
				}

				return r
			},
		},
		{
			name:          "bad credentials request",
			expectedError: true,
			existing: []runtime.Object{
				testReadOnlySecret(),
			},
			credentialsRequest: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest()
				cr.Status.ProviderStatus = &runtime.RawExtension{
					Raw: []byte("garbage data"),
				}

				return cr
			}(),
			clientBuilderRecorder: func(mockCtrl *gomock.Controller) *awsClientBuilderRecorder {
				r := &awsClientBuilderRecorder{}

				fakeAWSClient := mockaws.NewMockClient(mockCtrl)
				r.fakeAWSClient = fakeAWSClient

				return r
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.credentialsRequest == nil {
				test.credentialsRequest = testCredentialsRequest()
			}

			test.existing = append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			clientRecorder := test.clientBuilderRecorder(mockCtrl)

			a := &AWSActuator{
				Client:           fakeClient,
				Codec:            codec,
				AWSClientBuilder: clientRecorder.ClientBuilder,
			}

			aClient, err := a.buildReadAWSClient(test.credentialsRequest)

			if test.expectedError {
				assert.Error(t, err, "expected error for test case")
			} else {
				assert.NotNil(t, aClient)
				if test.validate != nil {
					test.validate(t, clientRecorder)
				}
			}
		})
	}
}
func TestGenerateUserName(t *testing.T) {
	tests := []struct {
		name           string
		clusterName    string
		credentialName string
		expectedPrefix string // last part is random
		expectedError  bool
	}{
		{
			name:           "max size no truncating required",
			clusterName:    "20charclustername111",                  // max 20 chars
			credentialName: "openshift-cluster-ingress111111111111", // max 37 chars
			expectedPrefix: "20charclustername111-openshift-cluster-ingress111111111111-",
		},
		{
			name:           "credential name truncated to 37 chars",
			clusterName:    "shortcluster",
			credentialName: "openshift-cluster-ingress111111111111333333333333333", // over 37 chars
			expectedPrefix: "shortcluster-openshift-cluster-ingress111111111111-",
		},
		{
			name:           "cluster name truncated to 20 chars",
			clusterName:    "longclustername1111137492374923874928347928374", // over 20 chars
			credentialName: "openshift-cluster-ingress",
			expectedPrefix: "longclustername11111-openshift-cluster-ingress-",
		},
		{
			name:           "empty credential name",
			clusterName:    "shortcluster",
			credentialName: "",
			expectedError:  true,
		},
		{
			name:           "empty infra name",
			clusterName:    "",
			credentialName: "something",
			expectedPrefix: "something-",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userName, err := generateUserName(test.clusterName, test.credentialName)
			if err != nil && !test.expectedError {
				t.Errorf("unexpected error: %v", err)
			} else if err == nil {
				if test.expectedError {
					t.Error("no error returned")
				} else {
					t.Logf("userName: %s, length=%d", userName, len(userName))
					assert.True(t, len(userName) <= 64)
					if test.expectedPrefix != "" {
						assert.True(t, strings.HasPrefix(userName, test.expectedPrefix), "username prefix does not match")
						assert.Equal(t, len(test.expectedPrefix)+5, len(userName), "username length does not match a 5 char random suffix")
					}
				}
			}
		})
	}
}

func TestUpgradeable(t *testing.T) {
	util.SetupScheme(scheme.Scheme)

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("failed to set up codec for tests: %v", err)
	}

	tests := []struct {
		name           string
		mode           operatorv1.CloudCredentialsMode
		existing       []runtime.Object
		expectedStatus configv1.ConditionStatus
		expectedReason string
	}{
		{
			name: "mint mode with root cred",
			mode: operatorv1.CloudCredentialsModeMint,
			existing: []runtime.Object{
				testRootSecret(),
				testCloudCredentialConfig(),
			},
			expectedStatus: configv1.ConditionTrue,
		},
		{
			name: "implicit mint mode with root cred",
			mode: operatorv1.CloudCredentialsModeDefault,
			existing: []runtime.Object{
				testRootSecret(),
				testCloudCredentialConfig(),
			},
			expectedStatus: configv1.ConditionTrue,
		},
		{
			name: "mint mode with missing root cred",
			mode: operatorv1.CloudCredentialsModeMint,
			existing: []runtime.Object{
				testCloudCredentialConfig(),
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: constants.MissingRootCredentialUpgradeableReason,
		},
		{
			name: "implicit mint mode with missing root cred",
			mode: operatorv1.CloudCredentialsModeDefault,
			existing: []runtime.Object{
				testCloudCredentialConfig(),
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: constants.MissingRootCredentialUpgradeableReason,
		},
		{
			name: "manual mode with annotation override",
			mode: operatorv1.CloudCredentialsModeManual,
			existing: []runtime.Object{
				testCloudCredentialConfigWithAnnotation(map[string]string{constants.UpgradeableAnnotation: "4.99"}),
			},
			expectedStatus: configv1.ConditionTrue,
		},
		{
			name: "manual mode missing annotation",
			mode: operatorv1.CloudCredentialsModeManual,
			existing: []runtime.Object{
				testCloudCredentialConfig(),
			},
			expectedStatus: configv1.ConditionFalse,
			expectedReason: constants.MissingUpgradeableAnnotationReason,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()

			fakeClient.Create(context.TODO(), testClusterVersion())

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			a := &AWSActuator{
				Client: fakeClient,
				Codec:  codec,
			}

			cond := a.Upgradeable(test.mode)

			if test.expectedStatus == configv1.ConditionTrue {
				assert.Nil(t, cond, "expect no condition when state is upgradable")
			} else {
				assert.Equal(t, test.expectedStatus, cond.Status)
				assert.Equal(t, test.expectedReason, cond.Reason)
			}
		})
	}
}

func testClusterVersion() *configv1.ClusterVersion {
	clusterVersion := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name: "version",
		},
		Status: configv1.ClusterVersionStatus{
			History: []configv1.UpdateHistory{
				{
					State:   configv1.CompletedUpdate,
					Version: "4.7.7",
				},
			},
		},
	}
	return clusterVersion
}

func TestSecretFormat(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)

	tests := []struct {
		name            string
		accessKeyID     string
		secretAccessKey string
		existingSecret  *corev1.Secret
	}{
		{
			name:            "new secret with credentials field",
			accessKeyID:     "AKFIRSTKEY",
			secretAccessKey: "FIRSTSECRET",
		},
		{
			name:            "existing secret without credentials field",
			accessKeyID:     "AKFIRSTKEY",
			secretAccessKey: "FIRSTSECRET",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testTargetSecret,
					Namespace: testTargetNamespace,
				},
				Data: map[string][]byte{
					"aws_access_key_id":     []byte("SOMEACCESSKEY"),
					"aws_secret_access_key": []byte("SOMESECRETKEY"),
				},
			},
		},
		{
			name:            "existing secret with outdated credentials field",
			accessKeyID:     "AKFIRSTKEY",
			secretAccessKey: "FIRSTSECRET",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testTargetSecret,
					Namespace: testTargetNamespace,
				},
				Data: map[string][]byte{
					"aws_access_key_id":     []byte("SOMEACCESSKEY"),
					"aws_secret_access_key": []byte("SOMESECRETKEY"),
					"credentials":           []byte("OLD AWS CONFIG"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var fakeClient client.Client
			if test.existingSecret != nil {
				fakeClient = fake.NewClientBuilder().WithRuntimeObjects(test.existingSecret).Build()
			} else {
				fakeClient = fake.NewClientBuilder().WithRuntimeObjects().Build()
			}

			a := &AWSActuator{
				Client: fakeClient,
			}

			cr := testCredentialsRequest()
			logger := a.getLogger(cr)
			err := a.syncAccessKeySecret(cr, test.accessKeyID, test.secretAccessKey, test.existingSecret, "exampleAWSPolicy", logger)

			require.NoError(t, err, "unexpected error creating/updating Secret")

			secret := &corev1.Secret{}
			secretNSN := types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Spec.SecretRef.Namespace}

			err = fakeClient.Get(context.TODO(), secretNSN, secret)
			require.NoError(t, err, "unexpected error retriving Secret")

			assert.Contains(t, secret.Data, "aws_access_key_id")
			assert.Equal(t, string(secret.Data["aws_access_key_id"]), test.accessKeyID)
			assert.Contains(t, secret.Data, "aws_secret_access_key")
			assert.Equal(t, string(secret.Data["aws_secret_access_key"]), test.secretAccessKey)

			require.Contains(t, secret.Data, "credentials")
			credentialsConfig := string(secret.Data["credentials"])
			assert.Contains(t, credentialsConfig, fmt.Sprintf("aws_access_key_id = %s", test.accessKeyID))
			assert.Contains(t, credentialsConfig, fmt.Sprintf("aws_secret_access_key = %s", test.secretAccessKey))
		})
	}
}

func testReadOnlySecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roAWSCredsSecret,
			Namespace: roAWSCredsSecretNamespace,
		},
		Data: map[string][]byte{
			"aws_access_key_id":     []byte(testROAccessKeyID),
			"aws_secret_access_key": []byte(testROSecretAccessKey),
		},
	}
}

func testSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"aws_access_key_id":     []byte(testROAccessKeyID),
			"aws_secret_access_key": []byte(testROSecretAccessKey),
		},
	}
}

func testRootSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AWSCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
		},
		Data: map[string][]byte{
			"aws_access_key_id":     []byte(testRootAccessKeyID),
			"aws_secret_access_key": []byte(testRootSecretAccessKey),
		},
	}
}

func testCloudCredentialConfigWithAnnotation(annotations map[string]string) *operatorv1.CloudCredential {
	credConfig := &operatorv1.CloudCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "cluster",
			Annotations: annotations,
		},
	}
	return credConfig
}

func testCloudCredentialConfig() *operatorv1.CloudCredential {
	credConfig := &operatorv1.CloudCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
	}
	return credConfig
}

func testCredentialsRequest() *minterv1.CredentialsRequest {
	return &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testcr",
			Namespace: "testnamespace",
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{
				Name:      testTargetSecret,
				Namespace: testTargetNamespace,
			},
		},
	}
}

type testAWSError struct {
	code string
}

func (a *testAWSError) Code() string {
	return a.code
}

func (a *testAWSError) Message() string {
	panic("not implemented")
}

func (a *testAWSError) OrigErr() error {
	panic("not implemented")
}

func (a *testAWSError) Error() string {
	panic("not implemented")
}

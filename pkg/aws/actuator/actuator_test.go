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
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"

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

	tests := []struct {
		name                  string
		existing              []runtime.Object
		existingAdmin         []runtime.Object
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
			name:     "no read only secret",
			existing: []runtime.Object{},
			existingAdmin: []runtime.Object{
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
			},
			existingAdmin: []runtime.Object{
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
			fakeAdminClient := fake.NewClientBuilder().WithRuntimeObjects(test.existingAdmin...).Build()

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			clientRecorder := test.clientBuilderRecorder(mockCtrl)

			a := &AWSActuator{
				Client:           fakeClient,
				RootCredClient:   fakeAdminClient,
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
				RootCredClient: fakeClient,
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
				fakeClient = fake.NewClientBuilder().Build()
			}

			a := &AWSActuator{
				Client: fakeClient,
			}

			cr := testCredentialsRequest()
			logger := a.getLogger(cr)
			err := a.syncAccessKeySecret(context.Background(), cr, test.accessKeyID, test.secretAccessKey, "exampleAWSPolicy", logger)

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

func TestDetectSTS(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		existing           []runtime.Object
		wantErr            assert.ErrorAssertionFunc
		CredentialsRequest *minterv1.CredentialsRequest
		issuer             string
	}{
		{
			name: "empty ServiceAccountIssuer on AWS STS-enabled CCO in Manual mode should error",
			existing: []runtime.Object{
				testInfrastructure(),
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
			},
			CredentialsRequest: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest()
				var err error
				cr.Spec.ProviderSpec, err = testAWSProviderConfig("")
				if err != nil {
					t.Log(err)
					t.FailNow()
				}
				return cr
			}(),
			issuer:  "",
			wantErr: assert.Error,
		},
		{
			name: "non-empty ServiceAccountIssuer on AWS STS-enabled CCO in Manual mode should note STS detected",
			existing: []runtime.Object{
				testInfrastructure(),
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
			},
			CredentialsRequest: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest()
				var err error
				cr.Spec.ProviderSpec, err = testAWSProviderConfig("not empty	")
				if err != nil {
					t.Log(err)
					t.FailNow()
				}
				return cr
			}(),
			issuer:  "non-empty",
			wantErr: assert.NoError,
		},
		{
			name: "STS mode and with a CloudTokenString and CloudTokenPath set in CredentialsRequest should create Secret & not error",
			existing: []runtime.Object{
				testInfrastructure(),
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
			},
			CredentialsRequest: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest()
				var err error
				cr.Spec.ProviderSpec, err = testAWSProviderConfig("cloud-token")
				if err != nil {
					t.FailNow()
				}
				cr.Spec.CloudTokenPath = "/var/token"
				return cr
			}(),
			issuer:  "non-empty",
			wantErr: assert.NoError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithStatusSubresource(&minterv1.CredentialsRequest{}).
				WithRuntimeObjects(test.existing...).Build()
			fakeAdminClient := fake.NewClientBuilder().Build()
			err := fakeClient.Create(context.TODO(), testAuthentication(test.issuer))
			if err != nil {
				panic(err)
			}
			a := &AWSActuator{
				Client:         fakeClient,
				RootCredClient: fakeAdminClient,
			}
			test.wantErr(t, a.sync(context.Background(), test.CredentialsRequest), fmt.Sprintf("sync(%v)", test.CredentialsRequest))
		})
	}
}

func testAWSProviderConfig(awsSTSIAMRoleARN string) (*runtime.RawExtension, error) {
	providerSpec := minterv1.AWSProviderSpec{
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
	}
	if awsSTSIAMRoleARN != "" {
		providerSpec.STSIAMRoleARN = awsSTSIAMRoleARN
	}
	awsProvSpec, err := minterv1.Codec.EncodeProviderSpec(&providerSpec)
	return awsProvSpec, err
}

func testInfrastructure() *configv1.Infrastructure {
	return &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.InfrastructureStatus{
			Platform:           configv1.AWSPlatformType,
			InfrastructureName: "test-infra",
			PlatformStatus: &configv1.PlatformStatus{
				AWS: &configv1.AWSPlatformStatus{
					Region: "test-region-2",
				},
			},
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

func testAuthentication(issuer string) *configv1.Authentication {
	conf := &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: configv1.AuthenticationSpec{
			ServiceAccountIssuer: issuer,
		},
	}
	return conf
}

func TestGetDesiredUserPolicyInfraCondition(t *testing.T) {
	a := &AWSActuator{}
	infraName := "test-infra"
	conditionKey := ccaws.InfraResourceTagKeyPrefix + infraName
	userARN := "arn:aws:iam::123456789012:user/test-user"

	t.Run("scoped actions get infra condition", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"ec2:TerminateInstances"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		require.Len(t, doc.Statement, 2)
		strEq := doc.Statement[0].Condition["StringEquals"]
		assert.Equal(t, ccaws.InfraResourceTagValue, strEq[conditionKey])
	})

	t.Run("existing StringEquals condition preserved on scoped action", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{
				Effect:   "Allow",
				Action:   []string{"ec2:TerminateInstances"},
				Resource: "*",
				PolicyCondition: minterv1.IAMPolicyCondition{
					"StringEquals": minterv1.IAMPolicyConditionKeyValue{
						"ec2:Region": "us-east-1",
					},
				},
			},
		}
		snapshot := entries[0].PolicyCondition.DeepCopy()

		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		assert.Equal(t, *snapshot, entries[0].PolicyCondition)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		strEq := doc.Statement[0].Condition["StringEquals"]
		assert.Equal(t, "us-east-1", strEq["ec2:Region"])
		assert.Equal(t, ccaws.InfraResourceTagValue, strEq[conditionKey])
	})

	t.Run("unscoped actions do not get infra condition", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"ec2:DescribeInstances"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		require.Len(t, doc.Statement, 2)
		assert.Nil(t, doc.Statement[0].Condition)
	})

	t.Run("S3 actions are all unscoped", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"s3:CreateBucket", "s3:GetObject", "s3:PutObject"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		require.Len(t, doc.Statement, 2)
		assert.ElementsMatch(t, []string{"s3:CreateBucket", "s3:GetObject", "s3:PutObject"}, doc.Statement[0].Action)
		assert.Nil(t, doc.Statement[0].Condition)
	})

	t.Run("multiple scoped statements all get condition", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"ec2:TerminateInstances"}, Resource: "*"},
			{Effect: "Allow", Action: []string{"ec2:DeleteVolume"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		require.Len(t, doc.Statement, 3)
		for _, stmt := range doc.Statement[:2] {
			strEq := stmt.Condition["StringEquals"]
			assert.Equal(t, ccaws.InfraResourceTagValue, strEq[conditionKey])
		}
	})

	t.Run("empty infraName skips condition", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"ec2:TerminateInstances"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, "")
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		assert.Nil(t, doc.Statement[0].Condition)
	})

	t.Run("empty infraName preserves existing condition without mutation", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{
				Effect:   "Allow",
				Action:   []string{"ec2:TerminateInstances"},
				Resource: "*",
				PolicyCondition: minterv1.IAMPolicyCondition{
					"StringEquals": minterv1.IAMPolicyConditionKeyValue{
						"ec2:Region": "us-east-1",
					},
				},
			},
		}
		snapshot := entries[0].PolicyCondition.DeepCopy()

		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, "")
		require.NoError(t, err)

		assert.Equal(t, *snapshot, entries[0].PolicyCondition)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		assert.Equal(t, "us-east-1", doc.Statement[0].Condition["StringEquals"]["ec2:Region"])
	})

	t.Run("mixed scoped and unscoped actions are split", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{
				Effect:   "Allow",
				Action:   []string{"ec2:RunInstances", "ec2:TerminateInstances", "ec2:DescribeInstances"},
				Resource: "*",
			},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		// Scoped (TerminateInstances) + unscoped (RunInstances, DescribeInstances) + iam:GetUser = 3
		require.Len(t, doc.Statement, 3)

		assert.Equal(t, []string{"ec2:TerminateInstances"}, doc.Statement[0].Action)
		assert.Equal(t, ccaws.InfraResourceTagValue, doc.Statement[0].Condition["StringEquals"][conditionKey])

		assert.ElementsMatch(t, []string{"ec2:RunInstances", "ec2:DescribeInstances"}, doc.Statement[1].Action)
		assert.Nil(t, doc.Statement[1].Condition)

		assert.Equal(t, []string{"iam:GetUser"}, doc.Statement[2].Action)
	})

	t.Run("mixed statement preserves original condition on both halves", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{
				Effect:   "Allow",
				Action:   []string{"ec2:RunInstances", "ec2:TerminateInstances"},
				Resource: "*",
				PolicyCondition: minterv1.IAMPolicyCondition{
					"Bool": minterv1.IAMPolicyConditionKeyValue{
						"kms:GrantIsForAWSResource": true,
					},
				},
			},
		}
		snapshot := entries[0].PolicyCondition.DeepCopy()

		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		assert.Equal(t, *snapshot, entries[0].PolicyCondition)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		require.Len(t, doc.Statement, 3)

		assert.Equal(t, true, doc.Statement[0].Condition["Bool"]["kms:GrantIsForAWSResource"])
		assert.Equal(t, ccaws.InfraResourceTagValue, doc.Statement[0].Condition["StringEquals"][conditionKey])

		assert.Equal(t, true, doc.Statement[1].Condition["Bool"]["kms:GrantIsForAWSResource"])
		_, hasStringEquals := doc.Statement[1].Condition["StringEquals"]
		assert.False(t, hasStringEquals)
	})

	t.Run("Deny statements are never conditioned", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Deny", Action: []string{"s3:DeleteBucket"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		assert.Nil(t, doc.Statement[0].Condition)
	})

	t.Run("iam:GetUser self-lookup has no infra condition", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"ec2:TerminateInstances"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		getUserStmt := doc.Statement[len(doc.Statement)-1]
		assert.Equal(t, []string{"iam:GetUser"}, getUserStmt.Action)
		assert.Empty(t, getUserStmt.Condition)
	})

	t.Run("unknown action returns error", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"ec2:TerminateInstances", "foo:BarAction"}, Resource: "*"},
		}
		_, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "foo:BarAction")
		assert.Contains(t, err.Error(), "openshift/cloud-credential-operator")
	})

	t.Run("unknown action with empty infraName is not checked", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"foo:BarAction"}, Resource: "*"},
		}
		_, err := a.getDesiredUserPolicy(entries, userARN, "")
		require.NoError(t, err)
	})

	t.Run("KMS actions are scoped via key resource type", func(t *testing.T) {
		entries := []minterv1.StatementEntry{
			{Effect: "Allow", Action: []string{"kms:Decrypt", "kms:Encrypt"}, Resource: "*"},
		}
		policyJSON, err := a.getDesiredUserPolicy(entries, userARN, infraName)
		require.NoError(t, err)

		var doc PolicyDocument
		require.NoError(t, json.Unmarshal([]byte(policyJSON), &doc))

		require.Len(t, doc.Statement, 2)
		strEq := doc.Statement[0].Condition["StringEquals"]
		assert.Equal(t, ccaws.InfraResourceTagValue, strEq[conditionKey])
	})
}

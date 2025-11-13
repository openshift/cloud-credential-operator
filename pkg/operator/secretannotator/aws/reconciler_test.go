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

package aws_test

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	annaws "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/aws"
)

const (
	testSecretName         = "testsecret"
	testNamespace          = "testproject"
	testAWSUser            = "credTestUser"
	testAWSUserARN         = "arn:aws:iam::123456789012:user/credTestUser"
	testAWSAccessKeyID     = "FAKEAWSACCESSKEYID"
	testInfraName          = "testcluster-abc123"
	testAWSSecretAccessKey = "KEEPITSECRET"
	testAWSRegion          = "test-region-2"
)

var (
	failedSimulationResponse = &iam.SimulatePrincipalPolicyOutput{
		EvaluationResults: []iamtypes.EvaluationResult{
			{
				EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
				EvalActionName: awssdk.String("SomeAWSAction"),
			},
		},
	}
	successfulSimulateResponse = &iam.SimulatePrincipalPolicyOutput{
		EvaluationResults: []iamtypes.EvaluationResult{
			{
				EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
				EvalActionName: awssdk.String("SomeAWSAction"),
			},
		},
	}
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestSecretAnnotatorReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name                    string
		existing                []runtime.Object
		existingRootCred        []runtime.Object
		expectErr               bool
		mockAWSClient           func(mockCtrl *gomock.Controller) *mockaws.MockClient
		validateAnnotationValue string
	}{
		{
			name: "cred minter mode",
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterSuccess(mockAWSClient)

				return mockAWSClient
			},
			validateAnnotationValue: constants.MintAnnotation,
		},
		{
			name: "operator disabled via configmap",
			existing: []runtime.Object{
				testOperatorConfigMap("true"),
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
		},
		{
			name: "operator disabled",
			existing: []runtime.Object{
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
		},
		{
			name: "detect root user creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetRootUser(mockAWSClient)

				return mockAWSClient
			},
			expectErr: true,
		},
		{
			name: "cred passthrough mode",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(configv1.AWSPlatformType),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient)

				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredPassthrough(mockAWSClient, testAWSRegion)

				return mockAWSClient
			},
			validateAnnotationValue: constants.PassthroughAnnotation,
		},
		{
			name: "cred passthrough mode wrong region permission",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(configv1.AWSPlatformType),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient)

				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredPassthrough(mockAWSClient, "expect-this-region")

				return mockAWSClient
			},
			validateAnnotationValue: constants.InsufficientAnnotation,
		},
		{
			name: "useless creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(configv1.AWSPlatformType),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient)

				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredPassthroughFail(mockAWSClient)

				return mockAWSClient
			},
			validateAnnotationValue: constants.InsufficientAnnotation,
		},
		{
			name: "useless creds - None platform",
			existing: []runtime.Object{
				testOperatorConfig(""),
				testInfrastructure(configv1.NonePlatformType),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient)

				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredPassthroughFail(mockAWSClient)

				return mockAWSClient
			},
			validateAnnotationValue: constants.InsufficientAnnotation,
		},
		{
			name: "missing secret",
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			expectErr: true,
		},
		{
			name:      "secret missing key",
			expectErr: true,
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testNamespace,
					},
					Data: map[string][]byte{
						annaws.AwsAccessKeyName:     []byte(testAWSAccessKeyID),
						"not_aws_secret_access_key": []byte(testAWSSecretAccessKey),
					},
				},
			},
		},
		{
			name: "annotation matches forced mode",
			existing: []runtime.Object{
				testOperatorConfig(operatorv1.CloudCredentialsModeMint),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			validateAnnotationValue: constants.MintAnnotation,
		},
		{
			name: "unknown mode",
			existing: []runtime.Object{
				testOperatorConfig("notARealMode"),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			expectErr: true,
		},
		{
			name:     "error on missing config CR",
			existing: []runtime.Object{},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()
			fakeRootCredClient := fake.NewClientBuilder().WithRuntimeObjects(test.existingRootCred...).Build()

			fakeAWSClient := mockaws.NewMockClient(mockCtrl)
			if test.mockAWSClient != nil {
				fakeAWSClient = test.mockAWSClient(mockCtrl)
			}

			rcc := &annaws.ReconcileCloudCredSecret{
				Client:         fakeClient,
				RootCredClient: fakeRootCredClient,
				Logger:         log.WithField("controller", "testController"),
				AWSClientBuilder: func(accessKeyID, secretAccessKey []byte, c client.Client) (ccaws.Client, error) {
					return fakeAWSClient, nil
				},
			}

			_, err := rcc.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      constants.AWSCloudCredSecretName,
					Namespace: constants.CloudCredSecretNamespace,
				},
			})

			if !test.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validateAnnotationValue != "" {
				validateSecretAnnotation(fakeRootCredClient, t, test.validateAnnotationValue)
			}
		})
	}
}

func testSecret() *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AWSCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
		},
		Data: map[string][]byte{
			annaws.AwsAccessKeyName:       []byte(testAWSAccessKeyID),
			annaws.AwsSecretAccessKeyName: []byte(testAWSSecretAccessKey),
		},
	}
	return s
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

func testInfrastructure(platformType configv1.PlatformType) *configv1.Infrastructure {
	infra := &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.InfrastructureStatus{
			Platform:           platformType,
			InfrastructureName: testInfraName,
			PlatformStatus: &configv1.PlatformStatus{
				Type: platformType,
			},
		},
	}
	if platformType == configv1.AWSPlatformType {
		infra.Status.PlatformStatus.AWS = &configv1.AWSPlatformStatus{
			Region: testAWSRegion,
		}
	}
	return infra
}

func mockGetRootUser(mockAWSClient *mockaws.MockClient) {
	rootAcctNum := "123456789012"

	mockAWSClient.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&iam.GetUserOutput{
		User: &iamtypes.User{
			UserName: awssdk.String("name-of-aws-account"),
			Arn:      awssdk.String("arn:aws:iam::" + rootAcctNum + ":root"),
			UserId:   awssdk.String(rootAcctNum),
		},
	}, nil)
}

func mockGetUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&iam.GetUserOutput{
		User: &iamtypes.User{
			UserName: awssdk.String(testAWSUser),
			Arn:      awssdk.String(testAWSUserARN),
			UserId:   awssdk.String(testAWSAccessKeyID),
		},
	}, nil)
}

func mockSimulatePrincipalPolicyCredMinterSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(successfulSimulateResponse, nil)
}

func mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(failedSimulationResponse, nil)
}

func mockSimulatePrincipalPolicyCredPassthrough(mockAWSClient *mockaws.MockClient, expectedRegion string) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, input *iam.SimulatePrincipalPolicyInput, options ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			if checkRegionParamSet(input, expectedRegion) {
				return successfulSimulateResponse, nil
			}
			return failedSimulationResponse, nil
		})
}

func checkRegionParamSet(input *iam.SimulatePrincipalPolicyInput, expectedRegion string) bool {
	for _, ctx := range input.ContextEntries {
		if *ctx.ContextKeyName == "aws:RequestedRegion" {
			for _, value := range ctx.ContextKeyValues {
				if value == expectedRegion {
					return true
				}
			}
		}
	}
	return false
}

func mockSimulatePrincipalPolicyCredPassthroughFail(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(failedSimulationResponse, nil)
}

func validateSecretAnnotation(c client.Client, t *testing.T, value string) {
	secret := getCredSecret(c)
	validateAnnotation(t, secret, value)
}

func validateAnnotation(t *testing.T, secret *corev1.Secret, annotation string) {
	if secret.ObjectMeta.Annotations == nil {
		t.Errorf("unexpected empty annotations on secret")
	}
	if _, ok := secret.ObjectMeta.Annotations[constants.AnnotationKey]; !ok {
		t.Errorf("missing annotation")
	}

	assert.Exactly(t, annotation, secret.ObjectMeta.Annotations[constants.AnnotationKey])
}

func getCredSecret(c client.Client) *corev1.Secret {
	secret := &corev1.Secret{}
	if err := c.Get(context.TODO(), client.ObjectKey{Name: constants.AWSCloudCredSecretName, Namespace: constants.CloudCredSecretNamespace}, secret); err != nil {
		return nil
	}
	return secret
}

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

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	constants2 "github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"

	annaws "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
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
	failedSimulationResponse = &iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{
				EvalDecision:   aws.String("notallowed"),
				EvalActionName: aws.String("SomeAWSAction"),
			},
		},
	}
	successfulSimulateResponse = &iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{
				EvalDecision:   aws.String("allowed"),
				EvalActionName: aws.String("SomeAWSAction"),
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
		expectErr               bool
		mockAWSClient           func(mockCtrl *gomock.Controller) *mockaws.MockClient
		validateAnnotationValue string
	}{
		{
			name: "cred minter mode",
			existing: []runtime.Object{
				testSecret(),
				testOperatorConfig(""),
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
				testSecret(),
				testOperatorConfigMap("true"),
				testOperatorConfig(""),
			},
		},
		{
			name: "operator disabled",
			existing: []runtime.Object{
				testSecret(),
				testOperatorConfig(operatorv1.CloudCredentialsModeManual),
			},
		},
		{
			name: "detect root user creds",
			existing: []runtime.Object{
				testSecret(),
				testOperatorConfig(""),
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
				testSecret(),
				testOperatorConfig(""),
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
				testSecret(),
				testOperatorConfig(""),
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
				testSecret(),
				testOperatorConfig(""),
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
				testOperatorConfig(""),
			},
		},
		{
			name: "annotation matches forced mode",
			existing: []runtime.Object{
				testSecret(),
				testOperatorConfig(operatorv1.CloudCredentialsModeMint),
			},
			validateAnnotationValue: constants.MintAnnotation,
		},
		{
			name: "unknown mode",
			existing: []runtime.Object{
				testSecret(),
				testOperatorConfig("notARealMode"),
			},
			expectErr: true,
		},
		{
			name: "error on missing config CR",
			existing: []runtime.Object{
				testSecret(),
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			infra := &configv1.Infrastructure{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.InfrastructureStatus{
					Platform:           configv1.AWSPlatformType,
					InfrastructureName: testInfraName,
					PlatformStatus: &configv1.PlatformStatus{
						AWS: &configv1.AWSPlatformStatus{
							Region: testAWSRegion,
						},
					},
				},
			}

			existing := append(test.existing, infra)

			fakeClient := fake.NewFakeClient(existing...)

			fakeAWSClient := mockaws.NewMockClient(mockCtrl)
			if test.mockAWSClient != nil {
				fakeAWSClient = test.mockAWSClient(mockCtrl)
			}

			rcc := &annaws.ReconcileCloudCredSecret{
				Client: fakeClient,
				Logger: log.WithField("controller", "testController"),
				AWSClientBuilder: func(accessKeyID, secretAccessKey []byte, region, infraName string) (ccaws.Client, error) {
					return fakeAWSClient, nil
				},
			}

			_, err := rcc.Reconcile(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      constants2.AWSCloudCredSecretName,
					Namespace: constants.CloudCredSecretNamespace,
				},
			})

			if !test.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validateAnnotationValue != "" {
				validateSecretAnnotation(fakeClient, t, test.validateAnnotationValue)
			}
		})
	}
}

func testSecret() *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants2.AWSCloudCredSecretName,
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
			Name:      minterv1.CloudCredOperatorConfigMap,
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
			Name: constants2.CloudCredOperatorConfig,
		},
		Spec: operatorv1.CloudCredentialSpec{
			CredentialsMode: mode,
		},
	}

	return conf
}

func mockGetRootUser(mockAWSClient *mockaws.MockClient) {
	rootAcctNum := "123456789012"

	mockAWSClient.EXPECT().GetUser(nil).Return(&iam.GetUserOutput{
		User: &iam.User{
			UserName: aws.String("name-of-aws-account"),
			Arn:      aws.String("arn:aws:iam::" + rootAcctNum + ":root"),
			UserId:   aws.String(rootAcctNum),
		},
	}, nil)
}

func mockGetUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(nil).Return(&iam.GetUserOutput{
		User: &iam.User{
			UserName: aws.String(testAWSUser),
			Arn:      aws.String(testAWSUserARN),
			UserId:   aws.String(testAWSAccessKeyID),
		},
	}, nil)
}

func mockSimulatePrincipalPolicyCredMinterSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicyPages(gomock.Any(), gomock.Any()).Return(nil).
		Do(func(input *iam.SimulatePrincipalPolicyInput, f func(*iam.SimulatePolicyResponse, bool) bool) {
			f(successfulSimulateResponse, true)
		})
}

func mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicyPages(gomock.Any(), gomock.Any()).Return(nil).
		// Now in the Do() receive the lambda function f() so we can send it the failed result
		Do(func(input *iam.SimulatePrincipalPolicyInput, f func(*iam.SimulatePolicyResponse, bool) bool) {
			f(failedSimulationResponse, true)
		})
}

func mockSimulatePrincipalPolicyCredPassthrough(mockAWSClient *mockaws.MockClient, expectedRegion string) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicyPages(gomock.Any(), gomock.Any()).Return(nil).
		Do(func(input *iam.SimulatePrincipalPolicyInput, f func(*iam.SimulatePolicyResponse, bool) bool) {
			if checkRegionParamSet(input, expectedRegion) {
				f(successfulSimulateResponse, true)
			} else {
				f(failedSimulationResponse, true)
			}
		})
}

func checkRegionParamSet(input *iam.SimulatePrincipalPolicyInput, expectedRegion string) bool {
	for _, ctx := range input.ContextEntries {
		if *ctx.ContextKeyName == "aws:RequestedRegion" {
			for _, value := range ctx.ContextKeyValues {
				if *value == expectedRegion {
					return true
				}
			}
		}
	}
	return false
}

func mockSimulatePrincipalPolicyCredPassthroughFail(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicyPages(gomock.Any(), gomock.Any()).Return(nil).
		// Now in the Do() receive the lambda function f() so we can send it the failed result
		Do(func(input *iam.SimulatePrincipalPolicyInput, f func(*iam.SimulatePolicyResponse, bool) bool) {
			f(failedSimulationResponse, true)
		})
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
	if err := c.Get(context.TODO(), client.ObjectKey{Name: constants2.AWSCloudCredSecretName, Namespace: constants.CloudCredSecretNamespace}, secret); err != nil {
		return nil
	}
	return secret
}

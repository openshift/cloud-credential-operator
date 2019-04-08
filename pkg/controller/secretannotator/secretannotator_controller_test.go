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

package secretannotator

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

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/openshift/cloud-credential-operator/pkg/apis"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
)

const (
	testSecretName         = "testsecret"
	testNamespace          = "testproject"
	testAWSUser            = "credTestUser"
	testAWSUserARN         = "arn:aws:iam::123456789012:user/credTestUser"
	testAWSAccessKeyID     = "FAKEAWSACCESSKEYID"
	testInfraName          = "testcluster-abc123"
	testAWSSecretAccessKey = "KEEPITSECRET"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestSecretAnnotatorReconcile(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)
	configv1.Install(scheme.Scheme)

	tests := []struct {
		name                    string
		existing                []runtime.Object
		expectErr               bool
		mockAWSClient           func(mockCtrl *gomock.Controller) *mockaws.MockClient
		validateAnnotationValue string
	}{
		{
			name:     "cred minter mode",
			existing: []runtime.Object{testSecret()},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterSuccess(mockAWSClient)

				return mockAWSClient
			},
			validateAnnotationValue: MintAnnotation,
		},
		{
			name:     "detect root user creds",
			existing: []runtime.Object{testSecret()},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetRootUser(mockAWSClient)

				return mockAWSClient
			},
			expectErr: true,
		},
		{
			name:     "cred passthrough mode",
			existing: []runtime.Object{testSecret()},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient)

				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredPassthroughSuccess(mockAWSClient)

				return mockAWSClient
			},
			validateAnnotationValue: PassthroughAnnotation,
		},
		{
			name:     "useless creds",
			existing: []runtime.Object{testSecret()},
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient)

				mockGetUser(mockAWSClient)
				mockSimulatePrincipalPolicyCredPassthroughFail(mockAWSClient)

				return mockAWSClient
			},
			validateAnnotationValue: InsufficientAnnotation,
		},
		{
			name:      "missing secret",
			expectErr: true,
		},
		{
			name:      "secret missing key",
			expectErr: true,
			existing: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testSecretName,
					Namespace: testNamespace,
				},
				Data: map[string][]byte{
					AwsAccessKeyName:            []byte(testAWSAccessKeyID),
					"not_aws_secret_access_key": []byte(testAWSSecretAccessKey),
				},
			}},
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
				},
			}

			existing := append(test.existing, infra)

			fakeClient := fake.NewFakeClient(existing...)

			fakeAWSClient := mockaws.NewMockClient(mockCtrl)
			if test.mockAWSClient != nil {
				fakeAWSClient = test.mockAWSClient(mockCtrl)
			}

			rcc := &ReconcileCloudCredSecret{
				Client: fakeClient,
				logger: log.WithField("controller", "testController"),
				AWSClientBuilder: func(accessKeyID, secretAccessKey []byte, infraName string) (ccaws.Client, error) {
					return fakeAWSClient, nil
				},
			}

			_, err := rcc.Reconcile(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testSecretName,
					Namespace: testNamespace,
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
			Name:      testSecretName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			AwsAccessKeyName:       []byte(testAWSAccessKeyID),
			AwsSecretAccessKeyName: []byte(testAWSSecretAccessKey),
		},
	}
	return s
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
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any()).Return(&iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{EvalDecision: aws.String("allowed")},
		},
	}, nil)
}

func mockSimulatePrincipalPolicyCredMinterFail(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any()).Return(&iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{
				EvalDecision:   aws.String("notallowed"),
				EvalActionName: aws.String("SomeAWSAction"),
			},
		},
	}, nil)
}

func mockSimulatePrincipalPolicyCredPassthroughSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any()).Return(&iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{EvalDecision: aws.String("allowed")},
		},
	}, nil)
}

func mockSimulatePrincipalPolicyCredPassthroughFail(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().SimulatePrincipalPolicy(gomock.Any()).Return(&iam.SimulatePolicyResponse{
		EvaluationResults: []*iam.EvaluationResult{
			{
				EvalDecision:   aws.String("notallowed"),
				EvalActionName: aws.String("SomeAWSAction"),
			},
		},
	}, nil)
}

func validateSecretAnnotation(c client.Client, t *testing.T, value string) {
	secret := getCredSecret(c)
	if secret.ObjectMeta.Annotations == nil {
		t.Errorf("unexpected empty annotations on secret")
	}
	if _, ok := secret.ObjectMeta.Annotations[AnnotationKey]; !ok {
		t.Errorf("missing annotation")
	}

	assert.Exactly(t, value, secret.ObjectMeta.Annotations[AnnotationKey])
}

func getCredSecret(c client.Client) *corev1.Secret {
	secret := &corev1.Secret{}
	if err := c.Get(context.TODO(), client.ObjectKey{Name: testSecretName, Namespace: testNamespace}, secret); err != nil {
		return nil
	}
	return secret
}

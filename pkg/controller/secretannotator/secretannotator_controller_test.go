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
	testAWSAccessKeyID     = "FAKEAWSACCESSKEYID"
	testAWSSecretAccessKey = "KEEPITSECRET"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestSecretAnnotatorReconcile(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)

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
			validateAnnotationValue: mintAnnotation,
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
			validateAnnotationValue: passthroughAnnotation,
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
			validateAnnotationValue: insufficientAnnotation,
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
					awsAccessKeyName:            []byte(testAWSAccessKeyID),
					"not_aws_secret_access_key": []byte(testAWSSecretAccessKey),
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			fakeClient := fake.NewFakeClient(test.existing...)

			fakeAWSClient := mockaws.NewMockClient(mockCtrl)
			if test.mockAWSClient != nil {
				fakeAWSClient = test.mockAWSClient(mockCtrl)
			}

			rcc := &ReconcileCloudCredSecret{
				Client: fakeClient,
				logger: log.WithField("controller", "testController"),
				AWSClientBuilder: func(accessKeyID, secretAccessKey []byte) (ccaws.Client, error) {
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
			awsAccessKeyName:       []byte(testAWSAccessKeyID),
			awsSecretAccessKeyName: []byte(testAWSSecretAccessKey),
		},
	}
	return s
}

func mockGetUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(nil).Return(&iam.GetUserOutput{
		User: &iam.User{
			UserName: aws.String(testAWSUser),
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
	if _, ok := secret.ObjectMeta.Annotations[annotationKey]; !ok {
		t.Errorf("missing annotation")
	}

	assert.Exactly(t, value, secret.ObjectMeta.Annotations[annotationKey])
}

func getCredSecret(c client.Client) *corev1.Secret {
	secret := &corev1.Secret{}
	if err := c.Get(context.TODO(), client.ObjectKey{Name: testSecretName, Namespace: testNamespace}, secret); err != nil {
		return nil
	}
	return secret
}

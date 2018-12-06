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
	"encoding/base64"
	"testing"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	//apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	//"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openshift/cloud-creds/pkg/apis"
	ccv1 "github.com/openshift/cloud-creds/pkg/apis/cloudcreds/v1beta1"
	ccaws "github.com/openshift/cloud-creds/pkg/aws"
	mockaws "github.com/openshift/cloud-creds/pkg/aws/mock"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
)

var c client.Client

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestCredentialsRequestReconcile(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)

	// Utility function to get the test credentials request from the fake client
	getCR := func(c client.Client) *ccv1.CredentialsRequest {
		cr := &ccv1.CredentialsRequest{}
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

	tests := []struct {
		name               string
		existing           []runtime.Object
		expectErr          bool
		buildMockAWSClient func(mockCtrl *gomock.Controller) *mockaws.MockClient
		validate           func(client.Client, *testing.T)
	}{
		{
			name: "add finalizer",
			existing: []runtime.Object{
				func() *ccv1.CredentialsRequest {
					cr := testCredentialsRequest()
					// Remove the finalizer
					cr.ObjectMeta.Finalizers = []string{}
					return cr
				}(),
				testAWSCredsSecret("kube-system", "aws-creds", "akeyid", "secretaccess"),
			},
			buildMockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				if cr == nil || !HasFinalizer(cr, ccv1.FinalizerDeprovision) {
					t.Errorf("did not get expected finalizer")
				}
			},
		},
		{
			name: "new credential",
			existing: []runtime.Object{
				testCredentialsRequest(),
				testAWSCredsSecret("kube-system", "aws-creds", "akeyid", "secretaccess"),
			},
			buildMockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockGetUserNotFound(mockAWSClient)
				mockPutUserPolicy(mockAWSClient)
				mockCreateUser(mockAWSClient)
				mockListAccessKeysEmpty(mockAWSClient)
				mockCreateAccessKey(mockAWSClient)
				return mockAWSClient
			},
			validate: func(c client.Client, t *testing.T) {
				cr := getCR(c)
				if cr == nil || !HasFinalizer(cr, ccv1.FinalizerDeprovision) {
					t.Errorf("did not get expected finalizer")
				}

				targetSecret := getSecret(c)
				if assert.NotNil(t, targetSecret) {
					assert.Equal(t, testAWSAccessKeyID, base64DecodeOrFail(t, targetSecret.Data["aws_access_key_id"]))
					assert.Equal(t, testAWSSecretAccessKey, base64DecodeOrFail(t, targetSecret.Data["aws_secret_access_key"]))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAWSClient := test.buildMockAWSClient(mockCtrl)
			fakeClient := fake.NewFakeClient(test.existing...)
			rcr := &ReconcileCredentialsRequest{
				Client: fakeClient,
				scheme: scheme.Scheme,
				awsClientBuilder: func(accessKeyID, secretAccessKey []byte) (ccaws.Client, error) {
					return mockAWSClient, nil
				},
			}

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
		})
	}
}

const (
	testCRName             = "openshift-component-a"
	testNamespace          = "myproject"
	testClusterName        = "testcluster"
	testClusterID          = "e415fe1c-f894-11e8-8eb2-f2801f1b9fd1"
	secretNamespace        = "openshift-image-registry"
	testSecretName         = "test-secret"
	testSecretNamespace    = "myproject"
	testAWSUser            = "mycluster-test-aws-user"
	testAWSUserID          = "FAKEAWSUSERID"
	testAWSAccessKeyID     = "FAKEAWSACCESSKEYID"
	testAWSSecretAccessKey = "KEEPITSECRET"
)

func testCredentialsRequest() *ccv1.CredentialsRequest {
	return &ccv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testCRName,
			Namespace:   testNamespace,
			Finalizers:  []string{ccv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
		},
		Spec: ccv1.CredentialsRequestSpec{
			ClusterName: testClusterName,
			ClusterID:   testClusterID,
			Secret:      corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			AWS: &ccv1.AWSCreds{
				StatementEntries: []ccv1.StatementEntry{
					{
						Effect: "Allow",
						Action: []string{
							"s3:CreateBucket",
							"s3:DeleteBucket",
						},
						Resource: "*",
					},
				},
			},
		},
		Status: ccv1.CredentialsRequestStatus{
			AWS: &ccv1.AWSStatus{
				User:        testAWSUser,
				AccessKeyID: testAWSAccessKeyID,
			},
		},
	}
}

func testAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			// TODO: these are not properly b64 encoded
			"aws_access_key_id":     []byte(accessKeyID),
			"aws_secret_access_key": []byte(secretAccessKey),
		},
	}
	return s
}

func mockGetUserNotFound(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(nil, awserr.New(iam.ErrCodeNoSuchEntityException, "no such entity", nil))
}

func mockGetUser(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().GetUser(gomock.Any()).Return(
		&iam.GetUserOutput{
			User: &iam.User{
				UserId:   aws.String(testAWSUserID),
				UserName: aws.String(testAWSUser),
				Tags: []*iam.Tag{
					{
						Key:   aws.String("tectonicClusterID"),
						Value: aws.String("testClusterID"),
					},
				},
			},
		}, nil)
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
			},
		}, nil)
}

func mockCreateAccessKey(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().CreateAccessKey(
		&iam.CreateAccessKeyInput{
			UserName: aws.String(testAWSUser),
		}).Return(
		&iam.CreateAccessKeyOutput{
			AccessKey: &iam.AccessKey{
				AccessKeyId:     aws.String(testAWSAccessKeyID),
				SecretAccessKey: aws.String(testAWSSecretAccessKey),
			},
		}, nil)
}

func mockPutUserPolicy(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().PutUserPolicy(gomock.Any()).Return(&iam.PutUserPolicyOutput{}, nil)
}

func base64DecodeOrFail(t *testing.T, data []byte) string {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Logf("error decoding base64")
		t.Fail()
		return ""
	} else {
		return string(decoded)
	}

}

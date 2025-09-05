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

package gcp_test

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

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
	mockgcp "github.com/openshift/cloud-credential-operator/pkg/gcp/mock"

	"google.golang.org/api/cloudresourcemanager/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	anngcp "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/gcp"
	gcputils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/gcp"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testSecretName  = "testsecret"
	testNamespace   = "testproject"
	testInfraName   = "testcluster-abc123"
	testGCPAuthJSON = "SECRETJSON"
)

var (
	mintServicesEnabledMap = map[string]bool{
		"resourcemanager.googleapis.com": true,
		"serviceusage.googleapis.com":    true,
		"iam.googleapis.com":             true,
	}

	passthroughServicesEnabledMap = map[string]bool{
		"resourcemanager.googleapis.com": true,
		"serviceusage.googleapis.com":    true,
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
		mockGCPClient           func(mockCtrl *gomock.Controller) *mockgcp.MockClient
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
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockTestMintQueryTestablePermissionsSuccess(mockGCPClient)
				mockTestMintIamPermissionsSuccess(mockGCPClient)
				mockListMintServicesEnabledSuccess(mockGCPClient)

				return mockGCPClient
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
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				return mockGCPClient
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
			name: "cred passthrough mode",
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockTestMintIamPermissionsFail(mockGCPClient)

				mockTestPassthroughIamPermissionsSuccess(mockGCPClient)
				mockListMintServicesEnabledSuccess(mockGCPClient)

				return mockGCPClient
			},
			validateAnnotationValue: constants.PassthroughAnnotation,
		},
		{
			name: "useless creds",
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockGetProjectName(mockGCPClient)
				mockTestMintIamPermissionsFail(mockGCPClient)

				mockTestPassthroughIamPermissionsFail(mockGCPClient)

				return mockGCPClient
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
			name: "secret missing key",
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
						"not-the-right-key": []byte(testGCPAuthJSON),
					},
				},
			},
			validateAnnotationValue: constants.InsufficientAnnotation,
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
					Platform:           configv1.GCPPlatformType,
					InfrastructureName: testInfraName,
				},
			}

			existing := append(test.existing, infra)

			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(existing...).Build()
			fakeRootCredClient := fake.NewClientBuilder().WithRuntimeObjects(test.existingRootCred...).Build()

			fakeGCPClient := mockgcp.NewMockClient(mockCtrl)
			if test.mockGCPClient != nil {
				fakeGCPClient = test.mockGCPClient(mockCtrl)
			}

			rcc := &anngcp.ReconcileCloudCredSecret{
				Client:         fakeClient,
				RootCredClient: fakeRootCredClient,
				Logger:         log.WithField("controller", "testController"),
				GCPClientBuilder: func(projectName string, authJSON []byte, endpoints []configv1.GCPServiceEndpoint) (ccgcp.Client, error) {
					return fakeGCPClient, nil
				},
			}

			_, err := rcc.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testSecretName,
					Namespace: testNamespace,
				},
			})

			if test.expectErr {
				assert.Error(t, err, "expected error to be returned")
			} else if test.validateAnnotationValue != "" {
				validateSecretAnnotation(fakeRootCredClient, t, test.validateAnnotationValue)
			}
		})
	}
}

func validateSecretAnnotation(c client.Client, t *testing.T, value string) {
	secret := getCredSecret(c)
	validateAnnotation(t, secret, value)
}

func validateAnnotation(t *testing.T, secret *corev1.Secret, annotation string) {
	assert.NotNil(t, secret.ObjectMeta.Annotations, "unexpected empty annotations on secret")

	assert.Contains(t, secret.ObjectMeta.Annotations, constants.AnnotationKey, "didn't find annotation key")

	assert.Exactly(t, annotation, secret.ObjectMeta.Annotations[constants.AnnotationKey])
}

func getCredSecret(c client.Client) *corev1.Secret {
	secret := &corev1.Secret{}
	if err := c.Get(context.TODO(), client.ObjectKey{Name: testSecretName, Namespace: testNamespace}, secret); err != nil {
		return nil
	}
	return secret
}

func testSecret() *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSecretName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			anngcp.GCPAuthJSONKey: []byte(testGCPAuthJSON),
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

func mockGetProjectName(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().GetProjectName().AnyTimes().Return("test-GCP-project")
}

func mockTestMintQueryTestablePermissionsSuccess(mockGCPClient *mockgcp.MockClient) {

	permResponse := []*iamadminpb.Permission{}

	for _, perm := range gcputils.CredMintingPermissions {
		permResponse = append(permResponse, &iamadminpb.Permission{Name: perm})
	}

	mockGCPClient.EXPECT().QueryTestablePermissions(gomock.Any(), gomock.Any()).Return(&iamadminpb.QueryTestablePermissionsResponse{
		Permissions: permResponse,
	}, nil)
}

func mockTestMintIamPermissionsSuccess(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().TestIamPermissions(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.TestIamPermissionsResponse{
		Permissions: gcputils.CredMintingPermissions,
	}, nil)
}

func mockTestPassthroughIamPermissionsSuccess(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().TestIamPermissions(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.TestIamPermissionsResponse{
		Permissions: gcputils.CredPassthroughPermissions,
	}, nil)
}

func mockTestMintIamPermissionsFail(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().TestIamPermissions(gomock.Any(), gomock.Any()).Return(&cloudresourcemanager.TestIamPermissionsResponse{
		Permissions: []string{}, // nothing allowed
	}, nil)
}

func mockTestPassthroughIamPermissionsFail(mockGCPClient *mockgcp.MockClient) {
	// we just want it to return an empty list of permissions
	mockTestMintIamPermissionsFail(mockGCPClient)
}

func mockListMintServicesEnabledSuccess(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServicesEnabled().Return(mintServicesEnabledMap, nil)
}

func mockListPassthroughServicesEnabledSuccess(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().ListServicesEnabled().Return(passthroughServicesEnabledMap, nil)
}

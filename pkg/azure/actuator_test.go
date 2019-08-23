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

package azure_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2015-11-01/resources"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang/mock/gomock"
	openshiftapiv1 "github.com/openshift/api/config/v1"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/azure"
	azuremock "github.com/openshift/cloud-credential-operator/pkg/azure/mock"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace       = "default"
	testAppRegName      = "Test App Reg"
	testAppRegID        = "some-unique-app-id"
	testAppRegObjID     = "some-unique-app-obj-id"
	testCredRequestName = "testCredRequest"
	testRoleName        = "Contributor"
)

var (
	rootSecretMintAnnotation = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      azure.RootSecretName,
			Namespace: azure.RootSecretNamespace,
			Annotations: map[string]string{
				annotatorconst.AnnotationKey: annotatorconst.MintAnnotation,
			},
		},
	}

	azureSpec = &minterv1.AzureProviderSpec{
		RoleBindings: []minterv1.RoleBinding{
			{
				Role: testRoleName,
			},
		},
	}
)

func TestDecodeToUnknown(t *testing.T) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("failed to create codec %#v", err)
	}
	var raw *runtime.RawExtension
	aps := minterv1.AzureProviderSpec{}
	raw, err = codec.EncodeProviderSpec(&aps)
	if err != nil {
		t.Fatalf("failed to encode codec %#v", err)
	}
	unknown := runtime.Unknown{}
	err = codec.DecodeProviderStatus(raw, &unknown)
	if err != nil {
		t.Fatalf("should be able to decode to Unknown %#v", err)
	}
	if unknown.Kind != reflect.TypeOf(minterv1.AzureProviderSpec{}).Name() {
		t.Fatalf("expected decoded kind to be %s but was %s", reflect.TypeOf(minterv1.AzureProviderSpec{}).Name(), unknown.Kind)
	}
}

func TestAnnotations(t *testing.T) {
	var tests = []struct {
		name      string
		in        corev1.Secret
		errRegexp string
	}{
		{"TestValidSecretAnnotation", validRootSecret, ""},
		{"TestBadSecretAnnotation", rootSecretBadAnnotation, "invalid mode"},
		{"TestMissingSecretAnnotation", rootSecretNoAnnotation, "cannot proceed without cloud cred secret annotation.*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fake.NewFakeClient(&tt.in, &validSecret)
			actuator, err := azure.NewActuator(f)
			if err != nil {
				assert.Regexp(t, tt.errRegexp, err)
				assert.Nil(t, actuator)
				return
			}
			assert.Nil(t, err)
			assert.NotNil(t, actuator)
		})
	}
}

func getCredRequest(t *testing.T, c client.Client) *minterv1.CredentialsRequest {
	cr := &minterv1.CredentialsRequest{}
	assert.NoError(t, c.Get(context.TODO(), types.NamespacedName{Namespace: testNamespace, Name: testCredRequestName}, cr))
	return cr
}

func getProviderStatus(t *testing.T, cr *minterv1.CredentialsRequest) minterv1.AzureProviderStatus {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("error creating Azure codec: %v", err)
	}
	azStatus := minterv1.AzureProviderStatus{}

	assert.NoError(t, codec.DecodeProviderStatus(cr.Status.ProviderStatus, &azStatus))

	return azStatus
}

func TestActuator(t *testing.T) {
	if err := openshiftapiv1.Install(scheme.Scheme); err != nil {
		t.Fatal(err)
	}

	if err := minterv1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatal(err)
	}

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("error creating Azure codec: %v", err)
	}

	tests := []struct {
		name                       string
		existing                   []runtime.Object
		mockAppClient              func(*gomock.Controller) *azuremock.MockAppClient
		mockServicePrincipalClient func(*gomock.Controller) *azuremock.MockServicePrincipalClient
		mockRoleDefinitionClient   func(*gomock.Controller) *azuremock.MockRoleDefinitionClient
		mockRoleAssignmentsClient  func(*gomock.Controller) *azuremock.MockRoleAssignmentsClient
		op                         func(*azure.Actuator, *minterv1.CredentialsRequest) error
		credentialsRequest         *minterv1.CredentialsRequest
		expectedErr                error
		validate                   func(*testing.T, client.Client)
	}{
		{
			name:               "Create SP",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)

				azStatus := getProviderStatus(t, cr)
				assert.Equal(t, testAppRegID, azStatus.AppID)

				expectedSPName := fmt.Sprintf("%s-%s", testInfrastructureName, testCredRequestName)
				assert.Equal(t, expectedSPName, azStatus.ServicePrincipalName)
			},
		},
		{
			name:     "Create SP (service principal display name different from expected)",
			existing: defaultExistingObjects(),
			credentialsRequest: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest(t)
				cr.Name = "differentname"
				return cr
			}(),
			mockRoleAssignmentsClient: mockRoleAssignmentClientNoCalls,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			expectedErr: fmt.Errorf("error syncing creds in mint-mode: service principal name \"%v\" retrieved from Azure is different from the name \"%v\" that was requested", generateDisplayName(), testInfrastructureName+"-differentname"),
		},
		{
			name:     "Create SP (service principal name too long)",
			existing: defaultExistingObjects(),
			credentialsRequest: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest(t)
				cr.Name = strings.Repeat("0123456789", 10)
				return cr
			}(),
			mockRoleAssignmentsClient:  mockRoleAssignmentClientNoCalls,
			mockServicePrincipalClient: mockServicePrincipalClientNoCalls,
			mockAppClient:              mockAppClientNoCalls,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			expectedErr: fmt.Errorf("error syncing creds in mint-mode: generated name \"%v\" is longer than 93 characters", testInfrastructureName+"-"+strings.Repeat("0123456789", 10)),
		},
		{
			name:               "Update SP",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Update(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)

				azStatus := getProviderStatus(t, cr)
				assert.Equal(t, testAppRegID, azStatus.AppID)

				expectedSPName := fmt.Sprintf("%s-%s", testInfrastructureName, testCredRequestName)
				assert.Equal(t, expectedSPName, azStatus.ServicePrincipalName)
			},
		},
		{
			name: "Delete SP (no AAD application found)",
			existing: []runtime.Object{
				&clusterInfra,
				&rootSecretMintAnnotation,
				&clusterDNS,
				testCredRequestTargetSecret(testCredentialsRequest(t)),
			},
			credentialsRequest: testCredentialsRequest(t),
			mockAppClient: func(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
				client := azuremock.NewMockAppClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					// return that no AAD was found
					[]graphrbac.Application{}, nil,
				)

				return client
			},
			mockServicePrincipalClient: mockServicePrincipalClientNoCalls,
			mockRoleAssignmentsClient:  mockRoleAssignmentClientNoCalls,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Delete(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)
				s := &corev1.Secret{}
				// secret should be deleted
				assert.Error(t, c.Get(context.TODO(),
					types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Spec.SecretRef.Namespace},
					s),
				)
			},
		},
		{
			name: "Delete SP (AAD application found)",
			existing: []runtime.Object{
				&clusterInfra,
				&rootSecretMintAnnotation,
				&clusterDNS,
				testCredRequestTargetSecret(testCredentialsRequest(t)),
			},
			credentialsRequest: testCredentialsRequest(t),
			mockAppClient: func(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
				client := azuremock.NewMockAppClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]graphrbac.Application{testAADApplication()},
					nil,
				)
				client.EXPECT().Delete(gomock.Any(), testAppRegObjID)

				return client
			},
			mockRoleAssignmentsClient:  mockRoleAssignmentClientNoCalls,
			mockServicePrincipalClient: mockServicePrincipalClientNoCalls,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Delete(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)
				s := &corev1.Secret{}
				// secret should be deleted
				assert.Error(t, c.Get(context.TODO(),
					types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Spec.SecretRef.Namespace},
					s),
				)
			},
		},
		{
			name:               "Tag SP on create",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			mockServicePrincipalClient: func(mockCtrl *gomock.Controller) *azuremock.MockServicePrincipalClient {
				client := azuremock.NewMockServicePrincipalClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return([]graphrbac.ServicePrincipal{}, nil)
				client.EXPECT().Create(gomock.Any(), graphrbac.ServicePrincipalCreateParameters{
					AppID:          to.StringPtr(testAppRegID),
					AccountEnabled: to.BoolPtr(true),
					Tags:           &[]string{fmt.Sprintf("kubernetes.io_cluster.%s=owned", testInfrastructureName)},
				}).Return(testServicePrincipal(), nil)
				return client
			},
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewFakeClient(allObjects...)

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			if test.mockAppClient == nil {
				test.mockAppClient = defaultMockAppClient
			}
			appClient := test.mockAppClient(mockCtrl)

			if test.mockServicePrincipalClient == nil {
				test.mockServicePrincipalClient = defaultMockServicePrincipalClient
			}
			spClient := test.mockServicePrincipalClient(mockCtrl)

			if test.mockRoleDefinitionClient == nil {
				test.mockRoleDefinitionClient = defaultMockRoleDefinitionClient
			}
			rdClient := test.mockRoleDefinitionClient(mockCtrl)

			if test.mockRoleAssignmentsClient == nil {
				test.mockRoleAssignmentsClient = defaultMockRoleAssignmentsClient
			}
			raClient := test.mockRoleAssignmentsClient(mockCtrl)

			actuator := azure.NewFakeActuator(
				fakeClient,
				codec,
				func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*azure.AzureCredentialsMinter, error) {
					return azure.NewFakeAzureCredentialsMinter(logger,
						clientID,
						clientSecret,
						tenantID,
						subscriptionID,
						appClient,
						spClient,
						raClient,
						rdClient,
					)
				},
			)

			testErr := test.op(actuator, test.credentialsRequest)

			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
			} else {
				test.validate(t, fakeClient)
			}

		})
	}
}

func testCredRequestTargetSecret(cr *minterv1.CredentialsRequest) *corev1.Secret {
	s := &corev1.Secret{}
	s.Name = cr.Spec.SecretRef.Name
	s.Namespace = cr.Spec.SecretRef.Namespace

	return s
}

func testAADApplication() graphrbac.Application {
	app := graphrbac.Application{
		AppID:       to.StringPtr(testAppRegID),
		DisplayName: to.StringPtr(generateDisplayName()),
		ObjectID:    to.StringPtr(testAppRegObjID),
	}
	return app
}

func testServicePrincipal() graphrbac.ServicePrincipal {
	sp := graphrbac.ServicePrincipal{
		AppID:       testAADApplication().AppID,
		ObjectID:    to.StringPtr("sp-object-id"),
		DisplayName: to.StringPtr(generateDisplayName()),
	}
	return sp
}

func generateDisplayName() string {
	return fmt.Sprintf("%s-%s", clusterInfra.Status.InfrastructureName, testCredRequestName)
}

func testResourceGroup() resources.Group {
	rg := resources.Group{
		Name: to.StringPtr(testResourceGroupName),
		Tags: map[string]*string{},
	}
	return rg
}

func testCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("error creating Azure codec: %v", err)
	}

	rawObj, err := codec.EncodeProviderSpec(azureSpec)
	if err != nil {
		t.Fatalf("error decoding provider v1 spec: %v", err)
	}

	cr := &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testCredRequestName,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Namespace: "default", Name: "credentials"},
			ProviderSpec: rawObj,
		},
	}

	return cr
}

func defaultMockAppClient(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
	client := azuremock.NewMockAppClient(mockCtrl)
	client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
		[]graphrbac.Application{testAADApplication()}, nil,
	)
	client.EXPECT().UpdatePasswordCredentials(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	return client
}

func mockAppClientNoCalls(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
	client := azuremock.NewMockAppClient(mockCtrl)
	return client
}

func defaultMockServicePrincipalClient(mockCtrl *gomock.Controller) *azuremock.MockServicePrincipalClient {
	client := azuremock.NewMockServicePrincipalClient(mockCtrl)
	client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
		[]graphrbac.ServicePrincipal{},
		nil,
	)
	client.EXPECT().Create(gomock.Any(), gomock.Any()).Return(testServicePrincipal(), nil)
	return client
}

func mockServicePrincipalClientNoCalls(mockCtrl *gomock.Controller) *azuremock.MockServicePrincipalClient {
	client := azuremock.NewMockServicePrincipalClient(mockCtrl)
	return client
}

func testRoleDefinition() authorization.RoleDefinition {
	rd := authorization.RoleDefinition{
		Name: to.StringPtr(testRoleName),
		ID:   to.StringPtr("some-role-def-id"),
	}
	return rd
}

func defaultMockRoleDefinitionClient(mockCtrl *gomock.Controller) *azuremock.MockRoleDefinitionClient {
	client := azuremock.NewMockRoleDefinitionClient(mockCtrl)
	client.EXPECT().List(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		[]authorization.RoleDefinition{testRoleDefinition()},
		nil,
	).AnyTimes()
	return client
}

func mockRoleAssignmentClientNoCalls(mockCtrl *gomock.Controller) *azuremock.MockRoleAssignmentsClient {
	client := azuremock.NewMockRoleAssignmentsClient(mockCtrl)
	return client
}

func testRoleAssignment() authorization.RoleAssignment {
	ra := authorization.RoleAssignment{
		ID: to.StringPtr("some-role-assignment-id"),
		Properties: &authorization.RoleAssignmentPropertiesWithScope{
			RoleDefinitionID: testRoleDefinition().ID,
			Scope:            to.StringPtr(fmt.Sprintf("subscriptions/%s/resourceGroups/%s", "", testResourceGroupName)),
		},
	}
	return ra
}

func defaultMockRoleAssignmentsClient(mockCtrl *gomock.Controller) *azuremock.MockRoleAssignmentsClient {
	client := azuremock.NewMockRoleAssignmentsClient(mockCtrl)
	// one create for the resource group where the cluster lives
	client.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		testRoleAssignment(),
		nil,
	)
	// one create for the resource group where the dns entries exist
	client.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		// code doesn't check the returned roleassignment result, so it's okay
		// to send a generic role assignment.
		testRoleAssignment(),
		nil,
	)
	client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
		[]authorization.RoleAssignment{testRoleAssignment()},
		nil,
	)
	return client
}

func defaultExistingObjects() []runtime.Object {
	objs := []runtime.Object{
		&clusterInfra,
		&rootSecretMintAnnotation,
		&clusterDNS,
	}
	return objs
}

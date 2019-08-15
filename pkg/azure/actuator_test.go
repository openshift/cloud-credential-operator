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
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang/mock/gomock"
	openshiftapiv1 "github.com/openshift/api/config/v1"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/azure"
	azuremock "github.com/openshift/cloud-credential-operator/pkg/azure/mock"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
				Role: "Contributor",
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

func TestActuatorCreateUpdateDelete(t *testing.T) {
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

	rawObj, err := codec.EncodeProviderSpec(azureSpec)
	if err != nil {
		t.Fatalf("error decoding provider v1 spec: %v", err)
	}

	testAADApplication := graphrbac.Application{
		AppID:    to.StringPtr(uuid.NewV4().String()),
		ObjectID: to.StringPtr(uuid.NewV4().String()),
	}

	testAADApplicationList := []graphrbac.Application{testAADApplication}

	testCredentialRequest := &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "CCrequest",
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Namespace: "default", Name: "credentials"},
			ProviderSpec: rawObj,
		},
	}

	testCredentialRequestDifferentName := testCredentialRequest.DeepCopy()
	testCredentialRequestDifferentName.Name = "differentCCrequestName"

	// names with more than 93 characters are invalid
	testCredentialRequestNameTooLong := testCredentialRequest.DeepCopy()
	testCredentialRequestNameTooLong.Name = strings.Repeat("0123456789", 10)

	testServicePrincipal := graphrbac.ServicePrincipal{
		AppID:       testAADApplication.AppID,
		ObjectID:    to.StringPtr(uuid.NewV4().String()),
		DisplayName: to.StringPtr(testCredentialRequest.Name),
	}

	roleDefinitionList := []authorization.RoleDefinition{
		{
			ID: to.StringPtr(uuid.NewV4().String()),
		},
	}

	tests := []struct {
		name                 string
		application          graphrbac.Application
		applicationList      []graphrbac.Application
		servicePrincipal     graphrbac.ServicePrincipal
		servicePrincipalList []graphrbac.ServicePrincipal
		roleDefinitionList   []authorization.RoleDefinition
		roleAssignment       authorization.RoleAssignment
		roleAssignmentList   []authorization.RoleAssignment
		credentialRequest    *minterv1.CredentialsRequest
		op                   func(*azure.Actuator, *minterv1.CredentialsRequest) error
		err                  error
	}{
		{
			name:               "Create SP",
			application:        testAADApplication,
			servicePrincipal:   testServicePrincipal,
			roleDefinitionList: roleDefinitionList,
			credentialRequest:  testCredentialRequest,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
		},
		{
			name:               "Create SP (service principal display name different from expected)",
			application:        testAADApplication,
			servicePrincipal:   testServicePrincipal,
			roleDefinitionList: roleDefinitionList,
			credentialRequest:  testCredentialRequestDifferentName,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			err: fmt.Errorf("error syncing creds in mint-mode: service principal name \"%v\" retrieved from Azure is different from the name \"%v\" that was requested", *testServicePrincipal.DisplayName, testCredentialRequestDifferentName.Name),
		},
		{
			name:               "Create SP (service principal name too long)",
			application:        testAADApplication,
			servicePrincipal:   testServicePrincipal,
			roleDefinitionList: roleDefinitionList,
			credentialRequest:  testCredentialRequestNameTooLong,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			err: fmt.Errorf("error syncing creds in mint-mode: generated name \"%v\" is longer than 93 characters", strings.Repeat("0123456789", 10)),
		},
		{
			name:               "Update SP",
			application:        testAADApplication,
			servicePrincipal:   testServicePrincipal,
			roleDefinitionList: roleDefinitionList,
			credentialRequest:  testCredentialRequest,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Update(context.TODO(), cr)
			},
		},
		{
			name:              "Delete SP (no AAD application found)",
			application:       testAADApplication,
			credentialRequest: testCredentialRequest,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Delete(context.TODO(), cr)
			},
		},
		{
			name:              "Delete SP (AAD application found)",
			applicationList:   testAADApplicationList,
			credentialRequest: testCredentialRequest,
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Delete(context.TODO(), cr)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewFakeClient(&clusterInfra, &rootSecretMintAnnotation, test.credentialRequest)

			mockCtrl := gomock.NewController(t)

			mockAppClient := azuremock.NewMockAppClient(mockCtrl)
			mockSpClient := azuremock.NewMockServicePrincipalClient(mockCtrl)
			mockRoleAssignmentsClient := azuremock.NewMockRoleAssignmentsClient(mockCtrl)
			mockRoleDefinitionClient := azuremock.NewMockRoleDefinitionClient(mockCtrl)

			mockAppClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(test.applicationList, nil).AnyTimes()
			mockAppClient.EXPECT().Create(gomock.Any(), gomock.Any()).Return(test.application, nil).AnyTimes()
			mockAppClient.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			mockSpClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(test.servicePrincipalList, nil).AnyTimes()
			mockSpClient.EXPECT().Create(gomock.Any(), gomock.Any()).Return(test.servicePrincipal, nil).AnyTimes()
			mockRoleDefinitionClient.EXPECT().List(gomock.Any(), gomock.Any(), gomock.Any()).Return(test.roleDefinitionList, nil).AnyTimes()
			mockRoleAssignmentsClient.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(test.roleAssignment, nil).AnyTimes()
			mockRoleAssignmentsClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(test.roleAssignmentList, nil).AnyTimes()

			actuator := azure.NewFakeActuator(
				fakeClient,
				codec,
				func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*azure.AzureCredentialsMinter, error) {
					return azure.NewFakeAzureCredentialsMinter(logger,
						clientID,
						clientSecret,
						tenantID,
						subscriptionID,
						mockAppClient,
						mockSpClient,
						mockRoleAssignmentsClient,
						mockRoleDefinitionClient,
					)
				},
			)

			err = test.op(actuator, test.credentialRequest)
			if err == nil && test.err != nil {
				t.Errorf("Expected error %q, got nil", test.err)
			}
			if err != nil && test.err == nil {
				t.Errorf("Unexpected error %q, expected nil", err)
			}
			if err != nil && test.err != nil {
				if err.Error() != test.err.Error() {
					t.Errorf("Unexpected error %q, expected %q", err, test.err)
				}
			}
		})
	}
}

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
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/microsoftgraph/msgraph-sdk-go/models"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	openshiftapiv1 "github.com/openshift/api/config/v1"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/azure"
	azuremock "github.com/openshift/cloud-credential-operator/pkg/azure/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	validNamespace = "valid-namespace"
	validName      = "valid-name"

	rootClientID       = "root_client_id"
	rootClientSecret   = "root_client_secret"
	rootRegion         = "root_region"
	rootResourceGroup  = "root_resource_group"
	rootResourcePrefix = "root_resource_prefix"
	rootSubscriptionID = "root_subscription_id"
	rootTenantID       = "root_tenant_id"

	mintedClientID     = "minted_client_id"
	mintedClientSecret = "minted_client_secret"

	testNamespace          = "default"
	testAppRegName         = "Test App Reg"
	testAppRegID           = "some-unique-app-id"
	testAppRegObjID        = "some-unique-app-obj-id"
	testCredRequestName    = "testCredRequest"
	testRandomSuffix       = "rando"
	testRoleName           = "Contributor"
	testRoleDefinitionID   = "some-role-def-id"
	testResourceGroupName  = "Test Resource Group"
	testInfrastructureName = "test-cluster-abcd"

	testTargetSecretNamespace = "my-namespace"
	testTargetSecretName      = "my-secret"

	workloadIdentityRegion         = "wi_region"
	workloadIdentityClientID       = "wi_client_id"
	workloadIdentityTenantID       = "wi_tenant_id"
	workloadIdentitySubscriptionID = "wi_subscription_id"
)

var (
	rootSecretMintAnnotation = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AzureCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.MintAnnotation,
			},
			ResourceVersion: "rootResourceVersion",
		},
	}

	azureSpec = &minterv1.AzureProviderSpec{
		RoleBindings: []minterv1.RoleBinding{
			{
				Role: testRoleName,
			},
		},
	}

	validPassthroughRootSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AzureCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.PassthroughAnnotation,
			},
		},
		Data: map[string][]byte{
			azure.AzureClientID:       []byte(rootClientID),
			azure.AzureClientSecret:   []byte(rootClientSecret),
			azure.AzureRegion:         []byte(rootRegion),
			azure.AzureResourceGroup:  []byte(rootResourceGroup),
			azure.AzureResourcePrefix: []byte(rootResourcePrefix),
			azure.AzureSubscriptionID: []byte(rootSubscriptionID),
			azure.AzureTenantID:       []byte(rootTenantID),
		},
	}

	validWorkloadIdentitySecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testTargetSecretName,
			Namespace: testTargetSecretNamespace,
		},
		StringData: map[string]string{
			azure.AzureClientID:           workloadIdentityClientID,
			azure.AzureTenantID:           workloadIdentityTenantID,
			azure.AzureRegion:             workloadIdentityRegion,
			azure.AzureSubscriptionID:     workloadIdentitySubscriptionID,
			azure.AzureFederatedTokenFile: provisioning.OidcTokenPath,
		},
	}

	rootSecretNoAnnotation = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.AzureCloudCredSecretName,
			Namespace:   constants.CloudCredSecretNamespace,
			Annotations: map[string]string{},
		},
	}

	clusterInfra = openshiftapiv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: openshiftapiv1.InfrastructureStatus{
			InfrastructureName: testInfrastructureName,
			PlatformStatus: &openshiftapiv1.PlatformStatus{
				Azure: &openshiftapiv1.AzurePlatformStatus{
					ResourceGroupName: testResourceGroupName,
				},
			},
		},
	}

	testDNSResourceGroupName = "os4-common"
	clusterDNS               = openshiftapiv1.DNS{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: openshiftapiv1.DNSSpec{
			PublicZone: &openshiftapiv1.DNSZone{
				ID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/" + testDNSResourceGroupName + "/providers/Microsoft.Network/dnszones/devcluster.openshift.com",
			},
		},
	}
)

func TestDecodeToUnknown(t *testing.T) {
	var err error
	var raw *runtime.RawExtension
	aps := minterv1.AzureProviderSpec{}
	raw, err = minterv1.Codec.EncodeProviderSpec(&aps)
	if err != nil {
		t.Fatalf("failed to encode codec %#v", err)
	}
	unknown := runtime.Unknown{}
	err = minterv1.Codec.DecodeProviderStatus(raw, &unknown)
	if err != nil {
		t.Fatalf("should be able to decode to Unknown %#v", err)
	}
	if unknown.Kind != reflect.TypeOf(minterv1.AzureProviderSpec{}).Name() {
		t.Fatalf("expected decoded kind to be %s but was %s", reflect.TypeOf(minterv1.AzureProviderSpec{}).Name(), unknown.Kind)
	}
}

func getCredRequest(t *testing.T, c client.Client) *minterv1.CredentialsRequest {
	cr := &minterv1.CredentialsRequest{}
	require.NoError(t, c.Get(context.TODO(), types.NamespacedName{Namespace: testNamespace, Name: testCredRequestName}, cr), "error while retriving credreq from fake client")
	return cr
}

func getProviderStatus(t *testing.T, cr *minterv1.CredentialsRequest) minterv1.AzureProviderStatus {
	azStatus := minterv1.AzureProviderStatus{}

	assert.NoError(t, minterv1.Codec.DecodeProviderStatus(cr.Status.ProviderStatus, &azStatus))

	return azStatus
}

func TestActuator(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		existing           []runtime.Object
		existingAdmin      []runtime.Object
		mockAppClient      func(*gomock.Controller) *azuremock.MockAppClient
		op                 func(*azure.Actuator, *minterv1.CredentialsRequest) error
		credentialsRequest *minterv1.CredentialsRequest
		expectedErr        error
		validate           func(*testing.T, client.Client, client.Client)
	}{
		{
			name: "Process a CredentialsRequest",
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))
				return objects
			}(),
			existingAdmin:      []runtime.Object{&validPassthroughRootSecret},
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client, adminC client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, adminC)

				assertSecretEquality(t, rootSecret, targetSecret)
			},
		},
		{
			name: "Migrate to passthrough",
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()

				// Add the existing targetSecret since we are mocking up
				// a previously minted scenario.
				targetSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testTargetSecretName,
						Namespace: testTargetSecretNamespace,
					},
					Data: map[string][]byte{
						azure.AzureClientID:       []byte(mintedClientID),
						azure.AzureClientSecret:   []byte(mintedClientSecret),
						azure.AzureRegion:         []byte(rootRegion),
						azure.AzureResourceGroup:  []byte(rootResourceGroup),
						azure.AzureResourcePrefix: []byte(rootResourcePrefix),
						azure.AzureSubscriptionID: []byte(rootSubscriptionID),
						azure.AzureTenantID:       []byte(rootTenantID),
					},
				}

				objects = append(objects, targetSecret)
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))

				return objects
			}(),
			existingAdmin: []runtime.Object{&validPassthroughRootSecret},
			credentialsRequest: func() *minterv1.CredentialsRequest {
				// Create a credreq that resembles what one previously handled via mint mode
				// would look like.
				cr := testCredentialsRequest(t)

				rawStatus := &minterv1.AzureProviderStatus{
					ServicePrincipalName:      testAppRegName,
					AppID:                     testAppRegID,
					SecretLastResourceVersion: "oldVersion",
				}
				encodedStatus, err := minterv1.Codec.EncodeProviderStatus(rawStatus)
				require.NoError(t, err, "error encoding status")

				cr.Status.ProviderStatus = encodedStatus
				cr.Status.Provisioned = true

				// to appear that we need an update
				cr.Status.LastSyncCloudCredsSecretResourceVersion = "oldResourceVersion"

				return cr
			}(),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Update(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client, adminC client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, adminC)

				// Post mint-to-passthrough pivot the targetSecret should be a copy of the
				// root secret.
				assertSecretEquality(t, rootSecret, targetSecret)

				// Make sure we've cleared out the old fields
				azureStatus := getProviderStatus(t, cr)
				assert.Empty(t, azureStatus.AppID, "expected AppID to be empty after cleanup")
				assert.Empty(t, azureStatus.ServicePrincipalName, "expected ServicePrincipalName to be empty after cleanup")
				assert.Empty(t, azureStatus.SecretLastResourceVersion, "expected SecretLatResourceVersion to be empty after cleanup")
			},
			mockAppClient: func(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
				client := azuremock.NewMockAppClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]models.Applicationable{testAADApplication()}, nil,
				)
				client.EXPECT().Delete(gomock.Any(), testAppRegObjID)
				return client
			},
		},
		{
			name: "Migrated but still need to cleanup",
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()

				// Add the existing targetSecret since we are mocking up
				// a previously migrated scenario.
				targetSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testTargetSecretName,
						Namespace: testTargetSecretNamespace,
					},
					Data: map[string][]byte{
						azure.AzureClientID:       []byte(rootClientID),
						azure.AzureClientSecret:   []byte(rootClientSecret),
						azure.AzureRegion:         []byte(rootRegion),
						azure.AzureResourceGroup:  []byte(rootResourceGroup),
						azure.AzureResourcePrefix: []byte(rootResourcePrefix),
						azure.AzureSubscriptionID: []byte(rootSubscriptionID),
						azure.AzureTenantID:       []byte(rootTenantID),
					},
				}

				objects = append(objects, targetSecret)
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))

				return objects
			}(),
			existingAdmin: []runtime.Object{&validPassthroughRootSecret},
			credentialsRequest: func() *minterv1.CredentialsRequest {
				// Create a credreq that resembles what one previously handled via mint mode
				// would look like.
				cr := testCredentialsRequest(t)

				rawStatus := &minterv1.AzureProviderStatus{
					ServicePrincipalName: testAppRegName,
					AppID:                testAppRegID,
					// SecretLastResourceVersion: "oldVersion",
				}
				encodedStatus, err := minterv1.Codec.EncodeProviderStatus(rawStatus)
				require.NoError(t, err, "error encoding status")

				cr.Status.ProviderStatus = encodedStatus
				cr.Status.Provisioned = true

				// to appear that we need an update
				cr.Status.LastSyncTimestamp = &metav1.Time{
					Time: time.Now().Add(-time.Hour * 2),
				}

				return cr
			}(),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Update(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client, adminC client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, adminC)

				// The targetSecret should be a copy of the root secret.
				assertSecretEquality(t, rootSecret, targetSecret)

				// Make sure we've cleared out the old fields
				azureStatus := getProviderStatus(t, cr)
				assert.Empty(t, azureStatus.AppID, "expected AppID to be empty after cleanup")
				assert.Empty(t, azureStatus.ServicePrincipalName, "expected ServicePrincipalName to be empty after cleanup")
				assert.Empty(t, azureStatus.SecretLastResourceVersion, "expected SecretLatResourceVersion to be empty after cleanup")
			},
			mockAppClient: func(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
				client := azuremock.NewMockAppClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]models.Applicationable{testAADApplication()}, nil,
				)
				client.EXPECT().Delete(gomock.Any(), testAppRegObjID)
				return client
			},
		},
		{
			name: "Failed to cleanup",
			expectedErr: &actuatoriface.ActuatorError{
				ErrReason: minterv1.OrphanedCloudResource,
				Message:   fmt.Sprintf("unable to clean up App Registration / Service Principal: %s", testAppRegName),
			},
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()

				// Add the existing targetSecret since we are mocking up
				// a previously migrated scenario.
				targetSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testTargetSecretName,
						Namespace: testTargetSecretNamespace,
					},
					Data: map[string][]byte{
						azure.AzureClientID:       []byte(mintedClientID),
						azure.AzureClientSecret:   []byte(mintedClientSecret),
						azure.AzureRegion:         []byte(rootRegion),
						azure.AzureResourceGroup:  []byte(rootResourceGroup),
						azure.AzureResourcePrefix: []byte(rootResourcePrefix),
						azure.AzureSubscriptionID: []byte(rootSubscriptionID),
						azure.AzureTenantID:       []byte(rootTenantID),
					},
				}

				objects = append(objects, targetSecret)
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))

				return objects
			}(),
			existingAdmin: []runtime.Object{&validPassthroughRootSecret},
			credentialsRequest: func() *minterv1.CredentialsRequest {
				// Create a credreq that resembles what one previously handled via mint mode
				// would look like.
				cr := testCredentialsRequest(t)

				rawStatus := &minterv1.AzureProviderStatus{
					ServicePrincipalName: testAppRegName,
					AppID:                testAppRegID,
				}
				encodedStatus, err := minterv1.Codec.EncodeProviderStatus(rawStatus)
				require.NoError(t, err, "error encoding status")

				cr.Status.ProviderStatus = encodedStatus
				cr.Status.Provisioned = true

				return cr
			}(),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Update(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client, adminC client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, adminC)

				// The targetSecret should be a copy of the root secret.
				assertSecretEquality(t, rootSecret, targetSecret)
			},
			mockAppClient: func(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
				client := azuremock.NewMockAppClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]models.Applicationable{}, fmt.Errorf("Azure AD Graph API has been sunset"),
				)
				// No Delete() call b/c of List() error above
				return client
			},
		},
		{
			name:        "Missing annotation",
			expectedErr: fmt.Errorf("error determining whether a credentials update is needed"),
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()
				// Add the existing targetSecret since we are mocking up
				// a previously migrated scenario.
				targetSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testTargetSecretName,
						Namespace: testTargetSecretNamespace,
					},
					Data: map[string][]byte{
						azure.AzureClientID:       []byte(mintedClientID),
						azure.AzureClientSecret:   []byte(mintedClientSecret),
						azure.AzureRegion:         []byte(rootRegion),
						azure.AzureResourceGroup:  []byte(rootResourceGroup),
						azure.AzureResourcePrefix: []byte(rootResourcePrefix),
						azure.AzureSubscriptionID: []byte(rootSubscriptionID),
						azure.AzureTenantID:       []byte(rootTenantID),
					},
				}

				objects = append(objects, targetSecret)
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))
				return objects
			}(),
			existingAdmin:      []runtime.Object{&rootSecretNoAnnotation},
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
		},
		{
			name:        "Mint annotation",
			expectedErr: fmt.Errorf("unexpected value or missing cloudcredential.openshift.io/mode annotation on admin credentials Secret"),
			existing: func() []runtime.Object {
				// Note: required now because of the isTimedToken() function
				objects := defaultExistingObjects()
				// Add the existing targetSecret since we are mocking up
				// a previously migrated scenario.
				targetSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testTargetSecretName,
						Namespace: testTargetSecretNamespace,
					},
					Data: map[string][]byte{
						azure.AzureClientID:       []byte(mintedClientID),
						azure.AzureClientSecret:   []byte(mintedClientSecret),
						azure.AzureRegion:         []byte(rootRegion),
						azure.AzureResourceGroup:  []byte(rootResourceGroup),
						azure.AzureResourcePrefix: []byte(rootResourcePrefix),
						azure.AzureSubscriptionID: []byte(rootSubscriptionID),
						azure.AzureTenantID:       []byte(rootTenantID),
					},
				}

				objects = append(objects, targetSecret)
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModePassthrough))
				return objects
			}(),
			existingAdmin:      []runtime.Object{&rootSecretMintAnnotation},
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithStatusSubresource(&minterv1.CredentialsRequest{}).
				WithRuntimeObjects(allObjects...).Build()
			fakeAdminClient := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithRuntimeObjects(test.existingAdmin...).Build()
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			if test.mockAppClient == nil {
				test.mockAppClient = mockAppClientNoCalls
			}
			appClient := test.mockAppClient(mockCtrl)

			actuator := azure.NewFakeActuator(
				fakeClient,
				fakeAdminClient,
				func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*azure.AzureCredentialsMinter, error) {
					return azure.NewFakeAzureCredentialsMinter(logger,
						clientID,
						clientSecret,
						tenantID,
						subscriptionID,
						appClient,
					)
				},
			)

			testErr := test.op(actuator, test.credentialsRequest)

			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
				if test.validate != nil {
					test.validate(t, fakeClient, fakeAdminClient)
				}
			} else {
				require.NoError(t, testErr, "unexpected error returned during test case")
				test.validate(t, fakeClient, fakeAdminClient)
			}
		})
	}
}

func TestActuatorCreateOnWorkloadIdentity(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name          string
		existing      []runtime.Object
		cr            *minterv1.CredentialsRequest
		mockAppClient func(*gomock.Controller) *azuremock.MockAppClient
		wantErr       assert.ErrorAssertionFunc
		validate      func(*testing.T, client.Client)
	}{
		{
			name: "Correctly configured Azure Workload Identity fields",
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()
				objects = append(objects, testAuthentication("issuer"))
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModeManual))
				return objects
			}(),
			cr: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest(t)

				azureSpec := &minterv1.AzureProviderSpec{}
				err := minterv1.Codec.DecodeProviderSpec(cr.Spec.ProviderSpec, azureSpec)
				require.NoError(t, err, "error decoding provider spec")

				azureSpec.AzureClientID = workloadIdentityClientID
				azureSpec.AzureTenantID = workloadIdentityTenantID
				azureSpec.AzureRegion = workloadIdentityTenantID
				azureSpec.AzureSubscriptionID = workloadIdentitySubscriptionID

				encodedSpec, err := json.Marshal(azureSpec)
				require.NoError(t, err, "error encoding provider spec")
				cr.Spec.ProviderSpec = &runtime.RawExtension{Raw: encodedSpec}

				return cr
			}(),
			mockAppClient: func(ctrl *gomock.Controller) *azuremock.MockAppClient {
				return azuremock.NewMockAppClient(ctrl)
			},
			wantErr: assert.NoError,
			validate: func(t *testing.T, c client.Client) {
				expectedSecret := &corev1.Secret{}
				err := c.Get(context.TODO(), types.NamespacedName{Name: testTargetSecretName, Namespace: testTargetSecretNamespace}, expectedSecret)
				require.NoError(t, err)
			},
		},
		{
			name: "Incorrectly configured Azure Workload Identity fields",
			existing: func() []runtime.Object {
				objects := defaultExistingObjects()
				objects = append(objects, testAuthentication("issuer"))
				objects = append(objects, testOperatorConfig(operatorv1.CloudCredentialsModeManual))
				return objects
			}(),
			cr: func() *minterv1.CredentialsRequest {
				cr := testCredentialsRequest(t)

				azureSpec := &minterv1.AzureProviderSpec{}
				err := minterv1.Codec.DecodeProviderSpec(cr.Spec.ProviderSpec, azureSpec)
				require.NoError(t, err, "error decoding provider spec")

				azureSpec.AzureClientID = ""
				azureSpec.AzureTenantID = workloadIdentityTenantID
				azureSpec.AzureRegion = workloadIdentityTenantID
				azureSpec.AzureSubscriptionID = ""

				encodedSpec, err := json.Marshal(azureSpec)
				require.NoError(t, err, "error encoding provider spec")
				cr.Spec.ProviderSpec = &runtime.RawExtension{Raw: encodedSpec}

				return cr
			}(),
			mockAppClient: func(ctrl *gomock.Controller) *azuremock.MockAppClient {
				return azuremock.NewMockAppClient(ctrl)
			},
			wantErr:  assert.Error,
			validate: nil,
		},
	}

	for _, test := range tests {

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(test.cr).
			WithRuntimeObjects(test.existing...).Build()

		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			appClient := test.mockAppClient(ctrl)

			act := azure.NewFakeActuator(
				fakeClient,
				fakeClient,
				func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*azure.AzureCredentialsMinter, error) {
					return azure.NewFakeAzureCredentialsMinter(logger, clientID, clientSecret, tenantID, subscriptionID, appClient)
				},
			)

			ctx := context.TODO()
			err := act.Create(ctx, test.cr)

			test.wantErr(t, err)

			if test.validate != nil {
				test.validate(t, fakeClient)
			}

			ctrl.Finish()
		})
	}
}

func getCredRequestTargetSecret(t *testing.T, c client.Client, cr *minterv1.CredentialsRequest) *corev1.Secret {
	s := &corev1.Secret{}
	sKey := types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}

	err := c.Get(context.TODO(), sKey, s)
	require.NoError(t, err, "unexpected error while fetching target secret")

	return s
}

func testAADApplication() models.Applicationable {
	app := models.NewApplication()
	appId := testAppRegID
	app.SetAppId(&appId)
	objId := testAppRegObjID
	app.SetId(&objId)
	name := generateDisplayName()
	app.SetDisplayName(&name)

	return app
}

func generateDisplayName() string {
	name, _ := testGenerateServicePrincipalName(testInfrastructureName, testCredRequestName)
	return name
}

func testCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	rawObj, err := minterv1.Codec.EncodeProviderSpec(azureSpec)
	if err != nil {
		t.Fatalf("error decoding provider v1 spec: %v", err)
	}

	cr := &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testCredRequestName,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Namespace: testTargetSecretNamespace, Name: testTargetSecretName},
			ProviderSpec: rawObj,
		},
	}

	return cr
}

func mockAppClientNoCalls(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
	client := azuremock.NewMockAppClient(mockCtrl)
	return client
}

func defaultExistingObjects() []runtime.Object {
	objs := []runtime.Object{
		&clusterInfra,
		&clusterDNS,
	}
	return objs
}

func testGenerateServicePrincipalName(infraName string, credName string) (string, error) {
	generated, err := utils.GenerateNameWithFieldLimits(infraName, 32, credName, 54)
	if err != nil {
		panic(fmt.Sprintf("test case input causing name generation errors: %v", err))
	}
	generated = generated + "-" + testRandomSuffix
	return generated, nil
}

func getRootSecret(t *testing.T, c client.Client) *corev1.Secret {
	rootSecretKey := types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.AzureCloudCredSecretName}
	rootSecret := &corev1.Secret{}
	err := c.Get(context.TODO(), rootSecretKey, rootSecret)
	require.NoError(t, err, "error fetching root secret from fake client")
	return rootSecret
}

func assertSecretEquality(t *testing.T, expectedSecret, assertingSecret *corev1.Secret) {
	assert.Equal(t, expectedSecret.Data[azure.AzureClientID], assertingSecret.Data[azure.AzureClientID])
	assert.Equal(t, expectedSecret.Data[azure.AzureClientSecret], assertingSecret.Data[azure.AzureClientSecret])
	assert.Equal(t, expectedSecret.Data[azure.AzureRegion], assertingSecret.Data[azure.AzureRegion])
	assert.Equal(t, expectedSecret.Data[azure.AzureResourceGroup], assertingSecret.Data[azure.AzureResourceGroup])
	assert.Equal(t, expectedSecret.Data[azure.AzureResourcePrefix], assertingSecret.Data[azure.AzureResourcePrefix])
	assert.Equal(t, expectedSecret.Data[azure.AzureSubscriptionID], assertingSecret.Data[azure.AzureSubscriptionID])
	assert.Equal(t, expectedSecret.Data[azure.AzureTenantID], assertingSecret.Data[azure.AzureTenantID])
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

func testAuthentication(issuer string) *openshiftapiv1.Authentication {
	return &openshiftapiv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: openshiftapiv1.AuthenticationSpec{
			ServiceAccountIssuer: "non-empty",
		},
		Status: openshiftapiv1.AuthenticationStatus{
			IntegratedOAuthMetadata: openshiftapiv1.ConfigMapNameReference{
				Name: issuer,
			},
		},
	}
}

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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/to"

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

	rootSecretBadAnnotation = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.AzureCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
			Annotations: map[string]string{
				constants.AnnotationKey: "blah",
			},
		},
	}

	rootSecretNoAnnotation = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.AzureCloudCredSecretName,
			Namespace:   constants.CloudCredSecretNamespace,
			Annotations: map[string]string{},
		},
	}

	validSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      validName,
			Namespace: validNamespace,
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
		{"TestValidSecretAnnotation", validPassthroughRootSecret, ""},
		{"TestBadSecretAnnotation", rootSecretBadAnnotation, "invalid mode"},
		{"TestMissingSecretAnnotation", rootSecretNoAnnotation, "cannot proceed without cloud cred secret annotation.*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fake.NewClientBuilder().WithRuntimeObjects(&tt.in, &validSecret).Build()
			actuator, err := azure.NewActuator(f, openshiftapiv1.AzurePublicCloud)
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
	require.NoError(t, c.Get(context.TODO(), types.NamespacedName{Namespace: testNamespace, Name: testCredRequestName}, cr), "error while retriving credreq from fake client")
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
		name               string
		existing           []runtime.Object
		mockAppClient      func(*gomock.Controller) *azuremock.MockAppClient
		op                 func(*azure.Actuator, *minterv1.CredentialsRequest) error
		credentialsRequest *minterv1.CredentialsRequest
		expectedErr        error
		validate           func(*testing.T, client.Client)
	}{
		{
			name:               "Process a CredentialsRequest",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, c)

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

				return objects
			}(),
			credentialsRequest: func() *minterv1.CredentialsRequest {
				// Create a credreq that resembles what one previously handled via mint mode
				// would look like.
				cr := testCredentialsRequest(t)

				rawStatus := &minterv1.AzureProviderStatus{
					ServicePrincipalName:      testAppRegName,
					AppID:                     testAppRegID,
					SecretLastResourceVersion: "oldVersion",
				}
				encodedStatus, err := codec.EncodeProviderStatus(rawStatus)
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
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, c)

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
					[]graphrbac.Application{testAADApplication()}, nil,
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

				return objects
			}(),
			credentialsRequest: func() *minterv1.CredentialsRequest {
				// Create a credreq that resembles what one previously handled via mint mode
				// would look like.
				cr := testCredentialsRequest(t)

				rawStatus := &minterv1.AzureProviderStatus{
					ServicePrincipalName: testAppRegName,
					AppID:                testAppRegID,
					//SecretLastResourceVersion: "oldVersion",
				}
				encodedStatus, err := codec.EncodeProviderStatus(rawStatus)
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
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, c)

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
					[]graphrbac.Application{testAADApplication()}, nil,
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

				return objects
			}(),
			credentialsRequest: func() *minterv1.CredentialsRequest {
				// Create a credreq that resembles what one previously handled via mint mode
				// would look like.
				cr := testCredentialsRequest(t)

				rawStatus := &minterv1.AzureProviderStatus{
					ServicePrincipalName: testAppRegName,
					AppID:                testAppRegID,
				}
				encodedStatus, err := codec.EncodeProviderStatus(rawStatus)
				require.NoError(t, err, "error encoding status")

				cr.Status.ProviderStatus = encodedStatus
				cr.Status.Provisioned = true

				return cr
			}(),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Update(context.TODO(), cr)
			},
			validate: func(t *testing.T, c client.Client) {
				cr := getCredRequest(t, c)

				targetSecret := getCredRequestTargetSecret(t, c, cr)

				rootSecret := getRootSecret(t, c)

				// The targetSecret should be a copy of the root secret.
				assertSecretEquality(t, rootSecret, targetSecret)
			},
			mockAppClient: func(mockCtrl *gomock.Controller) *azuremock.MockAppClient {
				client := azuremock.NewMockAppClient(mockCtrl)
				client.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]graphrbac.Application{}, fmt.Errorf("Azure AD Graph API has been sunset"),
				)
				// No Delete() call b/c of List() error above
				return client
			},
		},
		{
			name:        "Missing annotation",
			expectedErr: fmt.Errorf("error determining whether a credentials update is needed"),
			existing: func() []runtime.Object {

				objects := []runtime.Object{&rootSecretNoAnnotation}

				return objects
			}(),
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
		},
		{
			name:        "Mint annotation",
			expectedErr: fmt.Errorf("error determining whether a credentials update is needed"),
			existing: func() []runtime.Object {

				objects := []runtime.Object{&rootSecretMintAnnotation}

				return objects
			}(),
			credentialsRequest: testCredentialsRequest(t),
			op: func(actuator *azure.Actuator, cr *minterv1.CredentialsRequest) error {
				return actuator.Create(context.TODO(), cr)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(allObjects...).Build()

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			if test.mockAppClient == nil {
				test.mockAppClient = mockAppClientNoCalls
			}
			appClient := test.mockAppClient(mockCtrl)

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
					)
				},
			)

			testErr := test.op(actuator, test.credentialsRequest)

			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
				if test.validate != nil {
					test.validate(t, fakeClient)
				}
			} else {
				require.NoError(t, testErr, "unexpected error returned during test case")
				test.validate(t, fakeClient)
			}

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

func testAADApplication() graphrbac.Application {
	app := graphrbac.Application{
		AppID:       to.StringPtr(testAppRegID),
		DisplayName: to.StringPtr(generateDisplayName()),
		ObjectID:    to.StringPtr(testAppRegObjID),
	}
	return app
}

func generateDisplayName() string {
	name, _ := testGenerateServicePrincipalName(testInfrastructureName, testCredRequestName)
	return name
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
		&validPassthroughRootSecret,
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

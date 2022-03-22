/*
Copyright 2021 The OpenShift Authors.
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
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest/to"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	azureactuator "github.com/openshift/cloud-credential-operator/pkg/azure"
	mockazure "github.com/openshift/cloud-credential-operator/pkg/azure/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testAzureClientID            = "azureClientID"
	testAzureClientSecret        = "azureClientSecret"
	testAzureRegion              = "azureRegion"
	testAzureResourceGroup       = "azureResourceGroup"
	testAzureResourceGroupPrefix = "azureResourceGroupPrefix"
	testAzureSubscriptionID      = "azureSubscriptionID"
	testAzureTenantID            = "azureTenantID"

	testAzureAppRegObjectID = "some-unique-app-reg-obj-id"
)

var (
	testAzureMintedAppRegistration = graphrbac.Application{
		AppID:       to.StringPtr("some-unique-app-reg-id"),
		DisplayName: to.StringPtr("MintedAppRegistration"),
		ObjectID:    to.StringPtr(testAzureAppRegObjectID),
	}
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestCredentialsRequestAzureReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	codec, err := minterv1.NewCodec()
	if err != nil {
		fmt.Printf("error creating codec: %v", err)
		t.FailNow()
		return
	}

	tests := []struct {
		name               string
		existing           []runtime.Object
		expectErr          bool
		mockAzureAppClient func(mockCtrl *gomock.Controller) *mockazure.MockAppClient
		validate           func(client.Client, *testing.T)
		// Expected conditions on the credentials request:
		expectedConditions []ExpectedCondition
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []ExpectedCOCondition
	}{
		{
			name: "new credential",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testAzureCredsSecret(constants.CloudCredSecretNamespace, constants.AzureCloudCredSecretName),
				testAzureCredentialsRequest(t),
			},
			mockAzureAppClient: func(mockCtrl *gomock.Controller) *mockazure.MockAppClient {
				return mockazure.NewMockAppClient(mockCtrl)
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// most of these checks are done at the actuator-specific testing, so just a high level sanity check here...
				assert.Equal(t, testAzureClientID, string(targetSecret.Data[azureactuator.AzureClientID]), "unexpected AzureClientID field set in target secret")

				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "orphaned cloud resources",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testAzureCredsSecret(constants.CloudCredSecretNamespace, constants.AzureCloudCredSecretName),
				testAzureCredentialsRequestNeedingCleanup(t),
				testAzureTargetSecret(testSecretNamespace, testSecretName, "mintedAzureClientID"),
			},
			mockAzureAppClient: func(mockCtrl *gomock.Controller) *mockazure.MockAppClient {
				mockAzureAppClient := mockazure.NewMockAppClient(mockCtrl)
				mockAzureAppClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]graphrbac.Application{}, fmt.Errorf("Azure AD Graph API has been sunset"),
				)
				// No Delete() call b/c of List() error above
				return mockAzureAppClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// most of these checks are done at the actuator-specific testing, so just a high level sanity check here...
				assert.Equal(t, testAzureClientID, string(targetSecret.Data[azureactuator.AzureClientID]), "unexpected AzureClientID field set in target secret")

				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.OrphanedCloudResource,
					reason:        cloudResourceOrphaned,
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "clear orphaned cloud resources condition",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testAzureCredsSecret(constants.CloudCredSecretNamespace, constants.AzureCloudCredSecretName),
				testAzureCredentialsRequestWithOrphanedCloudResource(t),
				testAzureTargetSecret(testSecretNamespace, testSecretName, testAzureClientID),
			},
			mockAzureAppClient: func(mockCtrl *gomock.Controller) *mockazure.MockAppClient {
				mockAzureAppClient := mockazure.NewMockAppClient(mockCtrl)
				mockAzureAppClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(
					[]graphrbac.Application{testAzureMintedAppRegistration}, nil,
				)
				mockAzureAppClient.EXPECT().Delete(gomock.Any(), testAzureAppRegObjectID)
				return mockAzureAppClient
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// most of these checks are done at the actuator-specific testing, so just a high level sanity check here...
				assert.Equal(t, testAzureClientID, string(targetSecret.Data[azureactuator.AzureClientID]), "unexpected AzureClientID field set in target secret")

				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.OrphanedCloudResource,
					reason:        cloudResourceCleaned,
					status:        corev1.ConditionFalse,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAzureAppClient := mockazure.NewMockAppClient(mockCtrl)
			if test.mockAzureAppClient != nil {
				mockAzureAppClient = test.mockAzureAppClient(mockCtrl)
			}

			fakeClient := fake.NewFakeClient(test.existing...)

			azureActuator := azureactuator.NewFakeActuator(
				fakeClient,
				codec,
				func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*azureactuator.AzureCredentialsMinter, error) {
					return azureactuator.NewFakeAzureCredentialsMinter(logger,
						clientID,
						clientSecret,
						tenantID,
						subscriptionID,
						mockAzureAppClient,
					)
				},
			)
			rcr := &ReconcileCredentialsRequest{
				Client:       fakeClient,
				Actuator:     azureActuator,
				platformType: configv1.AzurePlatformType,
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

			cr := getCredRequest(fakeClient)
			assert.Equal(t, len(test.expectedConditions), len(cr.Status.Conditions), "number of expected conditions doesn't match actual number of conditions")
			for _, condition := range test.expectedConditions {
				foundCondition := utils.FindCredentialsRequestCondition(cr.Status.Conditions, condition.conditionType)
				assert.NotNil(t, foundCondition)
				assert.Exactly(t, condition.status, foundCondition.Status)
				assert.Exactly(t, condition.reason, foundCondition.Reason)
			}

			if test.expectedCOConditions != nil {
				logger := log.WithFields(log.Fields{"controller": controllerName})
				currentConditions, err := rcr.GetConditions(logger)
				require.NoError(t, err, "failed getting conditions")

				for _, expectedCondition := range test.expectedCOConditions {
					foundCondition := utils.FindClusterOperatorCondition(currentConditions, expectedCondition.conditionType)
					require.NotNil(t, foundCondition)
					assert.Equal(t, string(expectedCondition.status), string(foundCondition.Status), "condition %s had unexpected status", expectedCondition.conditionType)
					if expectedCondition.reason != "" {
						assert.Exactly(t, expectedCondition.reason, foundCondition.Reason)
					}
				}
			}
		})
	}
}

func testAzureCredentialsRequestWithOrphanedCloudResource(t *testing.T) *minterv1.CredentialsRequest {
	cr := testAzureCredentialsRequestNeedingCleanup(t)
	cr.Status.Conditions = append(cr.Status.Conditions, minterv1.CredentialsRequestCondition{
		Type:    minterv1.OrphanedCloudResource,
		Status:  corev1.ConditionTrue,
		Reason:  cloudResourceOrphaned,
		Message: "some cloud resource was unable to be cleaned up",
	})
	return cr
}
func testAzureCredentialsRequestNeedingCleanup(t *testing.T) *minterv1.CredentialsRequest {
	cr := testAzureCredentialsRequest(t)
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}

	azureProviderStatus, err := codec.EncodeProviderStatus(
		&minterv1.AzureProviderStatus{
			TypeMeta: metav1.TypeMeta{
				Kind: "AzureProviderStatus",
			},
			ServicePrincipalName:      "mintedServicePrincipal",
			AppID:                     "mintedAppID",
			SecretLastResourceVersion: "mintedLastResourceVersion",
		},
	)
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	cr.Status.ProviderStatus = azureProviderStatus
	cr.Status.Provisioned = true

	return cr
}

func testAzureCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}

	azureProviderSpec, err := codec.EncodeProviderSpec(
		&minterv1.AzureProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AzureProviderSpec",
			},
			RoleBindings: []minterv1.RoleBinding{
				{
					Role: "Contributor",
				},
			},
		},
	)
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	cr := &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testCRName,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
			Generation:  testCRGeneration,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			ProviderSpec: azureProviderSpec,
		},
	}

	return cr
}

func testAzureTargetSecret(namespace, name, azureClientID string) *corev1.Secret {
	s := testAzureCredsSecret(namespace, name)
	s.Data[azureactuator.AzureClientID] = []byte(azureClientID)

	return s
}

func testAzureCredsSecret(namespace, name string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.PassthroughAnnotation,
			},
		},
		Data: map[string][]byte{
			azureactuator.AzureClientID:       []byte(testAzureClientID),
			azureactuator.AzureClientSecret:   []byte(testAzureClientSecret),
			azureactuator.AzureRegion:         []byte(testAzureRegion),
			azureactuator.AzureResourceGroup:  []byte(testAzureResourceGroup),
			azureactuator.AzureResourcePrefix: []byte(testAzureResourceGroupPrefix),
			azureactuator.AzureSubscriptionID: []byte(testAzureSubscriptionID),
			azureactuator.AzureTenantID:       []byte(testAzureTenantID),
		},
	}
	return s
}

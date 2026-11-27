/*
Copyright 2020 The OpenShift Authors.

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
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
	"github.com/openshift/cloud-credential-operator/pkg/vsphere/actuator"
)

var (
	testVSphereCloudCredsSecretData = map[string][]byte{
		"key1": []byte("key1data"),
		"key2": []byte("key2data"),
	}
	testVSphereOverrideCredsSecretData = map[string][]byte{
		"key1": []byte("override-key1data"),
		"key2": []byte("override-key2data"),
	}
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestCredentialsRequestVSphereReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name          string
		existing      []runtime.Object
		existingAdmin []runtime.Object
		expectErr     bool
		validate      func(client.Client, *testing.T)
		// Expected conditions on the credentials request:
		expectedConditions []ExpectedCondition
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []ExpectedCOCondition
	}{
		{
			name: "new credentialsrequest passthrough",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testVSphereCloudCredsSecretData, targetSecret.Data)
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "new credential no root creds available",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
			},
			existingAdmin: []runtime.Object{},
			expectErr:     true,
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
				cr := getCredRequest(c)
				assert.False(t, cr.Status.Provisioned)
			},
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "cred deletion",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequestWithDeletionTimestamp(t),
				testSecret(testSecretNamespace, testSecretName, testVSphereCloudCredsSecretData),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret)
			},
		},
		{
			name: "existing cr up to date",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				testSecret(testSecretNamespace, testSecretName, testVSphereCloudCredsSecretData),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testVSphereCloudCredsSecretData, targetSecret.Data)
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "existing secret has old secret content",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				testSecret(testSecretNamespace, testSecretName, map[string][]byte{"key1": []byte("olddata")}),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// existing secret has updated content
				assert.Equal(t, testVSphereCloudCredsSecretData, targetSecret.Data)
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(&minterv1.CredentialsRequest{}).
				WithRuntimeObjects(test.existing...).Build()
			fakeAdminClient := fake.NewClientBuilder().
				WithRuntimeObjects(test.existingAdmin...).Build()
			rcr := &ReconcileCredentialsRequest{
				Client:      fakeClient,
				AdminClient: fakeAdminClient,
				Actuator: &actuator.VSphereActuator{
					Client:         fakeClient,
					RootCredClient: fakeAdminClient,
				},
				platformType: configv1.VSpherePlatformType,
			}

			_, err := rcr.Reconcile(context.TODO(), reconcile.Request{
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

func testVSphereCredentialsRequestWithDeletionTimestamp(t *testing.T) *minterv1.CredentialsRequest {
	cr := testVSphereCredentialsRequest(t)
	now := metav1.Now()
	cr.DeletionTimestamp = &now
	cr.Status.Provisioned = true
	return cr
}

func testVSphereCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	vsphereProvSpec, err := minterv1.Codec.EncodeProviderSpec(
		&minterv1.VSphereProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "VSphereProviderSpec",
			},
			Permissions: []minterv1.VSpherePermission{
				{
					Privileges: []string{
						"test.Permissions",
					},
				},
			},
		},
	)
	if err != nil {
		t.Logf("error encoding vsphereProviderSpec: %v", err)
		t.FailNow()
		return nil
	}

	return &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   testNamespace,
			Name:        testCRName,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
			Generation:  testCRGeneration,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			ProviderSpec: vsphereProvSpec,
		},
	}
}

func testVSphereCredsSecretPassthrough() *corev1.Secret {
	s := testVSphereCredsSecret()
	s.Annotations[constants.AnnotationKey] = constants.PassthroughAnnotation
	return s
}

func testVSphereCredsSecret() *corev1.Secret {
	s := testSecret("kube-system", constants.VSphereCloudCredSecretName, testVSphereCloudCredsSecretData)
	s.Annotations[constants.AnnotationKey] = constants.MintAnnotation

	return s
}

func testSecret(namespace, name string, secretData map[string][]byte) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.PassthroughAnnotation,
			},
		},
		Data: secretData,
	}
	return s
}

// testVSphereOverrideSecret creates a per-component override secret in
// openshift-config with both target annotations and the mode annotation.
func testVSphereOverrideSecret(name, targetNamespace, targetSecretName string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: constants.VSphereCredOverrideNamespace,
			Annotations: map[string]string{
				constants.AnnotationKey:                              constants.PassthroughAnnotation,
				constants.VSphereCredTargetSecretNamespaceAnnotation: targetNamespace,
				constants.VSphereCredTargetSecretNameAnnotation:      targetSecretName,
			},
		},
		Data: data,
	}
}

func TestIsVSphereOverrideSecret(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		annotations map[string]string
		expected    bool
	}{
		{
			name:      "valid override secret: correct namespace and both target annotations",
			namespace: constants.VSphereCredOverrideNamespace,
			annotations: map[string]string{
				constants.VSphereCredTargetSecretNamespaceAnnotation: "openshift-machine-api",
				constants.VSphereCredTargetSecretNameAnnotation:      "vsphere-cloud-credentials",
			},
			expected: true,
		},
		{
			name:      "wrong namespace: returns false",
			namespace: "kube-system",
			annotations: map[string]string{
				constants.VSphereCredTargetSecretNamespaceAnnotation: "openshift-machine-api",
				constants.VSphereCredTargetSecretNameAnnotation:      "vsphere-cloud-credentials",
			},
			expected: false,
		},
		{
			name:        "nil annotations: returns false",
			namespace:   constants.VSphereCredOverrideNamespace,
			annotations: nil,
			expected:    false,
		},
		{
			name:        "empty annotations: returns false",
			namespace:   constants.VSphereCredOverrideNamespace,
			annotations: map[string]string{},
			expected:    false,
		},
		{
			name:      "only target namespace annotation: returns false",
			namespace: constants.VSphereCredOverrideNamespace,
			annotations: map[string]string{
				constants.VSphereCredTargetSecretNamespaceAnnotation: "openshift-machine-api",
			},
			expected: false,
		},
		{
			name:      "only target name annotation: returns false",
			namespace: constants.VSphereCredOverrideNamespace,
			annotations: map[string]string{
				constants.VSphereCredTargetSecretNameAnnotation: "vsphere-cloud-credentials",
			},
			expected: false,
		},
		{
			name:      "unrelated annotations only: returns false",
			namespace: constants.VSphereCredOverrideNamespace,
			annotations: map[string]string{
				"some-other-key": "some-value",
			},
			expected: false,
		},
		{
			name:      "both annotations plus extras: still returns true",
			namespace: constants.VSphereCredOverrideNamespace,
			annotations: map[string]string{
				constants.VSphereCredTargetSecretNamespaceAnnotation: "openshift-cluster-csi-drivers",
				constants.VSphereCredTargetSecretNameAnnotation:      "vsphere-csi-credentials",
				constants.AnnotationKey:                              constants.PassthroughAnnotation,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsVSphereOverrideSecret(tt.namespace, tt.annotations)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCredentialsRequestVSphereReconcileWithOverride(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name          string
		existing      []runtime.Object
		existingAdmin []runtime.Object
		expectErr     bool
		validate      func(client.Client, *testing.T)
		// Expected conditions on the credentials request:
		expectedConditions []ExpectedCondition
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []ExpectedCOCondition
	}{
		{
			name: "new credentialsrequest with override secret: uses override data",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				testVSphereOverrideSecret("machine-api-override", testSecretNamespace, testSecretName, testVSphereOverrideCredsSecretData),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				assert.Equal(t, testVSphereOverrideCredsSecretData, targetSecret.Data)
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
				assert.Equal(t, int64(testCRGeneration), int64(cr.Status.LastSyncGeneration))
				assert.NotNil(t, cr.Status.LastSyncTimestamp)
			},
		},
		{
			name: "existing target with root data but override now present: updates to override data",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				testSecret(testSecretNamespace, testSecretName, testVSphereCloudCredsSecretData),
				testVSphereOverrideSecret("machine-api-override", testSecretNamespace, testSecretName, testVSphereOverrideCredsSecretData),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// Target secret should now hold the override data
				assert.Equal(t, testVSphereOverrideCredsSecretData, targetSecret.Data)
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
			},
		},
		{
			name: "override for non-matching target: falls back to root",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				// Override targets a DIFFERENT namespace/secret than the CR's SecretRef
				testVSphereOverrideSecret("csi-override", "openshift-cluster-csi-drivers", "vsphere-csi-credentials", testVSphereOverrideCredsSecretData),
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected non-empty target secret to exist")
				// Should use root data since override doesn't match
				assert.Equal(t, testVSphereCloudCredsSecretData, targetSecret.Data)
			},
		},
		{
			name: "override secret without mode annotation: returns error",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				// Override secret that has target annotations but is missing the
				// cloudcredential.openshift.io/mode annotation (not yet processed
				// by the secret annotator).
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "unannotated-override",
						Namespace: constants.VSphereCredOverrideNamespace,
						Annotations: map[string]string{
							constants.VSphereCredTargetSecretNamespaceAnnotation: testSecretNamespace,
							constants.VSphereCredTargetSecretNameAnnotation:      testSecretName,
						},
					},
					Data: testVSphereOverrideCredsSecretData,
				},
			},
			existingAdmin: []runtime.Object{
				testVSphereCredsSecretPassthrough(),
			},
			expectErr: true,
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				assert.Nil(t, targetSecret, "target secret should not be created when override is unannotated")
				cr := getCredRequest(c)
				assert.False(t, cr.Status.Provisioned)
			},
			expectedCOConditions: []ExpectedCOCondition{
				{
					conditionType: configv1.OperatorProgressing,
					status:        corev1.ConditionTrue,
				},
			},
		},
		{
			name: "override present with no root secret: uses override only",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testSecretNamespace),
				testVSphereCredentialsRequest(t),
				testVSphereOverrideSecret("machine-api-override", testSecretNamespace, testSecretName, testVSphereOverrideCredsSecretData),
			},
			existingAdmin: []runtime.Object{},
			validate: func(c client.Client, t *testing.T) {
				targetSecret := getCredRequestTargetSecret(c)
				require.NotNil(t, targetSecret, "expected target secret to exist even without root credential")
				assert.Equal(t, testVSphereOverrideCredsSecretData, targetSecret.Data)
				cr := getCredRequest(c)
				assert.NotNil(t, cr)
				assert.True(t, cr.Status.Provisioned)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(&minterv1.CredentialsRequest{}).
				WithRuntimeObjects(test.existing...).Build()
			fakeAdminClient := fake.NewClientBuilder().
				WithRuntimeObjects(test.existingAdmin...).Build()
			rcr := &ReconcileCredentialsRequest{
				Client:      fakeClient,
				AdminClient: fakeAdminClient,
				Actuator: &actuator.VSphereActuator{
					Client:         fakeClient,
					RootCredClient: fakeAdminClient,
				},
				platformType: configv1.VSpherePlatformType,
			}

			_, err := rcr.Reconcile(context.TODO(), reconcile.Request{
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

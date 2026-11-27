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
package actuator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testTargetNamespace = "openshift-machine-api"
	testTargetSecret    = "vsphere-cloud-credentials"
)

func TestGetCredentialsRootSecret(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name string
		// objects visible to the regular client (component namespaces, openshift-config)
		existing []runtime.Object
		// objects visible to the root credential client (kube-system)
		existingRootCred []runtime.Object
		// target namespace for the CredentialsRequest
		targetNamespace string
		// target secret name for the CredentialsRequest
		targetSecretName string
		// expected secret data key/value the method should return
		expectDataKey   string
		expectDataValue string
		expectErr       bool
		expectErrMsg    string
	}{
		{
			name:             "override secret with matching annotations: uses override data",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testOverrideSecret("my-machine-api-creds", "openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("override-user"),
					"password": []byte("override-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "override-user",
		},
		{
			name:             "override secret absent: falls back to root secret",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing:         []runtime.Object{},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "root-user",
		},
		{
			name:             "override for csi drivers",
			targetNamespace:  "openshift-cluster-csi-drivers",
			targetSecretName: "vsphere-csi-credentials",
			existing: []runtime.Object{
				testOverrideSecret("csi-driver-creds", "openshift-cluster-csi-drivers", "vsphere-csi-credentials", map[string][]byte{
					"username": []byte("csi-user"),
					"password": []byte("csi-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "csi-user",
		},
		{
			name:             "override secret not mode-annotated: returns error",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testUnannotatedOverrideSecret("my-creds", "openshift-machine-api", testTargetSecret),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectErr:    true,
			expectErrMsg: "cannot proceed without per-component override secret annotation",
		},
		{
			name:             "override with wrong target namespace annotation: ignored, falls back to root",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testOverrideSecret("wrong-ns-creds", "openshift-wrong-ns", testTargetSecret, map[string][]byte{
					"username": []byte("wrong-user"),
					"password": []byte("wrong-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "root-user",
		},
		{
			name:             "override with wrong target name annotation: ignored, falls back to root",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testOverrideSecret("wrong-name-creds", "openshift-machine-api", "wrong-secret-name", map[string][]byte{
					"username": []byte("wrong-user"),
					"password": []byte("wrong-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "root-user",
		},
		{
			name:             "override with missing annotations: ignored, falls back to root",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				// Secret in openshift-config but with no target annotations at all
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "some-other-secret",
						Namespace: constants.VSphereCredOverrideNamespace,
					},
					Data: map[string][]byte{
						"username": []byte("other-user"),
					},
				},
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "root-user",
		},
		{
			name:             "root secret not annotated: returns error",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing:         []runtime.Object{},
			existingRootCred: []runtime.Object{
				testUnannotatedRootSecret(),
			},
			expectErr:    true,
			expectErrMsg: "cannot proceed without cloud cred secret annotation",
		},
		{
			name:             "neither override nor root secret exists: returns error",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing:         []runtime.Object{},
			existingRootCred: []runtime.Object{},
			expectErr:        true,
			expectErrMsg:     "unable to fetch root cloud cred secret",
		},
		{
			name:             "multiple overrides: correct one matched by annotations",
			targetNamespace:  "openshift-cloud-controller-manager",
			targetSecretName: "vsphere-ccm-credentials",
			existing: []runtime.Object{
				// Override targeting machine-api (should NOT match)
				testOverrideSecret("machine-api-creds", "openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("machine-api-user"),
					"password": []byte("machine-api-pass"),
				}),
				// Override targeting CCM (should match)
				testOverrideSecret("ccm-creds", "openshift-cloud-controller-manager", "vsphere-ccm-credentials", map[string][]byte{
					"username": []byte("ccm-user"),
					"password": []byte("ccm-pass"),
				}),
				// Override targeting CSI (should NOT match)
				testOverrideSecret("csi-creds", "openshift-cluster-csi-drivers", "vsphere-csi-credentials", map[string][]byte{
					"username": []byte("csi-user"),
					"password": []byte("csi-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "ccm-user",
		},
		{
			name:             "override secret name is arbitrary: matches by annotations not name",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testOverrideSecret("arbitrary-admin-chosen-name", "openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("arbitrary-user"),
					"password": []byte("arbitrary-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectDataKey:   "username",
			expectDataValue: "arbitrary-user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(tt.existing...).Build()
			fakeRootCredClient := fake.NewClientBuilder().WithRuntimeObjects(tt.existingRootCred...).Build()

			actuator := &VSphereActuator{
				Client:         fakeClient,
				RootCredClient: fakeRootCredClient,
			}

			cr := testCredentialsRequest(tt.targetNamespace, tt.targetSecretName)

			secret, err := actuator.GetCredentialsRootSecret(context.TODO(), cr)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErrMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, secret)
			assert.Equal(t, tt.expectDataValue, string(secret.Data[tt.expectDataKey]))
		})
	}
}

func TestNeedsUpdate(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name             string
		existing         []runtime.Object
		existingRootCred []runtime.Object
		targetNamespace  string
		targetSecretName string
		expectUpdate     bool
	}{
		{
			name:             "target matches override: no update needed",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testOverrideSecret("machine-api-creds", "openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("override-user"),
					"password": []byte("override-pass"),
				}),
				testTargetSecretWithData("openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("override-user"),
					"password": []byte("override-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectUpdate: false,
		},
		{
			name:             "target matches root, no override: no update needed",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testTargetSecretWithData("openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("root-user"),
					"password": []byte("root-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectUpdate: false,
		},
		{
			name:             "target has root data but override now exists: update needed",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing: []runtime.Object{
				testOverrideSecret("machine-api-creds", "openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("override-user"),
					"password": []byte("override-pass"),
				}),
				testTargetSecretWithData("openshift-machine-api", testTargetSecret, map[string][]byte{
					"username": []byte("root-user"),
					"password": []byte("root-pass"),
				}),
			},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectUpdate: true,
		},
		{
			name:             "target secret missing: update needed",
			targetNamespace:  "openshift-machine-api",
			targetSecretName: testTargetSecret,
			existing:         []runtime.Object{},
			existingRootCred: []runtime.Object{
				testRootSecret(),
			},
			expectUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(tt.existing...).Build()
			fakeRootCredClient := fake.NewClientBuilder().WithRuntimeObjects(tt.existingRootCred...).Build()

			actuator := &VSphereActuator{
				Client:         fakeClient,
				RootCredClient: fakeRootCredClient,
			}

			cr := testCredentialsRequest(tt.targetNamespace, tt.targetSecretName)
			needsUpdate, err := actuator.needsUpdate(context.TODO(), cr)
			require.NoError(t, err)
			assert.Equal(t, tt.expectUpdate, needsUpdate)
		})
	}
}

// --- Test helpers ---

func testCredentialsRequest(targetNamespace, targetSecretName string) *minterv1.CredentialsRequest {
	vsphereProviderSpec := &minterv1.VSphereProviderSpec{}
	providerSpec, _ := minterv1.Codec.EncodeProviderSpec(vsphereProviderSpec)

	return &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cred-request",
			Namespace: "openshift-cloud-credential-operator",
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{
				Name:      targetSecretName,
				Namespace: targetNamespace,
			},
			ProviderSpec: providerSpec,
		},
	}
}

func testRootSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.VSphereCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.PassthroughAnnotation,
			},
		},
		Data: map[string][]byte{
			"username": []byte("root-user"),
			"password": []byte("root-pass"),
		},
	}
}

func testUnannotatedRootSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.VSphereCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
		},
		Data: map[string][]byte{
			"username": []byte("root-user"),
			"password": []byte("root-pass"),
		},
	}
}

// testOverrideSecret creates a per-component override secret in
// openshift-config with annotation-based targeting. The secret name is
// arbitrary; mapping is done via annotations.
func testOverrideSecret(name, targetNamespace, targetSecretName string, data map[string][]byte) *corev1.Secret {
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

// testUnannotatedOverrideSecret creates an override secret that has the
// target annotations but is missing the cloudcredential.openshift.io/mode
// annotation, simulating a secret the annotator has not yet processed.
func testUnannotatedOverrideSecret(name, targetNamespace, targetSecretName string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: constants.VSphereCredOverrideNamespace,
			Annotations: map[string]string{
				constants.VSphereCredTargetSecretNamespaceAnnotation: targetNamespace,
				constants.VSphereCredTargetSecretNameAnnotation:      targetSecretName,
			},
		},
		Data: map[string][]byte{
			"username": []byte("override-user"),
			"password": []byte("override-pass"),
		},
	}
}

func testTargetSecretWithData(namespace, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
}

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

package vsphere

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
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testSecretName = "testsecret"
	testNamespace  = "testproject"
	testInfraName  = "testcluster-abc123"
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
		validateAnnotationValue string
	}{
		{
			name: "operator disabled",
			existing: []runtime.Object{
				testOperatorConfigMap("true"),
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
		},
		{
			name: "operator enabled",
			existing: []runtime.Object{
				testOperatorConfigMap("false"),
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
		},
		{
			name: "annotate passthrough mode",
			// right now only passthrough mode is supported so any secret works
			existing: []runtime.Object{
				testOperatorConfig(""),
			},
			existingRootCred: []runtime.Object{
				testSecret(),
			},
			validateAnnotationValue: constants.PassthroughAnnotation,
		},
		{
			name:      "missing secret",
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
					Platform:           configv1.VSpherePlatformType,
					InfrastructureName: testInfraName,
				},
			}

			existing := append(test.existing, infra)

			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(existing...).Build()
			fakeRootCredClient := fake.NewClientBuilder().WithRuntimeObjects(test.existingRootCred...).Build()

			rcc := &ReconcileCloudCredSecret{
				Client:         fakeClient,
				RootCredClient: fakeRootCredClient,
				Logger:         log.WithField("controller", "testController"),
			}

			_, err := rcc.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testSecretName,
					Namespace: testNamespace,
				},
			})

			if !test.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validateAnnotationValue != "" {
				validateSecretAnnotation(fakeRootCredClient, t, test.validateAnnotationValue)
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
			"username": []byte("someuser"),
			"password": []byte("somepassword"),
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

func validateSecretAnnotation(c client.Client, t *testing.T, value string) {
	secret := getCredSecret(c)
	validateAnnotation(t, secret, value)
}

func validateAnnotation(t *testing.T, secret *corev1.Secret, annotation string) {
	if secret.ObjectMeta.Annotations == nil {
		t.Errorf("unexpected empty annotations on secret")
	}
	if _, ok := secret.ObjectMeta.Annotations[constants.AnnotationKey]; !ok {
		t.Errorf("missing annotation")
	}

	assert.Exactly(t, annotation, secret.ObjectMeta.Annotations[constants.AnnotationKey])
}

func getCredSecret(c client.Client) *corev1.Secret {
	secret := &corev1.Secret{}
	if err := c.Get(context.TODO(), client.ObjectKey{Name: testSecretName, Namespace: testNamespace}, secret); err != nil {
		return nil
	}
	return secret
}

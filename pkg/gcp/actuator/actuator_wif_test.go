/*
Copyright 2026 The OpenShift Authors.

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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

func TestNeedsUpdateWIF(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	const (
		secretNS   = "openshift-machine-api"
		secretName = "gcp-cloud-credentials"
		audience   = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/test/providers/test"
		saEmail    = "test-sa@project.iam.gserviceaccount.com"
		tokenPath  = "/var/run/secrets/openshift/serviceaccount/token"
	)

	gcpSpec := &minterv1.GCPProviderSpec{
		Audience:            audience,
		ServiceAccountEmail: saEmail,
	}
	providerSpec, err := minterv1.Codec.EncodeProviderSpec(gcpSpec.DeepCopyObject().(runtime.Object))
	require.NoError(t, err)

	emptyEmailSpec, err := minterv1.Codec.EncodeProviderSpec((&minterv1.GCPProviderSpec{
		Audience: audience,
	}).DeepCopyObject().(runtime.Object))
	require.NoError(t, err)

	desiredJSON := fmt.Sprintf(gcpSTSCredsTemplate, audience, "googleapis.com", "googleapis.com", saEmail, tokenPath, "")

	crWithEmail := &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cr",
			Namespace: minterv1.CloudCredOperatorNamespace,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{
				Namespace: secretNS,
				Name:      secretName,
			},
			ProviderSpec:   providerSpec,
			CloudTokenPath: tokenPath,
		},
	}

	crEmptyEmail := crWithEmail.DeepCopy()
	crEmptyEmail.Spec.ProviderSpec = emptyEmailSpec

	tests := []struct {
		name              string
		cr                *minterv1.CredentialsRequest
		existing          []client.Object
		expectNeedsUpdate bool
	}{
		{
			name:              "WIF with empty ServiceAccountEmail needs no update",
			cr:                crEmptyEmail,
			existing:          []client.Object{testWIFOperatorConfig(), testWIFAuthConfig("https://issuer.example"), testWIFInfrastructure()},
			expectNeedsUpdate: false,
		},
		{
			name: "WIF with matching secret needs no update",
			cr:   crWithEmail,
			existing: []client.Object{
				testWIFOperatorConfig(),
				testWIFAuthConfig("https://issuer.example"),
				testWIFInfrastructure(),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: secretNS,
					},
					Data: map[string][]byte{
						gcpSecretJSONKey: []byte(desiredJSON),
					},
				},
			},
			expectNeedsUpdate: false,
		},
		{
			name: "WIF with missing secret needs update",
			cr:   crWithEmail,
			existing: []client.Object{
				testWIFOperatorConfig(),
				testWIFAuthConfig("https://issuer.example"),
				testWIFInfrastructure(),
			},
			expectNeedsUpdate: true,
		},
		{
			name: "WIF with stale secret content needs update",
			cr:   crWithEmail,
			existing: []client.Object{
				testWIFOperatorConfig(),
				testWIFAuthConfig("https://issuer.example"),
				testWIFInfrastructure(),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: secretNS,
					},
					Data: map[string][]byte{
						gcpSecretJSONKey: []byte(`{"type":"external_account","audience":"stale"}`),
					},
				},
			},
			expectNeedsUpdate: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithObjects(test.existing...).Build()
			a := &Actuator{Client: fakeClient}

			apisEnabled, needsUpdate, err := a.needsUpdate(context.Background(), test.cr)
			require.NoError(t, err)
			assert.True(t, apisEnabled, "WIF short-circuit should treat service APIs as enabled")
			assert.Equal(t, test.expectNeedsUpdate, needsUpdate)
		})
	}
}

func testWIFOperatorConfig() *operatorv1.CloudCredential {
	return &operatorv1.CloudCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: operatorv1.CloudCredentialSpec{
			CredentialsMode: operatorv1.CloudCredentialsModeManual,
		},
	}
}

func testWIFAuthConfig(issuer string) *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.AuthenticationSpec{
			ServiceAccountIssuer: issuer,
		},
	}
}

func testWIFInfrastructure() *configv1.Infrastructure {
	return &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Status: configv1.InfrastructureStatus{
			InfrastructureName: "test-cluster",
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.GCPPlatformType,
				GCP:  &configv1.GCPPlatformStatus{},
			},
		},
	}
}

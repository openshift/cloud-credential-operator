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
	"testing"

	openshiftapiv1 "github.com/openshift/api/config/v1"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/azure"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	validNamespace = "valid-namespace"
	validName      = "valid-name"

	notFoundNamespace = "not-found-namespace"
	notFoundName      = "not-found-name"

	rootClientID       = "root_client_id"
	rootClientSecret   = "root_client_secret"
	rootRegion         = "root_region"
	rootResourceGroup  = "root_resource_group"
	rootResourcePrefix = "root_resource_prefix"
	rootSubscriptionID = "root_subscription_id"
	rootTenantID       = "root_tenant_id"
)

var (
	unknownError  = errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonUnknown}}
	notFoundError = errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonNotFound}}

	validStatus = minterv1.AzureProviderStatus{ServicePrincipalName: "http://test-credential", AppID: "1DB7BC50-6390-4DC8-A576-F20F42DCFF23"}
	emptyStatus = minterv1.AzureProviderStatus{}

	validObjectKey    = client.ObjectKey{Namespace: validNamespace, Name: validName}
	notFoundObjectKey = client.ObjectKey{Namespace: notFoundNamespace, Name: notFoundName}

	secretExistsCredentialRequest = minterv1.CredentialsRequest{
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{Namespace: validNamespace, Name: validName},
		},
	}

	secretNotFoundCredentialRequest = minterv1.CredentialsRequest{
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{Namespace: notFoundNamespace, Name: notFoundName},
		},
	}

	validRootSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      azure.RootSecretName,
			Namespace: azure.RootSecretNamespace,
			Annotations: map[string]string{
				annotatorconst.AnnotationKey: annotatorconst.PassthroughAnnotation,
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
			Name:      azure.RootSecretName,
			Namespace: azure.RootSecretNamespace,
			Annotations: map[string]string{
				annotatorconst.AnnotationKey: "blah",
			},
		},
	}

	rootSecretNoAnnotation = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        azure.RootSecretName,
			Namespace:   azure.RootSecretNamespace,
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
			PlatformStatus: &openshiftapiv1.PlatformStatus{
				Azure: &openshiftapiv1.AzurePlatformStatus{
					ResourceGroupName: "testRG",
				},
			},
		},
	}

	clusterDNS = openshiftapiv1.DNS{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: openshiftapiv1.DNSSpec{
			PublicZone: &openshiftapiv1.DNSZone{
				ID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/os4-common/providers/Microsoft.Network/dnszones/devcluster.openshift.com",
			},
		},
	}
)

type testInput struct {
	req    *minterv1.CredentialsRequest
	spec   *minterv1.AzureProviderSpec
	status *minterv1.AzureProviderStatus
}

func TestPassthroughExists(t *testing.T) {
	var tests = []struct {
		name   string
		in     *testInput
		exists bool
		err    error
	}{
		{"TestPassthroughExistsEmptyRequest", &testInput{req: &minterv1.CredentialsRequest{}, spec: &minterv1.AzureProviderSpec{}, status: &emptyStatus}, false, nil},
		{"TestPassthroughExistsMissing", &testInput{req: &secretNotFoundCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, false, nil},
		{"TestPassthroughExists", &testInput{req: &secretExistsCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fake.NewFakeClient(&validRootSecret, &validSecret)
			actuator, err := azure.NewActuator(f)
			assert.Nil(t, err)

			cr, err := newCredentialsRequest(tt.in)
			assert.Nil(t, err)

			exists, err := actuator.Exists(context.TODO(), cr)
			assert.Equal(t, err, tt.err)

			assert.Equal(t, exists, tt.exists)
		})
	}
}

func TestPassthroughCreate(t *testing.T) {
	var tests = []struct {
		name string
		in   *testInput
		err  error
	}{
		{"TestPassthroughCreateNew", &testInput{req: &secretNotFoundCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, nil},
		{"TestPassthroughCreateExists", &testInput{req: &secretExistsCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, nil},
	}

	if err := openshiftapiv1.Install(scheme.Scheme); err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fake.NewFakeClient(&validRootSecret, &validSecret, &clusterInfra, &clusterDNS)
			actuator, err := azure.NewActuator(f)
			assert.Nil(t, err)

			cr, err := newCredentialsRequest(tt.in)
			assert.Nil(t, err)

			err = actuator.Create(context.TODO(), cr)
			assert.Equal(t, tt.err, err)

			secret := corev1.Secret{}
			key := client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}
			err = f.Get(context.TODO(), key, &secret)
			assert.Nil(t, err)
			assert.Equal(t, secret.Data[azure.AzureClientID], []byte(rootClientID))
			assert.Equal(t, secret.Data[azure.AzureClientSecret], []byte(rootClientSecret))
			assert.Equal(t, secret.Data[azure.AzureRegion], []byte(rootRegion))
			assert.Equal(t, secret.Data[azure.AzureResourceGroup], []byte(rootResourceGroup))
			assert.Equal(t, secret.Data[azure.AzureResourcePrefix], []byte(rootResourcePrefix))
			assert.Equal(t, secret.Data[azure.AzureSubscriptionID], []byte(rootSubscriptionID))
			assert.Equal(t, secret.Data[azure.AzureTenantID], []byte(rootTenantID))
		})
	}
}

func TestPassthroughUpdate(t *testing.T) {
	var tests = []struct {
		name string
		in   *testInput
		err  error
	}{
		{"TestPassthroughUpdateNew", &testInput{req: &secretNotFoundCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, nil},
		{"TestPassthroughUpdateExists", &testInput{req: &secretExistsCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, nil},
	}

	if err := openshiftapiv1.Install(scheme.Scheme); err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fake.NewFakeClient(&validRootSecret, &validSecret, &clusterInfra, &clusterDNS)
			actuator, err := azure.NewActuator(f)
			assert.Nil(t, err)

			cr, err := newCredentialsRequest(tt.in)
			assert.Nil(t, err)

			err = actuator.Update(context.TODO(), cr)
			assert.Equal(t, err, tt.err)

			secret := corev1.Secret{}
			key := client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}
			err = f.Get(context.TODO(), key, &secret)
			assert.Nil(t, err)
			assert.Equal(t, secret.Data[azure.AzureClientID], []byte(rootClientID))
			assert.Equal(t, secret.Data[azure.AzureClientSecret], []byte(rootClientSecret))
		})
	}
}

func TestPassthroughDelete(t *testing.T) {
	var tests = []struct {
		name     string
		in       *testInput
		expected string
	}{
		{"TestPassthroughDeleteNotFound", &testInput{req: &secretNotFoundCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, `secrets "not-found-name" not found`},
		{"TestPassthroughDeleteExists", &testInput{req: &secretExistsCredentialRequest, spec: &minterv1.AzureProviderSpec{}, status: &validStatus}, `secrets "valid-name" not found`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fake.NewFakeClient(&validRootSecret, &validSecret)
			actuator, err := azure.NewActuator(f)
			assert.Nil(t, err)

			cr, err := newCredentialsRequest(tt.in)
			assert.Nil(t, err)

			err = actuator.Delete(context.TODO(), cr)
			assert.Equal(t, err, nil)

			secret := corev1.Secret{}
			key := client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}
			err = f.Get(context.TODO(), key, &secret)
			switch tt.expected {
			case "":
				assert.Nil(t, err)
			default:
				assert.EqualError(t, err, tt.expected)
			}
		})
	}
}

func newCredentialsRequest(in *testInput) (*minterv1.CredentialsRequest, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		return nil, err
	}

	sp, err := codec.EncodeProviderSpec(in.spec)
	if err != nil {
		return nil, err
	}

	st, err := codec.EncodeProviderStatus(in.status)
	if err != nil {
		return nil, err
	}

	in.req.Spec.ProviderSpec = sp
	in.req.Status.ProviderStatus = st
	return in.req, nil
}

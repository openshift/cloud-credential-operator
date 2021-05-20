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

package ibmcloud_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/ibmcloud"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/util"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	kubernetesclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace                            = "ibmcloud-cloud-credential-operator"
	testCredRequestName                      = "openshift-machine-api-ibmcloud"
	testInfrastructureName                   = "test-cluster-abcd"
	testRandomSuffix                         = "random"
	testOpenshiftMachineAPIIBMCloudNamespace = "openshift-machine-api"
)

var (
	ibmcloudCredentialData = []byte("data")

	ibmcloudSpec = &minterv1.IBMCloudProviderSpec{}

	ibmcloudCredentialsSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IBMCloudCredSecretName,
			Namespace: constants.CloudCredSecretNamespace,
		},
		Data: map[string][]byte{
			ibmcloud.IBMCloudCredentialsSecretKey: ibmcloudCredentialData,
		},
	}

	ibmcloudOpenshiftMachineApiSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.IBMCloudCredSecretName,
			Namespace: testOpenshiftMachineAPIIBMCloudNamespace,
		},
		Data: map[string][]byte{
			ibmcloud.IBMCloudCredentialsSecretKey: ibmcloudCredentialData,
		},
	}
)

func TestDecodeToUnknown(t *testing.T) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("failed to create codec %#v", err)
	}
	var raw *runtime.RawExtension
	aps := minterv1.IBMCloudProviderSpec{}
	raw, err = codec.EncodeProviderSpec(&aps)
	if err != nil {
		t.Fatalf("failed to encode codec %#v", err)
	}
	unknown := runtime.Unknown{}
	err = codec.DecodeProviderStatus(raw, &unknown)
	if err != nil {
		t.Fatalf("should be able to decode to Unknown %#v", err)
	}
	if unknown.Kind != reflect.TypeOf(minterv1.IBMCloudProviderSpec{}).Name() {
		t.Fatalf("expected decoded kind to be %s but was %s", reflect.TypeOf(minterv1.IBMCloudProviderSpec{}).Name(), unknown.Kind)
	}
}

func TestCreateCR(t *testing.T) {
	util.SetupScheme(scheme.Scheme)
	tests := []struct {
		name               string
		existing           []runtime.Object
		credentialsRequest *minterv1.CredentialsRequest
		expectedErr        error
		errRegexp          string
		validate           func(*testing.T, kubernetesclient.Client)
	}{
		{
			name:               "Create CR happy flow",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			validate: func(t *testing.T, c kubernetesclient.Client) {
				cr := getCredRequest(t, c)
				assert.NotNil(t, cr)

				secret := getSecret(t, c)
				assert.NotNil(t, secret)

			},
		},
		{
			name:               "Create CR fail on getCredentialSecret kube-system:ibmcloud-credentials",
			existing:           []runtime.Object{},
			credentialsRequest: testCredentialsRequest(t),
			expectedErr:        fmt.Errorf("unable to fetch root cloud cred secret: secrets \"ibmcloud-credentials\" not found"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewFakeClientWithScheme(scheme.Scheme, allObjects...)

			actuator, err := ibmcloud.NewActuator(fakeClient)
			if err != nil {
				assert.Regexp(t, test.errRegexp, err)
				assert.Nil(t, actuator)
				return
			}
			testErr := actuator.Create(context.TODO(), test.credentialsRequest)
			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
			} else {
				test.validate(t, fakeClient)
			}

		})
	}
}

func TestDeleteCR(t *testing.T) {
	util.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		existing           []runtime.Object
		credentialsRequest *minterv1.CredentialsRequest
		expectedErr        error
		errRegexp          string
		validate           func(*testing.T, kubernetesclient.Client)
	}{
		{
			name:               "Delete CR happy flow",
			existing:           existingObjectsAfterCreate(t),
			credentialsRequest: testCredentialsRequest(t),
			validate:           func(t *testing.T, c kubernetesclient.Client) {},
		},
		{
			name:               "Delete CR happy flow - existingSecret not exist",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			validate:           func(t *testing.T, c kubernetesclient.Client) {},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewFakeClientWithScheme(scheme.Scheme, allObjects...)

			actuator, err := ibmcloud.NewActuator(fakeClient)
			if err != nil {
				assert.Regexp(t, test.errRegexp, err)
				assert.Nil(t, actuator)
				return
			}
			testErr := actuator.Delete(context.TODO(), test.credentialsRequest)
			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
			} else {
				test.validate(t, fakeClient)
			}

		})
	}
}

func TestExistsCR(t *testing.T) {
	util.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		existing           []runtime.Object
		credentialsRequest *minterv1.CredentialsRequest
		expectedErr        error
		errRegexp          string
		validate           func(*testing.T, kubernetesclient.Client, bool)
	}{
		{
			name:               "Exists CR happy flow (true)",
			existing:           existingObjectsAfterCreate(t),
			credentialsRequest: testCredentialsRequest(t),
			validate: func(t *testing.T, c kubernetesclient.Client, isExists bool) {
				secret := getSecret(t, c)
				assert.Equal(t, isExists, true)
				assert.NotNil(t, secret)
			},
		},
		{
			name:               "Non Exists CR happy flow (false)",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			validate: func(t *testing.T, c kubernetesclient.Client, isExists bool) {
				secret := getSecret(t, c)
				assert.Equal(t, isExists, false)
				assert.Nil(t, secret)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewFakeClientWithScheme(scheme.Scheme, allObjects...)

			actuator, err := ibmcloud.NewActuator(fakeClient)
			if err != nil {
				assert.Regexp(t, test.errRegexp, err)
				assert.Nil(t, actuator)
				return
			}
			isExists, testErr := actuator.Exists(context.TODO(), test.credentialsRequest)
			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
			} else {
				test.validate(t, fakeClient, isExists)
			}

		})
	}
}

func TestUpdateCR(t *testing.T) {
	util.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		existing           []runtime.Object
		credentialsRequest *minterv1.CredentialsRequest
		expectedErr        error
		errRegexp          string
		validate           func(*testing.T, kubernetesclient.Client)
	}{
		{
			name:               "Update CR happy flow - non exists",
			existing:           defaultExistingObjects(),
			credentialsRequest: testCredentialsRequest(t),
			validate: func(t *testing.T, c kubernetesclient.Client) {
				cr := getCredRequest(t, c)
				assert.NotNil(t, cr)
			},
		},
		{
			name:               "Update CR happy flow - exists",
			existing:           existingObjectsAfterCreate(t),
			credentialsRequest: testCredentialsRequest(t),
			validate: func(t *testing.T, c kubernetesclient.Client) {
				cr := getCredRequest(t, c)
				assert.NotNil(t, cr)
			},
		},
		{
			name:               "Update CR fail on getCredentialSecret kube-system:ibmcloud-credentials",
			existing:           []runtime.Object{},
			credentialsRequest: testCredentialsRequest(t),
			expectedErr:        fmt.Errorf("unable to fetch root cloud cred secret: secrets \"ibmcloud-credentials\" not found"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allObjects := append(test.existing, test.credentialsRequest)
			fakeClient := fake.NewFakeClientWithScheme(scheme.Scheme, allObjects...)

			actuator, err := ibmcloud.NewActuator(fakeClient)
			if err != nil {
				assert.Regexp(t, test.errRegexp, err)
				assert.Nil(t, actuator)
				return
			}
			testErr := actuator.Update(context.TODO(), test.credentialsRequest)
			if test.expectedErr != nil {
				assert.Error(t, testErr)
				assert.Equal(t, test.expectedErr.Error(), testErr.Error())
			} else {
				test.validate(t, fakeClient)
			}

		})
	}
}

func getSecret(t *testing.T, c kubernetesclient.Client) *corev1.Secret {
	credRequest := getCredRequest(t, c)

	secret := &corev1.Secret{}
	err := c.Get(context.TODO(), types.NamespacedName{
		Namespace: credRequest.Spec.SecretRef.Namespace,
		Name:      credRequest.Spec.SecretRef.Name,
	}, secret)
	if err != nil && errors.IsNotFound(err) {
		return nil
	}

	assert.NoError(t, err)
	return secret
}

func getCredRequest(t *testing.T, c kubernetesclient.Client) *minterv1.CredentialsRequest {
	cr := &minterv1.CredentialsRequest{}
	assert.NoError(t, c.Get(context.TODO(), types.NamespacedName{Namespace: testNamespace, Name: testCredRequestName}, cr))
	return cr
}

func defaultExistingObjects() []runtime.Object {
	objs := []runtime.Object{
		&ibmcloudCredentialsSecret,
	}
	return objs
}

func existingObjectsAfterCreate(t *testing.T) []runtime.Object {
	objs := []runtime.Object{
		&ibmcloudCredentialsSecret,
		&ibmcloudOpenshiftMachineApiSecret,
	}
	return objs
}

func testCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Fatalf("error creating ibmcloud codec: %v", err)
	}

	rawObj, err := codec.EncodeProviderSpec(ibmcloudSpec)
	if err != nil {
		t.Fatalf("error decoding provider v1 spec: %v", err)
	}

	cr := &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testCredRequestName,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{
				Namespace: testOpenshiftMachineAPIIBMCloudNamespace,
				Name:      constants.IBMCloudCredSecretName,
			},
			ProviderSpec: rawObj,
		},
	}

	return cr
}

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
	"reflect"
	"testing"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/azure"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

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

package ovirt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConvertRootCredentials(t *testing.T) {
	tests := []struct {
		givenSecret    corev1.Secret
		expectedCreds  OvirtCreds
		expectedToFail bool
	}{
		{
			givenSecret: corev1.Secret{
				TypeMeta:   v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{},
				Data: map[string][]byte{
					"ovirt_url":      []byte("https://enginefqdn/ovirt-engine/api"),
					"ovirt_username": []byte("admin@internal"),
					"ovirt_password": []byte("secret"),
					"ovirt_cafile":   []byte("/etc/pki/ovirt-engine/ca.pem"),
					"ovirt_insecure": []byte("true"),
				},
				StringData: nil,
				Type:       "Opaque",
			},
			expectedCreds: OvirtCreds{
				URL:      "https://enginefqdn/ovirt-engine/api",
				Username: "admin@internal",
				Passord:  "secret",
				CAFile:   "/etc/pki/ovirt-engine/ca.pem",
				Insecure: true,
			},
			expectedToFail: false,
		},
		{
			givenSecret: corev1.Secret{
				TypeMeta:   v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{},
				Data:       nil,
				StringData: nil,
				Type:       "",
			},
			expectedCreds: OvirtCreds{
				URL:      "",
				Username: "",
				Passord:  "",
				CAFile:   "",
				Insecure: false,
			},
			expectedToFail: true,
		},
	}

	for _, v := range tests {
		ovirtCreds, err := secretToCreds(&v.givenSecret)
		if v.expectedToFail {
			assert.Error(t, err, "expected failure")
		} else {
			assert.NoError(t, err)
			assert.Equal(t, v.expectedCreds, ovirtCreds)
		}
	}
}

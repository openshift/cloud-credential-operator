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

package configmap

import (
	"crypto/md5"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestConfigMapReconcile(t *testing.T) {
	reconcileRequest := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      configMapName,
			Namespace: ccoNamespace,
		},
	}

	tests := []struct {
		name              string
		existingConfigMap runtime.Object
		existingHash      string
		expectErr         bool
		expectExit        bool
		expectedHash      string
	}{
		{
			name:              "no configmap data change",
			existingConfigMap: createTestConfigMap("some fake cert data"),
			expectedHash:      getMD5("some fake cert data"),
		},
		{
			name:              "restart on different data",
			existingConfigMap: createTestConfigMap("some fake cert data"),
			existingHash:      getMD5("other cert data"),
			expectExit:        true,
		},
		{
			name:              "error when no configmap",
			existingConfigMap: &corev1.ConfigMap{},
			expectErr:         true,
		},
		{
			name:              "new configmap first encountered on startup",
			existingConfigMap: createTestConfigMap("some fake cert data"),
			expectedHash:      getMD5("some fake cert data"),
		},
		{
			name:              "new config map with empty data",
			existingConfigMap: createTestConfigMap(""),
			expectedHash:      getMD5(""),
		},
		{
			name:              "config map with empty data",
			existingConfigMap: createTestConfigMap(""),
			existingHash:      getMD5(""),
			expectedHash:      getMD5(""),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewFakeClient(test.existingConfigMap)
			exitCalled := false

			rcm := &ReconcileConfigMap{
				Client:            fakeClient,
				logger:            log.WithField("controller", "testcontroller"),
				configMapDataHash: test.existingHash,
				exit: func() {
					exitCalled = true
				},
			}

			_, err := rcm.Reconcile(reconcileRequest)

			if test.expectErr {
				assert.Error(t, err, "expected error for test case")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expectExit, exitCalled)

				if test.expectedHash != "" {
					assert.Equal(t, test.expectedHash, rcm.configMapDataHash)
				}
			}
		})
	}
}

func createTestConfigMap(certData string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: ccoNamespace,
		},
		Data: map[string]string{
			configMapKeyName: certData,
		},
	}
	return cm
}

func getMD5(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

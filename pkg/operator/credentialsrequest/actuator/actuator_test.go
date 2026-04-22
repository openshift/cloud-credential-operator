/*
Copyright 2024 The OpenShift Authors.

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
	"testing"

	"github.com/stretchr/testify/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutil "github.com/openshift/cloud-credential-operator/pkg/util"
)

func TestDummyActuatorUpgradeable(t *testing.T) {
	schemeutil.SetupScheme(scheme.Scheme)

	completedVersion := "4.6.0-1"

	tests := []struct {
		name              string
		mode              operatorv1.CloudCredentialsMode
		withClient        bool
		upgradeAnnotation *string
		expectedStatus    *configv1.ConditionStatus
		expectedReason    *string
		expectNil         bool
	}{
		{
			name:       "non-Manual mode always upgradeable (no client)",
			mode:       operatorv1.CloudCredentialsModeDefault,
			withClient: false,
			expectedStatus: func() *configv1.ConditionStatus {
				s := configv1.ConditionTrue
				return &s
			}(),
		},
		{
			name:       "Manual mode with nil client falls through to upgradeable",
			mode:       operatorv1.CloudCredentialsModeManual,
			withClient: false,
			expectedStatus: func() *configv1.ConditionStatus {
				s := configv1.ConditionTrue
				return &s
			}(),
		},
		{
			name:              "Manual mode with client and annotation is upgradeable",
			mode:              operatorv1.CloudCredentialsModeManual,
			withClient:        true,
			upgradeAnnotation: strPtr("4.7"),
			expectNil:         true, // UpgradeableCheck returns nil when upgradeable
		},
		{
			name:       "Manual mode with client and no annotation is not upgradeable",
			mode:       operatorv1.CloudCredentialsModeManual,
			withClient: true,
			expectedStatus: func() *configv1.ConditionStatus {
				s := configv1.ConditionFalse
				return &s
			}(),
			expectedReason: strPtr(constants.MissingUpgradeableAnnotationReason),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := &DummyActuator{}

			if test.withClient {
				clusterVersion := &configv1.ClusterVersion{
					ObjectMeta: metav1.ObjectMeta{Name: "version"},
					Status: configv1.ClusterVersionStatus{
						History: []configv1.UpdateHistory{
							{State: configv1.CompletedUpdate, Version: completedVersion},
						},
					},
				}
				operatorConfig := &operatorv1.CloudCredential{
					ObjectMeta: metav1.ObjectMeta{Name: constants.CloudCredOperatorConfig},
					Spec: operatorv1.CloudCredentialSpec{
						CredentialsMode: test.mode,
					},
				}
				if test.upgradeAnnotation != nil {
					operatorConfig.Annotations = map[string]string{
						constants.UpgradeableAnnotation: *test.upgradeAnnotation,
					}
				}
				objs := []runtime.Object{clusterVersion, operatorConfig}
				a.Client = fake.NewClientBuilder().WithRuntimeObjects(objs...).Build()
			}

			condition := a.Upgradeable(test.mode)

			if test.expectNil {
				assert.Nil(t, condition, "expected nil condition (upgradeable) but got one")
				return
			}

			if test.expectedStatus != nil {
				assert.NotNil(t, condition)
				assert.Equal(t, configv1.OperatorUpgradeable, condition.Type)
				assert.Equal(t, *test.expectedStatus, condition.Status)
				if test.expectedReason != nil {
					assert.Equal(t, *test.expectedReason, condition.Reason)
				}
			}
		})
	}
}

func strPtr(s string) *string { return &s }

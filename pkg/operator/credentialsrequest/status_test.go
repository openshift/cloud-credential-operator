/*
Copyright 2018 The OpenShift Authors.

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
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

var (
	defaultAWSProviderConfig   = &runtime.RawExtension{}
	defaultAzureProviderConfig = &runtime.RawExtension{}
	defaultGCPProviderConfig   = &runtime.RawExtension{}
)

func TestClusterOperatorStatus(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	var err error
	defaultAWSProviderConfig, err = testAWSProviderConfig()
	if err != nil {
		t.Logf("error creating test AWS ProviderConfig: %v", err)
		t.FailNow()
	}

	defaultAzureProviderConfig, err = testAzureProviderConfig()
	if err != nil {
		t.Logf("error creating test Azure ProviderConfig: %v", err)
		t.FailNow()
	}

	defaultGCPProviderConfig, err = testGCPProviderConfig()
	if err != nil {
		t.Logf("error creating test GCP ProviderConfig: %v", err)
		t.FailNow()
	}

	tests := []struct {
		name               string
		credRequests       []minterv1.CredentialsRequest
		cloudPlatform      configv1.PlatformType
		operatorDisabled   bool
		expectedConditions []configv1.ClusterOperatorStatusCondition
	}{
		{
			name:          "no credentials requests",
			credRequests:  []minterv1.CredentialsRequest{},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
			},
		},
		{
			name: "progressing - generation mismatch",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				// generation 2 != lastSyncGeneration 1, so progressing
				testCredentialsRequestWithGeneration("cred2", false, []minterv1.CredentialsRequestCondition{}, nil, 2, 1),
				testCredentialsRequestWithGeneration("cred3", false, []minterv1.CredentialsRequestCondition{}, nil, 2, 1),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "progressing - unprovisioned but generation matches",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "degraded and progressing - errors with generation match",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "degraded and progressing - insufficient creds with generation match",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			// Handler reports both Progressing and Degraded. The status controller
			// centrally suppresses Degraded when ClusterVersion is upgrading.
			name: "progressing with errors - both progressing and degraded reported",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithGeneration("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil, 2, 1),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "provisioned no errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
			},
		},
		{
			// Provisioned CR with errors but generation matches: failing CRs trigger progressing
			name: "provisioned with errors - degraded but not progressing",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			// Provisioned CR with errors and generation mismatch: handler reports both.
			// ClusterVersion-based suppression happens in syncStatus, not here.
			name: "provisioned with errors - generation mismatch, both reported",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithGeneration("cred2", true, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil, 2, 1),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "ignore nonAWS credreqs",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("azurecred", false, []minterv1.CredentialsRequestCondition{}, defaultAzureProviderConfig),
				testCredentialsRequestWithStatus("gcpcred", false, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
			},
		},
		{
			name: "ignore nonGCP credreqs",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
				testCredentialsRequestWithStatus("awscred", false, []minterv1.CredentialsRequestCondition{}, defaultAWSProviderConfig),
				testCredentialsRequestWithStatus("azurecred", false, []minterv1.CredentialsRequestCondition{}, defaultAzureProviderConfig),
			},
			cloudPlatform: configv1.GCPPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
			},
		},
		{
			name: "available and degraded coexist - degraded does not suppress available",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name: "degraded and progressing both reported when errors during generation mismatch",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithGeneration("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil, 2, 1),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "single CR with multiple failure types",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "operator disabled",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
			},
			cloudPlatform:    configv1.AWSPlatformType,
			operatorDisabled: true,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				dummyUpgradeableCondition,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			dummyActuator := &actuator.DummyActuator{}
			operatorMode := operatorv1.CloudCredentialsModeMint
			if test.operatorDisabled {
				operatorMode = operatorv1.CloudCredentialsModeManual
			}
			clusterOperatorConditions := computeStatusConditions(
				dummyActuator,
				operatorMode,
				test.credRequests,
				test.cloudPlatform,
				log.WithField("test", test.name))

			assert.Equal(t, len(test.expectedConditions), len(clusterOperatorConditions),
				"expected %d conditions but got %d: %v",
				len(test.expectedConditions), len(clusterOperatorConditions), clusterOperatorConditions)

			for _, ec := range test.expectedConditions {
				c := utils.FindClusterOperatorCondition(clusterOperatorConditions, ec.Type)
				if assert.NotNil(t, c, "unexpected nil for condition %s", ec.Type) {
					assert.Equal(t, string(ec.Status), string(c.Status), "unexpected status for condition %s", ec.Type)
					assert.Equal(t, ec.Reason, c.Reason, "unexpected reason for condition %s", ec.Type)

					if ec.Message != "" {
						assert.Contains(t, c.Message, ec.Message)
					}
				}
			}
		})
	}
}

func TestDegradedGracePeriod(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	var err error
	defaultAWSProviderConfig, err = testAWSProviderConfig()
	if err != nil {
		t.FailNow()
	}

	t.Run("fresh failure within grace period - not degraded", func(t *testing.T) {
		dummyActuator := &actuator.DummyActuator{}
		conditions := computeStatusConditions(
			dummyActuator,
			operatorv1.CloudCredentialsModeMint,
			[]minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{
					// Failure started 1 minute ago — within grace period
					testCRConditionWithAge(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue, 1*time.Minute),
				}, nil),
			},
			configv1.AWSPlatformType,
			log.WithField("test", t.Name()))

		for _, c := range conditions {
			assert.NotEqual(t, configv1.OperatorDegraded, c.Type,
				"Degraded should not be reported for failures within the grace period")
		}
		assert.Equal(t, 1, len(conditions), "expected only the Upgradeable condition within grace period")
	})

	t.Run("old failure past grace period - degraded", func(t *testing.T) {
		dummyActuator := &actuator.DummyActuator{}
		conditions := computeStatusConditions(
			dummyActuator,
			operatorv1.CloudCredentialsModeMint,
			[]minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{
					// Failure started 10 minutes ago — past grace period
					testCRConditionWithAge(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue, 10*time.Minute),
				}, nil),
			},
			configv1.AWSPlatformType,
			log.WithField("test", t.Name()))

		assert.Equal(t, 2, len(conditions), "expected exactly two conditions (Upgradeable + Degraded) past grace period")
		foundDegraded := false
		for _, c := range conditions {
			if c.Type == configv1.OperatorDegraded {
				foundDegraded = true
				assert.Equal(t, configv1.ConditionTrue, c.Status)
			}
			// Progressing should NOT be set: the CR is provisioned with no
			// generation mismatch. Persistent failure alone does not mean
			// the operator is making forward progress.
			assert.NotEqual(t, configv1.OperatorProgressing, c.Type,
				"Progressing should not be set for provisioned CRs that are only failing")
		}
		assert.True(t, foundDegraded, "Degraded should be reported for failures past the grace period")
	})

	t.Run("early failure type within grace period does not mask later type past grace period", func(t *testing.T) {
		// Bug regression: the inner loop over FailureConditionTypes used to break
		// on the first True condition regardless of whether it passed the grace
		// period. If InsufficientCloudCredentials is True but recent (1 min),
		// and CredentialsProvisionFailure is True and old (10 min), the break
		// would skip the second type entirely, hiding the Degraded condition.
		dummyActuator := &actuator.DummyActuator{}
		conditions := computeStatusConditions(
			dummyActuator,
			operatorv1.CloudCredentialsModeMint,
			[]minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{
					// First in FailureConditionTypes order — within grace period
					testCRConditionWithAge(minterv1.FailureConditionTypes[0], corev1.ConditionTrue, 1*time.Minute),
					// Later in FailureConditionTypes order — past grace period
					testCRConditionWithAge(minterv1.FailureConditionTypes[1], corev1.ConditionTrue, 10*time.Minute),
				}, nil),
			},
			configv1.AWSPlatformType,
			log.WithField("test", t.Name()))

		found := false
		for _, c := range conditions {
			if c.Type == configv1.OperatorDegraded {
				found = true
				assert.Equal(t, configv1.ConditionTrue, c.Status)
			}
		}
		assert.True(t, found,
			"Degraded should be reported: the early failure type within grace period must not mask the later type past grace period")
	})
}

func TestOperatorDisabledNoProgressing(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	var err error
	defaultAWSProviderConfig, err = testAWSProviderConfig()
	if err != nil {
		t.FailNow()
	}

	// Even with unprovisioned and failing CRs, disabled operator should not
	// report Progressing or Degraded — it returns early after Upgradeable.
	dummyActuator := &actuator.DummyActuator{}
	conditions := computeStatusConditions(
		dummyActuator,
		operatorv1.CloudCredentialsModeManual,
		[]minterv1.CredentialsRequest{
			testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{
				testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
			}, nil),
			testCredentialsRequestWithGeneration("cred2", false, []minterv1.CredentialsRequestCondition{}, nil, 2, 1),
		},
		configv1.AWSPlatformType,
		log.WithField("test", t.Name()))

	for _, c := range conditions {
		assert.NotEqual(t, configv1.OperatorDegraded, c.Type,
			"Degraded should not be set when operator is disabled")
		assert.NotEqual(t, configv1.OperatorProgressing, c.Type,
			"Progressing should not be set when operator is disabled")
	}
}

func TestInvalidProviderSpecFiltered(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// CRs with nil/corrupt ProviderSpec should be filtered out — not cause errors
	// or count toward Degraded/Progressing
	dummyActuator := &actuator.DummyActuator{}
	conditions := computeStatusConditions(
		dummyActuator,
		operatorv1.CloudCredentialsModeMint,
		[]minterv1.CredentialsRequest{
			// Invalid ProviderSpec — will fail decode, should be skipped
			testCredentialsRequestWithStatus("bad-cr", false, []minterv1.CredentialsRequestCondition{
				testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
			}, &runtime.RawExtension{Raw: []byte("not valid json")}),
		},
		configv1.AWSPlatformType,
		log.WithField("test", t.Name()))

	// Only Upgradeable should be set — the bad CR is filtered out entirely
	assert.Equal(t, 1, len(conditions), "only Upgradeable should be set when all CRs are filtered out")
	assert.Equal(t, configv1.OperatorUpgradeable, conditions[0].Type)
}

func TestProgressingOnlyFromGenerationMismatch(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	var err error
	defaultAWSProviderConfig, err = testAWSProviderConfig()
	if err != nil {
		t.FailNow()
	}

	// Generation mismatch alone (no failures, all provisioned) should trigger Progressing
	dummyActuator := &actuator.DummyActuator{}
	conditions := computeStatusConditions(
		dummyActuator,
		operatorv1.CloudCredentialsModeMint,
		[]minterv1.CredentialsRequest{
			testCredentialsRequestWithGeneration("cred1", true, []minterv1.CredentialsRequestCondition{}, nil, 2, 1),
		},
		configv1.AWSPlatformType,
		log.WithField("test", t.Name()))

	foundProgressing := false
	for _, c := range conditions {
		if c.Type == configv1.OperatorProgressing {
			foundProgressing = true
			assert.Equal(t, configv1.ConditionTrue, c.Status)
		}
		assert.NotEqual(t, configv1.OperatorDegraded, c.Type,
			"Degraded should not be set for generation mismatch without failures")
	}
	assert.True(t, foundProgressing, "Progressing should be set for generation mismatch")
}

func testCondition(condType configv1.ClusterStatusConditionType, status configv1.ConditionStatus, reason string) configv1.ClusterOperatorStatusCondition {
	return configv1.ClusterOperatorStatusCondition{
		Type:   condType,
		Status: status,
		Reason: reason,
	}
}

// dummyUpgradeableCondition is always returned by DummyActuator.Upgradeable().
var dummyUpgradeableCondition = testCondition(configv1.OperatorUpgradeable, configv1.ConditionTrue, "")

func testCRCondition(condType minterv1.CredentialsRequestConditionType, status corev1.ConditionStatus) minterv1.CredentialsRequestCondition {
	return testCRConditionWithAge(condType, status, 10*time.Minute)
}

func testCRConditionWithAge(condType minterv1.CredentialsRequestConditionType, status corev1.ConditionStatus, age time.Duration) minterv1.CredentialsRequestCondition {
	return minterv1.CredentialsRequestCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
	}
}

func testCredentialsRequestWithStatus(name string, provisioned bool, conditions []minterv1.CredentialsRequestCondition, providerConfig *runtime.RawExtension) minterv1.CredentialsRequest {
	return testCredentialsRequestWithGeneration(name, provisioned, conditions, providerConfig, 1, 1)
}

func testCredentialsRequestWithGeneration(name string, provisioned bool, conditions []minterv1.CredentialsRequestCondition, providerConfig *runtime.RawExtension, generation, lastSyncGeneration int64) minterv1.CredentialsRequest {
	if providerConfig == nil {
		providerConfig = defaultAWSProviderConfig
	}

	return minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Generation:  generation,
			Annotations: map[string]string{},
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			ProviderSpec: providerConfig,
		},
		Status: minterv1.CredentialsRequestStatus{
			Provisioned:        provisioned,
			Conditions:         conditions,
			LastSyncGeneration: lastSyncGeneration,
		},
	}
}

func testAWSProviderConfig() (*runtime.RawExtension, error) {
	awsProvSpec, err := minterv1.Codec.EncodeProviderSpec(
		&minterv1.AWSProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AWSProviderSpec",
			},
			StatementEntries: []minterv1.StatementEntry{
				{
					Effect: "Allow",
					Action: []string{
						"iam:GetUser",
						"iam:GetUserPolicy",
						"iam:ListAccessKeys",
					},
					Resource: "*",
				},
			},
		})

	return awsProvSpec, err
}

func testGCPProviderConfig() (*runtime.RawExtension, error) {
	gcpProvSpec, err := minterv1.Codec.EncodeProviderSpec(
		&minterv1.GCPProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "GCPProviderSpec",
			},
			PredefinedRoles: []string{
				"roles/appengine.appAdmin",
			},
		})

	return gcpProvSpec, err
}

func testAzureProviderConfig() (*runtime.RawExtension, error) {
	azureProviderSpec, err := minterv1.Codec.EncodeProviderSpec(
		&minterv1.AzureProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AzureProviderSpec",
			},
			RoleBindings: []minterv1.RoleBinding{
				{
					Role: "testRole",
				},
			},
		})
	return azureProviderSpec, err
}

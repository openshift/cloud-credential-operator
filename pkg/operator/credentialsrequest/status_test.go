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
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

var (
	defaultAWSProviderConfig   = &runtime.RawExtension{}
	defaultAzureProviderConfig = &runtime.RawExtension{}
	defaultGCPProviderConfig   = &runtime.RawExtension{}
)

func TestClusterOperatorStatus(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
	}

	defaultAWSProviderConfig, err = testAWSProviderConfig(codec)
	if err != nil {
		t.Logf("error creating test AWS ProviderConfig: %v", err)
		t.FailNow()
	}

	defaultAzureProviderConfig, err = testAzureProviderConfig(codec)
	if err != nil {
		t.Logf("error creating test Azure ProviderConfig: %v", err)
		t.FailNow()
	}

	defaultGCPProviderConfig, err = testGCPProviderConfig(codec)
	if err != nil {
		t.Logf("error creating test GCP ProviderConfig: %v", err)
		t.FailNow()
	}

	tests := []struct {
		name               string
		credRequests       []minterv1.CredentialsRequest
		cloudPlatform      configv1.PlatformType
		operatorMode       operatorv1.CloudCredentialsMode
		configConflict     bool
		expectedConditions []configv1.ClusterOperatorStatusCondition
	}{
		{
			name:          "no credentials requests",
			operatorMode:  operatorv1.CloudCredentialsModeMint,
			credRequests:  []minterv1.CredentialsRequest{},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionFalse, reasonReconcilingComplete),
				testCondition(configv1.OperatorDegraded, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			name:         "progressing no errors",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			name:         "progressing with errors",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name:         "progressing with insufficient creds errors",
			operatorMode: operatorv1.CloudCredentialsModeMint,
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
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name:         "provisioned no errors",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionFalse, reasonReconcilingComplete),
				testCondition(configv1.OperatorDegraded, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			// Implies the credential was initially provisioned but an update is needed and it's failing:
			name:         "provisioned with errors",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name:         "ignore nonAWS credreqs",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("azurecred", false, []minterv1.CredentialsRequestCondition{}, defaultAzureProviderConfig),
				testCredentialsRequestWithStatus("gcpcred", false, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testConditionWithMessage(configv1.OperatorProgressing, configv1.ConditionFalse, reasonReconcilingComplete, "2 of 2 credentials requests"),
				testCondition(configv1.OperatorDegraded, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			name:         "ignore nonGCP credreqs",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
				testCredentialsRequestWithStatus("awscred", false, []minterv1.CredentialsRequestCondition{}, defaultAWSProviderConfig),
				testCredentialsRequestWithStatus("azurecred", false, []minterv1.CredentialsRequestCondition{}, defaultAzureProviderConfig),
			},
			cloudPlatform: configv1.GCPPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testConditionWithMessage(configv1.OperatorProgressing, configv1.ConditionFalse, reasonReconcilingComplete, "2 of 2 credentials requests"),
				testCondition(configv1.OperatorDegraded, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			name:         "set upgradeable condition",
			operatorMode: operatorv1.CloudCredentialsModeMint,
			credRequests: []minterv1.CredentialsRequest{},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorUpgradeable, configv1.ConditionTrue, ""),
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
			cloudPlatform: configv1.AWSPlatformType,
			operatorMode:  operatorv1.CloudCredentialsModeManual,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, reasonOperatorDisabled),
				testCondition(configv1.OperatorProgressing, configv1.ConditionFalse, reasonOperatorDisabled),
				testCondition(configv1.OperatorDegraded, configv1.ConditionFalse, reasonOperatorDisabled),
			},
		},
		{
			name: "operator configmap vs config conflict",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
			},
			cloudPlatform:  configv1.AWSPlatformType,
			operatorMode:   operatorv1.CloudCredentialsModeManual,
			configConflict: true,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, reasonOperatorDisabled),
				testCondition(configv1.OperatorProgressing, configv1.ConditionFalse, reasonOperatorDisabled),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, constants.StatusModeMismatch),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			schemeutils.SetupScheme(scheme.Scheme)
			dummyActuator := &actuator.DummyActuator{}
			clusterOperatorConditions := computeStatusConditions(dummyActuator, testUnknownConditions(), test.credRequests,
				test.cloudPlatform, test.operatorMode, test.configConflict, log.WithField("test", test.name))
			for _, ec := range test.expectedConditions {
				c := findClusterOperatorCondition(clusterOperatorConditions, ec.Type)
				if assert.NotNil(t, c) {
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

func TestClusterOperatorVersion(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	twentyHoursAgo := metav1.Time{
		Time: time.Now().Add(-20 * time.Hour),
	}

	tests := []struct {
		name                             string
		releaseVersionEnv                string
		currentProgressingLastTransition metav1.Time
		currentVersion                   string
		expectProgressingTransition      bool
	}{
		{
			name:                             "test version upgraded",
			currentProgressingLastTransition: twentyHoursAgo,
			currentVersion:                   "4.0.0-5",
			releaseVersionEnv:                "4.0.0-10",
			expectProgressingTransition:      true,
		},
		{
			name:                             "test version constant",
			currentProgressingLastTransition: twentyHoursAgo,
			currentVersion:                   "4.0.0-5",
			releaseVersionEnv:                "4.0.0-5",
			expectProgressingTransition:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			existingCO := testClusterOperator("4.0.0-5", twentyHoursAgo)
			operatorConfig := testOperatorConfig("")
			existing := []runtime.Object{existingCO, operatorConfig}
			fakeClient := fake.NewFakeClient(existing...)

			rcr := &ReconcileCredentialsRequest{
				Client:   fakeClient,
				Actuator: &actuator.DummyActuator{},
			}

			require.NoError(t, os.Setenv("RELEASE_VERSION", test.releaseVersionEnv), "unable to set environment variable for testing")
			err := rcr.syncOperatorStatus()

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			clusterop := &configv1.ClusterOperator{}

			err = fakeClient.Get(context.TODO(), client.ObjectKey{Name: cloudCredClusterOperator}, clusterop)
			assert.NoError(t, err)

			foundVersion := false
			for _, version := range clusterop.Status.Versions {
				if version.Name == "operator" {
					foundVersion = true
					assert.Equal(t, test.releaseVersionEnv, version.Version)
				}
			}
			assert.True(t, foundVersion, "didn't find an entry named 'operator' in the version list")

			progCond := findClusterOperatorCondition(clusterop.Status.Conditions,
				configv1.OperatorProgressing)
			require.NotNil(t, progCond)
			if test.expectProgressingTransition {
				assert.True(t, progCond.LastTransitionTime.Time.After(
					test.currentProgressingLastTransition.Time))
			} else {
				assert.Equal(t, test.currentProgressingLastTransition.Time.Format(time.UnixDate),
					progCond.LastTransitionTime.Time.Format(time.UnixDate))
			}
		})
	}
}

func testClusterOperator(version string, progressingLastTransition metav1.Time) *configv1.ClusterOperator {
	return &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{
			Name: cloudCredClusterOperator,
		},
		Status: configv1.ClusterOperatorStatus{
			Versions: []configv1.OperandVersion{
				{
					Name:    "operator",
					Version: version,
				},
			},
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:   configv1.OperatorProgressing,
					Status: "False",
					Reason: reasonReconcilingComplete,
					// Warning: must match what the controller status would check, otherwise we might get a false positive on this test.
					Message:            "0 of 0 credentials requests provisioned and reconciled.",
					LastTransitionTime: progressingLastTransition,
				},
			},
		},
	}
}

func testCondition(condType configv1.ClusterStatusConditionType, status configv1.ConditionStatus, reason string) configv1.ClusterOperatorStatusCondition {
	return configv1.ClusterOperatorStatusCondition{
		Type:   condType,
		Status: status,
		Reason: reason,
	}
}

func testConditionWithMessage(condType configv1.ClusterStatusConditionType, status configv1.ConditionStatus, reason, message string) configv1.ClusterOperatorStatusCondition {
	cond := testCondition(condType, status, reason)
	cond.Message = message

	return cond
}

func testCRCondition(condType minterv1.CredentialsRequestConditionType, status corev1.ConditionStatus) minterv1.CredentialsRequestCondition {
	return minterv1.CredentialsRequestCondition{
		Type:   condType,
		Status: status,
	}
}

func testUnknownConditions() []configv1.ClusterOperatorStatusCondition {
	return []configv1.ClusterOperatorStatusCondition{
		{
			Type:   configv1.OperatorAvailable,
			Status: configv1.ConditionUnknown,
			Reason: "",
		},
		{
			Type:   configv1.OperatorProgressing,
			Status: configv1.ConditionUnknown,
			Reason: "",
		},
		{
			Type:   configv1.OperatorDegraded,
			Status: configv1.ConditionUnknown,
			Reason: "",
		},
	}
}

func testCredentialsRequestWithStatus(name string, provisioned bool, conditions []minterv1.CredentialsRequestCondition, providerConfig *runtime.RawExtension) minterv1.CredentialsRequest {
	if providerConfig == nil {
		providerConfig = defaultAWSProviderConfig
	}

	return minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
			ProviderSpec: providerConfig,
		},
		Status: minterv1.CredentialsRequestStatus{
			Provisioned: provisioned,
			Conditions:  conditions,
		},
	}
}

func testAWSProviderConfig(codec *minterv1.ProviderCodec) (*runtime.RawExtension, error) {
	awsProvSpec, err := codec.EncodeProviderSpec(
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

func testGCPProviderConfig(codec *minterv1.ProviderCodec) (*runtime.RawExtension, error) {
	gcpProvSpec, err := codec.EncodeProviderSpec(
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

func testAzureProviderConfig(codec *minterv1.ProviderCodec) (*runtime.RawExtension, error) {
	azureProviderSpec, err := codec.EncodeProviderSpec(
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

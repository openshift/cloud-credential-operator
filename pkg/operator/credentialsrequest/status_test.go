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

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
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
		operatorDisabled   bool
		expectedConditions []configv1.ClusterOperatorStatusCondition
	}{
		{
			name:               "no credentials requests",
			credRequests:       []minterv1.CredentialsRequest{},
			cloudPlatform:      configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{},
		},
		{
			name: "progressing no errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
			},
		},
		{
			name: "progressing with errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name: "progressing with insufficient creds errors",
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
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name: "provisioned no errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform:      configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{},
		},
		{
			// Implies the credential was initially provisioned but an update is needed and it's failing:
			name: "provisioned with errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}, nil),
			},
			cloudPlatform: configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorDegraded, configv1.ConditionTrue, reasonCredentialsFailing),
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
			cloudPlatform:      configv1.AWSPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{},
		},
		{
			name: "ignore nonGCP credreqs",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}, defaultGCPProviderConfig),
				testCredentialsRequestWithStatus("awscred", false, []minterv1.CredentialsRequestCondition{}, defaultAWSProviderConfig),
				testCredentialsRequestWithStatus("azurecred", false, []minterv1.CredentialsRequestCondition{}, defaultAzureProviderConfig),
			},
			cloudPlatform:      configv1.GCPPlatformType,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{},
		},
		{
			name: "operator disabled",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{}, nil),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}, nil),
			},
			cloudPlatform:      configv1.AWSPlatformType,
			operatorDisabled:   true,
			expectedConditions: []configv1.ClusterOperatorStatusCondition{},
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

func testCondition(condType configv1.ClusterStatusConditionType, status configv1.ConditionStatus, reason string) configv1.ClusterOperatorStatusCondition {
	return configv1.ClusterOperatorStatusCondition{
		Type:   condType,
		Status: status,
		Reason: reason,
	}
}

func testCRCondition(condType minterv1.CredentialsRequestConditionType, status corev1.ConditionStatus) minterv1.CredentialsRequestCondition {
	return minterv1.CredentialsRequestCondition{
		Type:   condType,
		Status: status,
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

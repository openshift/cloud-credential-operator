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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/cloud-credential-operator/pkg/apis"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

func TestClusterOperatorStatus(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)
	configv1.Install(scheme.Scheme)

	tests := []struct {
		name               string
		credRequests       []minterv1.CredentialsRequest
		expectedConditions []configv1.ClusterOperatorStatusCondition
	}{
		{
			name:         "no credentials requests",
			credRequests: []minterv1.CredentialsRequest{},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionFalse, reasonReconcilingComplete),
				testCondition(configv1.OperatorFailing, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			name: "progressing no errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{}),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}),
			},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorFailing, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			name: "progressing with errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{}),
			},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorFailing, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name: "progressing with insufficient creds errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}),
				testCredentialsRequestWithStatus("cred2", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}),
				testCredentialsRequestWithStatus("cred3", false, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.InsufficientCloudCredentials, corev1.ConditionTrue),
				}),
			},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorFailing, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
		{
			name: "provisioned no errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{}),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}),
			},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionFalse, reasonReconcilingComplete),
				testCondition(configv1.OperatorFailing, configv1.ConditionFalse, reasonNoCredentialsFailing),
			},
		},
		{
			// Implies the credential was initially provisioned but an update is needed and it's failing:
			name: "provisioned with errors",
			credRequests: []minterv1.CredentialsRequest{
				testCredentialsRequestWithStatus("cred1", true, []minterv1.CredentialsRequestCondition{}),
				testCredentialsRequestWithStatus("cred2", true, []minterv1.CredentialsRequestCondition{
					testCRCondition(minterv1.CredentialsProvisionFailure, corev1.ConditionTrue),
				}),
				testCredentialsRequestWithStatus("cred3", true, []minterv1.CredentialsRequestCondition{}),
			},
			expectedConditions: []configv1.ClusterOperatorStatusCondition{
				testCondition(configv1.OperatorAvailable, configv1.ConditionTrue, ""),
				testCondition(configv1.OperatorProgressing, configv1.ConditionTrue, reasonReconciling),
				testCondition(configv1.OperatorFailing, configv1.ConditionTrue, reasonCredentialsFailing),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			clusterOperatorConditions := computeStatusConditions(testUnknownConditions(), test.credRequests)
			for _, ec := range test.expectedConditions {
				c := findClusterOperatorCondition(clusterOperatorConditions, ec.Type)
				if assert.NotNil(t, c) {
					assert.Equal(t, string(ec.Status), string(c.Status))
					assert.Equal(t, ec.Reason, c.Reason)
				}
			}
		})
	}
}

func TestClusterOperatorVersion(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)
	configv1.Install(scheme.Scheme)

	tests := []struct {
		name              string
		releaseVersionEnv string
	}{
		{
			name:              "test setting clusteroperator.status.version correctly",
			releaseVersionEnv: "TESTVERSION",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewFakeClient()
			rcr := &ReconcileCredentialsRequest{
				Client: fakeClient,
			}

			assert.NoError(t, os.Setenv("RELEASE_VERSION", test.releaseVersionEnv), "unable to set environment variable for testing")
			err := rcr.syncOperatorStatus()

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			clusterop := &configv1.ClusterOperator{}

			if err := fakeClient.Get(context.TODO(), client.ObjectKey{Name: cloudCredOperatorNamespace}, clusterop); err != nil {
				t.Errorf("error fetching clusteroperator object: %v", err)
			} else {
				foundVersion := false
				for _, version := range clusterop.Status.Versions {
					if version.Name == "operator" {
						foundVersion = true
						assert.Equal(t, test.releaseVersionEnv, version.Version)
					}
				}
				assert.True(t, foundVersion, "didn't find an entry named 'operator' in the version list")
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
			Type:   configv1.OperatorFailing,
			Status: configv1.ConditionUnknown,
			Reason: "",
		},
	}
}

// findClusterOperatorCondition iterates all conditions on a ClusterOperator looking for the
// specified condition type. If none exists nil will be returned.
func findClusterOperatorCondition(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) *configv1.ClusterOperatorStatusCondition {
	for i, condition := range conditions {
		if condition.Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func testCredentialsRequestWithStatus(name string, provisioned bool, conditions []minterv1.CredentialsRequestCondition) minterv1.CredentialsRequest {
	return minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef: corev1.ObjectReference{Name: testSecretName, Namespace: testSecretNamespace},
		},
		Status: minterv1.CredentialsRequestStatus{
			Provisioned: provisioned,
			Conditions:  conditions,
		},
	}
}

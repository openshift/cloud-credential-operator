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

package podidentity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	clientgotesting "k8s.io/client-go/testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	fakeclientgo "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestPodIdentityWebhookController(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	getDeployment := func(c kubernetes.Interface, name, namespace string) (*appsv1.Deployment, error) {
		return c.AppsV1().Deployments(namespace).Get(context.TODO(), name, v1.GetOptions{})
	}

	getPDB := func(c kubernetes.Interface, name, namespace string) (*policyv1.PodDisruptionBudget, error) {
		return c.PolicyV1().PodDisruptionBudgets(namespace).Get(context.TODO(), name, v1.GetOptions{})
	}

	getWebhook := func(c kubernetes.Interface, name string) (*admissionv1.MutatingWebhookConfiguration, error) {
		return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.TODO(), name, v1.GetOptions{})
	}

	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")
	t.Setenv("AZURE_POD_IDENTITY_WEBHOOK_IMAGE", "azure_identity_image")

	tests := []struct {
		name             string
		existing         []runtime.Object
		expectErr        bool
		expectedReplicas int32
		expectPDB        bool
		podIdentityType  PodIdentityManifestSource
	}{
		{
			name: "Cluster infrastructure topology is SingleReplica",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						InfrastructureTopology: configv1.SingleReplicaTopologyMode,
					},
				}},
			expectErr:        false,
			expectedReplicas: 1,
			expectPDB:        false,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name: "Cluster infrastructure topology is HighlyAvailable",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name: "Cluster infrastructure object has no infrastructure topology set",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name:            "Cluster infrastructure object doesn't exist",
			expectErr:       true,
			podIdentityType: AwsPodIdentity{},
		},
		{
			name: "Azure platform",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AzurePodIdentity{},
		},
		{
			name: "AWS platform: Cluster infrastructure object has no AWS region set",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						PlatformStatus: &configv1.PlatformStatus{
							AWS: &configv1.AWSPlatformStatus{
								Region: "",
							},
						},
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name: "AWS platform: Cluster infrastructure object has AWS region",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						PlatformStatus: &configv1.PlatformStatus{
							AWS: &configv1.AWSPlatformStatus{
								Region: "us-west-1",
							},
						},
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			logger := log.WithField("controller", "podidentitywebhookcontrollertest")
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()
			fakeClientset := fakeclientgo.NewSimpleClientset()
			r := &staticResourceReconciler{
				client:          fakeClient,
				clientset:       fakeClientset,
				logger:          logger,
				eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
				cache:           resourceapply.NewResourceCache(),
				conditionsMutex: &sync.RWMutex{},
				conditions:      []configv1.ClusterOperatorStatusCondition{},
				imagePullSpec:   test.podIdentityType.GetImagePullSpec(),
				podIdentityType: test.podIdentityType,
			}

			_, err := r.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "testName",
					Namespace: "testNamespace",
				},
			})

			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}

			if !test.expectErr {
				expectedImage := fmt.Sprintf("%s_identity_image", test.podIdentityType.Name())
				assert.Equal(t, r.imagePullSpec, expectedImage)

				podIdentityWebhookDeployment, err := getDeployment(fakeClientset, "pod-identity-webhook", "openshift-cloud-credential-operator")
				assert.Nil(t, err)
				assert.NotNil(t, podIdentityWebhookDeployment, "did not find expected pod-identity-webhook Deployment")

				if test.expectedReplicas != 0 {
					assert.Equal(t, *podIdentityWebhookDeployment.Spec.Replicas, test.expectedReplicas, "found unexpected pod-identity-webhook deployment replicas")
				}

				assert.Equal(t, podIdentityWebhookDeployment.Spec.Template.Spec.Containers[0].Image, expectedImage, "container image matches expected one")

				// Test ApplyDeploymentSubstitutionsInPlace()
				switch test.podIdentityType {
				case AwsPodIdentity{}:
					infra, ok := test.existing[0].(*configv1.Infrastructure)
					if !ok || infra.Status.PlatformStatus == nil || infra.Status.PlatformStatus.AWS == nil {
						// skip
						break
					}

					expectedRegion := infra.Status.PlatformStatus.AWS.Region
					if expectedRegion == "" {
						expectedRegion = "us-east-1"
					}

					matchesRegionFlag := false
					for _, arg := range podIdentityWebhookDeployment.Spec.Template.Spec.Containers[0].Command {
						if strings.Contains(arg, "--aws-default-region") && arg == fmt.Sprintf("--aws-default-region=%s", expectedRegion) {
							matchesRegionFlag = true
							break
						}
					}

					assert.Equal(t, matchesRegionFlag, true, "cmd", podIdentityWebhookDeployment.Spec.Template.Spec.Containers[0].Command)
				}

				podDisruptionBudget, err := getPDB(fakeClientset, "pod-identity-webhook", "openshift-cloud-credential-operator")
				if test.expectPDB {
					assert.Nil(t, err)
					assert.NotEqual(t, podDisruptionBudget.Kind, "", "did not find expected pod-identity-webhook PodDisruptionBudget")
				} else {
					assert.NotNil(t, err)
					assert.Equal(t, podDisruptionBudget.Kind, "", "found unexpected pod-identity-webhook PodDisruptionBudget")
				}

				webhook, err := getWebhook(fakeClientset, "pod-identity-webhook")
				assert.NotNil(t, webhook, "did not find expected pod-identity-webhook webhook config")
				assert.Contains(t, webhook.Webhooks[0].Name, test.podIdentityType.Name())
			}
		})
	}
}

func TestCheckPodStatus(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name              string
		deployment        *appsv1.Deployment
		expectedDesired   int32
		expectedAvailable int32
		expectedUpdated   int32
		expectedTotal     int32
	}{
		{
			name:            "Deployment not found",
			deployment:      nil,
			expectedDesired: 1,
		},
		{
			name:              "Deployment with all replicas available and updated",
			deployment:        testDeploymentWithReplicas(2, 2, 2, 2),
			expectedDesired:   2,
			expectedAvailable: 2,
			expectedUpdated:   2,
			expectedTotal:     2,
		},
		{
			name: "Deployment with nil replicas",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod-identity-webhook",
					Namespace: "openshift-cloud-credential-operator",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: nil,
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 1,
					UpdatedReplicas:   0,
					Replicas:          1,
				},
			},
			expectedDesired:   1,
			expectedAvailable: 1,
			expectedUpdated:   0,
			expectedTotal:     1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existing := []runtime.Object{}
			if test.deployment != nil {
				existing = append(existing, test.deployment)
			}

			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(existing...).Build()
			logger := log.WithField("controller", "podidentitywebhookcontrollertest")
			r := &staticResourceReconciler{
				client: fakeClient,
				logger: logger,
			}

			podStatus, err := r.CheckPodStatus(context.TODO())

			assert.Nil(t, err, "unexpected error: %v", err)
			assert.NotNil(t, podStatus)
			assert.Equal(t, test.expectedDesired, podStatus.desiredReplicas, "desiredReplicas mismatch")
			assert.Equal(t, test.expectedAvailable, podStatus.availableReplicas, "availableReplicas mismatch")
			assert.Equal(t, test.expectedUpdated, podStatus.updatedReplicas, "updatedReplicas mismatch")
			assert.Equal(t, test.expectedTotal, podStatus.totalReplicas, "totalReplicas mismatch")
		})
	}
}

func TestWebhookPodStatus(t *testing.T) {
	tests := []struct {
		name                string
		desiredReplicas     int32
		availableReplicas   int32
		updatedReplicas     int32
		totalReplicas       int32
		expectedAvailable   bool
		expectedProgressing bool
	}{
		{
			name:                "All pods available and up to date",
			desiredReplicas:     2,
			availableReplicas:   2,
			updatedReplicas:     2,
			totalReplicas:       2,
			expectedAvailable:   true,
			expectedProgressing: false,
		},
		{
			name:                "No pods available",
			desiredReplicas:     2,
			availableReplicas:   0,
			updatedReplicas:     0,
			totalReplicas:       0,
			expectedAvailable:   false,
			expectedProgressing: true,
		},
		{
			name:                "Some pods available, rollout in progress",
			desiredReplicas:     2,
			availableReplicas:   1,
			updatedReplicas:     1,
			totalReplicas:       2,
			expectedAvailable:   true,
			expectedProgressing: true,
		},
		{
			name:                "All pods available but not updated yet",
			desiredReplicas:     2,
			availableReplicas:   2,
			updatedReplicas:     0,
			totalReplicas:       2,
			expectedAvailable:   true,
			expectedProgressing: true,
		},
		{
			name:                "Single replica available and updated",
			desiredReplicas:     1,
			availableReplicas:   1,
			updatedReplicas:     1,
			totalReplicas:       1,
			expectedAvailable:   true,
			expectedProgressing: false,
		},
		{
			name:                "Scale down in progress",
			desiredReplicas:     2,
			availableReplicas:   2,
			updatedReplicas:     2,
			totalReplicas:       3,
			expectedAvailable:   true,
			expectedProgressing: true,
		},
		{
			name:                "Scale up in progress",
			desiredReplicas:     3,
			availableReplicas:   1,
			updatedReplicas:     1,
			totalReplicas:       1,
			expectedAvailable:   true,
			expectedProgressing: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wps := &webhookPodStatus{
				desiredReplicas:   test.desiredReplicas,
				availableReplicas: test.availableReplicas,
				updatedReplicas:   test.updatedReplicas,
				totalReplicas:     test.totalReplicas,
			}

			assert.Equal(t, test.expectedAvailable, wps.Available(), "Available() returned unexpected value")
			assert.Equal(t, test.expectedProgressing, wps.Progressing(), "Progressing() returned unexpected value")
		})
	}
}

func TestGetConditions(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name                   string
		deployment             *appsv1.Deployment
		existingConditions     []configv1.ClusterOperatorStatusCondition
		expectedConditionCount int
		expectAvailableFalse   bool
		expectProgressingTrue  bool
	}{
		{
			name:                   "Deployment not found",
			deployment:             nil,
			expectedConditionCount: 2,
			expectAvailableFalse:   true,
			expectProgressingTrue:  true,
		},
		{
			name:       "Deployment not found with existing conditions",
			deployment: nil,
			existingConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "JustBecause",
					Message: "Test degraded condition",
				},
			},
			expectedConditionCount: 3,
			expectAvailableFalse:   true,
			expectProgressingTrue:  true,
		},
		{
			name:                   "All pods available and updated - no additional conditions",
			deployment:             testDeploymentWithReplicas(2, 2, 2, 2),
			expectedConditionCount: 0,
			expectAvailableFalse:   false,
			expectProgressingTrue:  false,
		},
		{
			name:                   "No pods available",
			deployment:             testDeploymentWithReplicas(2, 0, 0, 0),
			expectedConditionCount: 2,
			expectAvailableFalse:   true,
			expectProgressingTrue:  true,
		},
		{
			name:                   "Rollout in progress",
			deployment:             testDeploymentWithReplicas(2, 1, 1, 2),
			expectedConditionCount: 1,
			expectAvailableFalse:   false,
			expectProgressingTrue:  true,
		},
		{
			name:                   "Rollout hasn't begun",
			deployment:             testDeploymentWithReplicas(2, 2, 0, 2),
			expectedConditionCount: 1,
			expectAvailableFalse:   false,
			expectProgressingTrue:  true,
		},
		{
			name:       "Existing conditions preserved and new ones added",
			deployment: testDeploymentWithReplicas(2, 0, 0, 0),
			existingConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionFalse,
					Reason:  "AsExpected",
					Message: "All is well",
				},
			},
			expectedConditionCount: 3,
			expectAvailableFalse:   true,
			expectProgressingTrue:  true,
		},
		{
			name:                   "Scale down in progress",
			deployment:             testDeploymentWithReplicas(2, 2, 2, 3),
			expectedConditionCount: 1,
			expectAvailableFalse:   false,
			expectProgressingTrue:  true,
		},
		{
			name:                   "Scale up in progress",
			deployment:             testDeploymentWithReplicas(3, 2, 2, 2),
			expectedConditionCount: 1,
			expectAvailableFalse:   false,
			expectProgressingTrue:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			existing := []runtime.Object{}
			if test.deployment != nil {
				existing = append(existing, test.deployment)
			}

			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(existing...).Build()
			logger := log.WithField("controller", "podidentitywebhookcontrollertest")
			r := &staticResourceReconciler{
				client:          fakeClient,
				logger:          logger,
				conditionsMutex: &sync.RWMutex{},
				conditions:      test.existingConditions,
			}

			conditions, err := r.GetConditions(context.TODO(), logger)

			assert.Nil(t, err, "unexpected error: %v", err)
			assert.Equal(t, test.expectedConditionCount, len(conditions), "unexpected number of conditions")

			// Check for conditions
			foundAvailableFalse := false
			foundProgressingTrue := false
			for _, cond := range conditions {
				if cond.Type == configv1.OperatorAvailable && cond.Status == configv1.ConditionFalse {
					foundAvailableFalse = true
					assert.Equal(t, reasonPodIdentityWebhookPodsNotAvailable, cond.Reason)
					assert.Contains(t, cond.Message, "No pod identity webhook pods are available")
				}
				if cond.Type == configv1.OperatorProgressing && cond.Status == configv1.ConditionTrue {
					foundProgressingTrue = true
					assert.Equal(t, reasonPodIdentityWebhookPodsStillUpdating, cond.Reason)
					assert.Contains(t, cond.Message, "Waiting for pod identity webhook deployment rollout")
				}
			}

			assert.Equal(t, test.expectAvailableFalse, foundAvailableFalse, "Available=False condition expectation mismatch")
			assert.Equal(t, test.expectProgressingTrue, foundProgressingTrue, "Progressing=True condition expectation mismatch")
		})
	}
}

func TestPodIdentityShouldDeploy(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	azureCredsSecretName := "azure-credentials"
	tests := []struct {
		name            string
		existing        []runtime.Object
		expectedResult  bool
		expectErr       bool
		podIdentityType PodIdentityManifestSource
	}{{
		name: "Azure secret with credentials exists",
		existing: []runtime.Object{
			&corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      azureCredsSecretName,
					Namespace: operatorNamespace,
				},
				Data: map[string][]byte{
					azureTenantIdKey: {},
				},
			}},
		podIdentityType: AzurePodIdentity{},
		expectedResult:  true,
		expectErr:       false,
	},
		{
			name: "Azure secret with credentials without tenant id",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      azureCredsSecretName,
						Namespace: operatorNamespace,
					},
					Data: map[string][]byte{},
				}},
			podIdentityType: AzurePodIdentity{},
			expectedResult:  false,
			expectErr:       false,
		},
		{
			name:            "Azure no secret with credentials",
			existing:        []runtime.Object{},
			podIdentityType: AzurePodIdentity{},
			expectedResult:  false,
			expectErr:       false,
		},
		{
			name: "Azure fails to get secret and error is not NotFound",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      azureCredsSecretName,
						Namespace: operatorNamespace,
					},
					Data: map[string][]byte{},
				}},
			podIdentityType: AzurePodIdentity{},
			expectedResult:  false,
			expectErr:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClientset := fakeclientgo.NewSimpleClientset(test.existing...)
			if test.expectErr {
				fakeClientset.PrependReactor("get", "secrets", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.Secret{}, fmt.Errorf("error getting secret")
				})
			}

			result, err := test.podIdentityType.ShouldBeDeployed(context.TODO(), fakeClientset, operatorNamespace)
			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}
			assert.Equal(t, result, test.expectedResult)
		})
	}
}

func testDeploymentWithReplicas(desired, available, updated, total int) *appsv1.Deployment {
	int32Ptr := func(i int32) *int32 { return &i }

	return &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "pod-identity-webhook",
			Namespace: "openshift-cloud-credential-operator",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(int32(desired)),
		},
		Status: appsv1.DeploymentStatus{
			AvailableReplicas: int32(available),
			UpdatedReplicas:   int32(updated),
			Replicas:          int32(total),
		},
	}
}
